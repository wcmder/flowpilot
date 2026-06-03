from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .models import PacketObservation
from .protocols.registry import extract_hooks

PROTOCOL_EXTRACT_HOOKS = extract_hooks()


def read_capture(
    path: Path,
    packet_limit: int | None = None,
    tls_keylog_file: Path | None = None,
    progress_callback: Callable[[int], None] | None = None,
) -> Iterator[PacketObservation]:
    try:
        import pyshark
    except ImportError as exc:  # pragma: no cover - dependency is declared, but message helps.
        raise RuntimeError("PyShark is not installed. Run `pip install -e .`.") from exc

    if not path.exists():
        raise FileNotFoundError(path)

    custom_parameters = _tshark_custom_parameters(tls_keylog_file)
    capture = pyshark.FileCapture(
        str(path),
        keep_packets=False,
        custom_parameters=custom_parameters,
    )
    try:
        for index, packet in enumerate(capture):
            if packet_limit is not None and index >= packet_limit:
                break
            if progress_callback:
                progress_callback(index + 1)
            observation = packet_to_observation(packet)
            if observation:
                yield observation
    finally:
        capture.close()


def _tshark_custom_parameters(tls_keylog_file: Path | None) -> list[str] | None:
    parameters = [
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
        "-o",
        "tls.desegment_ssl_records:TRUE",
        "-o",
        "tls.desegment_ssl_application_data:TRUE",
    ]
    if tls_keylog_file is None:
        return parameters
    if not tls_keylog_file.exists():
        raise FileNotFoundError(tls_keylog_file)
    return [
        "-o",
        f"tls.keylog_file:{tls_keylog_file}",
        *parameters,
    ]


def packet_to_observation(packet: Any) -> PacketObservation | None:
    src_ip, dst_ip = _ip_pair(packet)
    if not src_ip or not dst_ip:
        return None

    protocol = _transport_protocol(packet)
    src_port, dst_port = _ports(packet, protocol)

    observation_fields = {
        "timestamp": _timestamp(packet),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": _safe_int(getattr(packet, "length", 0)) or 0,
        "issue_tags": [],
        "http_host": _layer_attr(packet, "http", "host"),
        "http_location": _layer_attr(packet, "http", "location"),
    }
    helpers = _extract_helpers(src_ip=src_ip, src_port=src_port, protocol=protocol)
    for extract_protocol in PROTOCOL_EXTRACT_HOOKS:
        _merge_extracted_fields(observation_fields, extract_protocol(packet, helpers))
    return PacketObservation(**observation_fields)


def _extract_helpers(*, src_ip: str, src_port: int | None, protocol: str):
    return SimpleNamespace(
        src_ip=src_ip,
        src_port=src_port,
        protocol=protocol,
        layer_attr=_layer_attr,
        layer_attr_values=_layer_attr_values,
        layer_attr_values_from_layer=_layer_attr_values_from_layer,
        layer_field_candidates=_layer_field_candidates,
        string_values=_string_values,
        truthy_layer_attr=_truthy_layer_attr,
        safe_float=_safe_float,
        safe_int=_safe_int,
    )


def _merge_extracted_fields(observation_fields: dict, extracted_fields: dict) -> None:
    for field_name, value in extracted_fields.items():
        if field_name == "issue_tags":
            observation_fields["issue_tags"].extend(value)
        else:
            observation_fields[field_name] = value


def observations_from_iterable(packets: Iterable[Any]) -> Iterator[PacketObservation]:
    for packet in packets:
        if isinstance(packet, PacketObservation):
            yield packet
            continue
        observation = packet_to_observation(packet)
        if observation:
            yield observation


def _timestamp(packet: Any) -> datetime | None:
    sniff_time = getattr(packet, "sniff_time", None)
    if isinstance(sniff_time, datetime):
        return sniff_time
    return None


def _ip_pair(packet: Any) -> tuple[str | None, str | None]:
    ipv4 = getattr(packet, "ip", None)
    if ipv4 is not None:
        return getattr(ipv4, "src", None), getattr(ipv4, "dst", None)

    ipv6 = getattr(packet, "ipv6", None)
    if ipv6 is not None:
        return getattr(ipv6, "src", None), getattr(ipv6, "dst", None)

    return None, None


def _transport_protocol(packet: Any) -> str:
    layers = {getattr(layer, "layer_name", "").lower() for layer in getattr(packet, "layers", [])}
    for candidate in ("tcp", "udp", "esp", "ah", "gre", "icmp", "icmpv6"):
        if candidate in layers or hasattr(packet, candidate):
            return candidate.upper()
    return getattr(packet, "highest_layer", "UNKNOWN").upper()


def _ports(packet: Any, protocol: str) -> tuple[int | None, int | None]:
    layer = getattr(packet, protocol.lower(), None)
    if layer is None:
        return None, None
    return _safe_int(getattr(layer, "srcport", None)), _safe_int(getattr(layer, "dstport", None))


def _layer_attr(packet: Any, layer_name: str, attr_name: str) -> str | None:
    values = _layer_attr_values(packet, layer_name, attr_name)
    return values[0] if values else None


def _layer_attr_values(packet: Any, layer_name: str, attr_name: str) -> list[str]:
    layer = getattr(packet, layer_name, None)
    if layer is None:
        return []
    value = getattr(layer, attr_name, None)
    if value not in (None, ""):
        return _string_values(value)
    return _layer_field_values(layer, attr_name, layer_name=layer_name)


def _layer_field_value(layer: Any, attr_name: str, *, layer_name: str | None = None) -> Any:
    values = _layer_field_values(layer, attr_name, layer_name=layer_name)
    return values[0] if values else None


def _layer_field_values(layer: Any, attr_name: str, *, layer_name: str | None = None) -> list[str]:
    fields = getattr(layer, "_all_fields", {})
    candidates = _layer_field_candidates(attr_name, layer_name=layer_name)
    for candidate in candidates:
        value = fields.get(candidate)
        if value not in (None, ""):
            return _string_values(value)
    for key, value in fields.items():
        key_text = key.lower()
        attr_text = attr_name.lower()
        dotted_attr_text = attr_name.replace("_", ".").lower()
        if (
            key_text.endswith(f".{attr_text}")
            or key_text.endswith(f".{dotted_attr_text}")
        ) and value not in (None, ""):
            return _string_values(value)
    return []


def _layer_field_candidates(attr_name: str, *, layer_name: str | None = None) -> list[str]:
    candidates = [attr_name, attr_name.replace("_", ".")]
    if "_" in attr_name:
        prefix, suffix = attr_name.split("_", 1)
        candidates.append(f"{prefix}.{suffix}")
    if layer_name:
        candidates.extend(f"{layer_name}.{candidate}" for candidate in list(candidates))
    return list(dict.fromkeys(candidates))


def _string_values(value: Any) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, (list, tuple, set)):
        return [item for item in (_string_value(item) for item in value) if item]
    return [string_value] if (string_value := _string_value(value)) else []


def _string_value(value: Any) -> str | None:
    if value in (None, ""):
        return None
    for attr_name in ("showname_value", "raw_value", "value"):
        attr_value = getattr(value, attr_name, None)
        if attr_value not in (None, ""):
            return str(attr_value)
    return str(value)


def _layer_attr_values_from_layer(layer: Any, attr_name: str) -> list[str]:
    value = getattr(layer, attr_name, None)
    if value not in (None, ""):
        return _string_values(value)
    return _layer_field_values(layer, attr_name)


def _truthy_layer_attr(layer: Any, attr_name: str) -> bool:
    value = getattr(layer, attr_name, None)
    if value in (None, ""):
        values = _layer_field_values(layer, attr_name)
        return any(value not in ("0", "False", "false") for value in values)
    if value in (None, "", "0", "False", "false"):
        return False
    return True


def _safe_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        try:
            return int(str(value))
        except (TypeError, ValueError):
            return None


def _safe_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
