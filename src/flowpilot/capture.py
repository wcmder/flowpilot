from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import PacketObservation
from .protocols.smb import SMB2_COMMAND_NAMES
from .protocols.tls import tls_alert, tls_certificates, tls_sni


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

    certificates = tls_certificates(packet)
    certificates = [
        certificate.model_copy(update={"presenter_ip": src_ip, "presenter_port": src_port})
        for certificate in certificates
    ]

    smb_commands = _smb_commands(packet)
    tls_alert_level, tls_alert_description = tls_alert(packet)

    return PacketObservation(
        timestamp=_timestamp(packet),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=_safe_int(getattr(packet, "length", 0)) or 0,
        rtt_seconds=_tcp_rtt_seconds(packet),
        initial_rtt_seconds=_tcp_initial_rtt_seconds(packet),
        issue_tags=[
            *_issue_tags(packet, protocol),
            *_tls_issue_tags(tls_alert_level, tls_alert_description),
        ],
        esp_spi=_layer_attr(packet, "esp", "spi"),
        esp_sequence=_safe_int(_layer_attr(packet, "esp", "sequence")),
        dns_query=_layer_attr(packet, "dns", "qry_name"),
        dns_query_type=_layer_attr(packet, "dns", "qry_type"),
        dns_response_code=_layer_attr(packet, "dns", "flags_rcode"),
        dns_answers=_dns_answers(packet),
        dhcp_message_type=_dhcp_value(packet, "option_dhcp"),
        dhcp_transaction_id=_dhcp_value(packet, "id"),
        dhcp_client_mac=_dhcp_value(packet, "hw_mac_addr"),
        dhcp_hostname=_dhcp_value(packet, "option_hostname"),
        dhcp_requested_ip=_dhcp_value(packet, "option_requested_ip_address"),
        dhcp_your_ip=_dhcp_value(packet, "ip_your"),
        dhcp_server_id=_dhcp_value(packet, "option_dhcp_server_id"),
        dhcp_lease_time=_dhcp_value(packet, "option_ip_address_lease_time"),
        http_host=_layer_attr(packet, "http", "host"),
        http_location=_layer_attr(packet, "http", "location"),
        tls_sni=tls_sni(packet),
        tls_alert_level=tls_alert_level,
        tls_alert_description=tls_alert_description,
        tls_certificates=certificates,
        sip_call_id=_layer_attr(packet, "sip", "call_id"),
        sip_method=_layer_attr(packet, "sip", "method"),
        sip_status_code=_safe_int(_layer_attr(packet, "sip", "status_code")),
        sip_reason=_layer_attr(packet, "sip", "reason_phrase"),
        sip_from=_layer_attr(packet, "sip", "from_addr") or _layer_attr(packet, "sip", "from"),
        sip_to=_layer_attr(packet, "sip", "to_addr") or _layer_attr(packet, "sip", "to"),
        smb_command=smb_commands[0] if smb_commands else None,
        smb_commands_seen=smb_commands,
        smb_status=_smb_value(packet, "nt_status") or _smb_value(packet, "status"),
        smb_message_id=_smb_value(packet, "msg_id") or _smb_value(packet, "mid"),
        smb_is_response=_smb_is_response(packet),
        smb_session_id=_smb_value(packet, "sesid") or _smb_value(packet, "session_id"),
        smb_tree_id=_smb_value(packet, "tid") or _smb_value(packet, "tree_id"),
        smb_file_id=_smb_file_id(packet),
        smb_filename=_smb_value(packet, "file") or _smb_value(packet, "filename"),
        smb_create_desired_access=_smb_int_value(
            packet,
            (
                "create.desired_access",
                "create_desired_access",
                "desired_access",
                "create_access_mask",
            ),
        ),
        smb_create_file_attributes=_smb_int_value(
            packet,
            (
                "create.file_attributes",
                "create_file_attributes",
                "file_attributes",
            ),
        ),
        smb_read_length=_smb_transfer_length(
            packet,
            (
                "read_length",
                "read_count",
                "read_data_len",
                "read_data_length",
                "data_length",
                "data_len",
                "data_len_low",
                "data_size",
                "file_rw_length",
                "count",
                "count_low",
                "dc",
                "tdc",
                "bcc",
            ),
        ),
        smb_write_length=_smb_transfer_length(
            packet,
            (
                "write_length",
                "write_count",
                "write_data_len",
                "write_data_length",
                "data_length",
                "data_len",
                "data_len_low",
                "data_size",
                "file_rw_length",
                "count",
                "count_low",
                "dc",
                "tdc",
                "bcc",
            ),
        ),
        smb_file_offset=_smb_file_offset(packet),
        smb_encrypted=_smb_encrypted(packet),
        smb_capabilities=_smb_capabilities(packet),
    )


def _tls_issue_tags(level: str | None, description: str | None) -> list[str]:
    if not level and not description:
        return []
    tags = ["tls_alert"]
    alert_text = f"{level or ''} {description or ''}".lower()
    if "fatal" in alert_text or alert_text.startswith("2"):
        tags.append("tls_fatal_alert")
    return tags


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


def _dns_answers(packet: Any) -> list[str]:
    dns = getattr(packet, "dns", None)
    if dns is None:
        return []
    answers = []
    for attr_name in ("a", "aaaa", "resp_addr"):
        value = getattr(dns, attr_name, None)
        if not value:
            continue
        answers.extend(str(value).split(","))
    return [answer.strip() for answer in answers if answer.strip()]


def _dhcp_value(packet: Any, attr_name: str) -> str | None:
    for layer_name in ("dhcp", "bootp"):
        value = _layer_attr(packet, layer_name, attr_name)
        if value:
            return value
    return None


def _smb_int_value(packet: Any, attr_names: tuple[str, ...]) -> int | None:
    match = _smb_int_match(packet, attr_names)
    return match[1] if match else None


def _smb_int_match(packet: Any, attr_names: tuple[str, ...]) -> tuple[str, int] | None:
    for attr_name in attr_names:
        value = _safe_int(_smb_value(packet, attr_name))
        if value is not None:
            return attr_name, value
    return None


def _smb_commands(packet: Any) -> list[str]:
    smb2_layer = getattr(packet, "smb2", None)
    smb2_commands = [
        *(_layer_attr_values(packet, "smb2", "cmd")),
        *(_layer_attr_values(packet, "smb2", "command")),
    ]
    if smb2_commands:
        return [SMB2_COMMAND_NAMES.get(command.lower(), command) for command in smb2_commands]
    if smb2_layer is not None:
        commands = [*(_smb_values(packet, "cmd")), *(_smb_values(packet, "command"))]
        return [SMB2_COMMAND_NAMES.get(command.lower(), command) for command in commands]
    return _layer_attr_values(packet, "smb", "cmd")


def _smb_value(packet: Any, attr_name: str) -> str | None:
    values = _smb_values(packet, attr_name)
    return values[0] if values else None


def _smb_values(packet: Any, attr_name: str) -> list[str]:
    for layer_name in ("smb2", "smb"):
        values = _layer_attr_values(packet, layer_name, attr_name)
        if values:
            return values
    return []


def _smb_is_response(packet: Any) -> bool | None:
    response_flag = _first_smb_value(packet, ("flags_response", "flags_response_to"))
    if response_flag is None:
        return None
    return response_flag not in {"0", "False", "false"}


def _smb_file_id(packet: Any) -> str | None:
    return _first_smb_value(
        packet,
        (
            "file_id",
            "fid",
            "fid_hash",
            "server_fid",
            "create_file_id",
            "create_file_id_64b",
        ),
    )


def _first_smb_value(packet: Any, attr_names: tuple[str, ...]) -> str | None:
    for attr_name in attr_names:
        value = _smb_value(packet, attr_name)
        if value:
            return value
    return None


def _smb_transfer_length(packet: Any, attr_names: tuple[str, ...]) -> int | None:
    match = _smb_int_match(packet, attr_names)
    if match is None:
        return None
    attr_name, length = match
    base_name = attr_name.removesuffix("_low")
    high = _smb_int_value(packet, (f"{base_name}_high",))
    if high:
        return length + (high << 32)
    return length


def _smb_file_offset(packet: Any) -> int | None:
    match = _smb_int_match(
        packet,
        (
            "file_offset",
            "file_rw_offset",
            "offset",
            "offset_low",
        ),
    )
    if match is None:
        return None
    attr_name, offset = match
    base_name = attr_name.removesuffix("_low")
    high = _smb_int_value(packet, (f"{base_name}_high",))
    if high:
        return offset + (high << 32)
    return offset


def _smb_encrypted(packet: Any) -> bool:
    smb2_layer = getattr(packet, "smb2", None)
    if smb2_layer is None:
        return False
    encrypted_field_names = (
        "transform_header",
        "transform_session_id",
        "transform_signature",
        "transform_nonce",
        "transform_original_message_size",
    )
    if any(_truthy_layer_attr(smb2_layer, field_name) for field_name in encrypted_field_names):
        return True
    fields = getattr(smb2_layer, "_all_fields", {})
    return any(
        _is_smb_encrypted_payload_field(key)
        and value not in (None, "", "0", "False", "false")
        for key, value in fields.items()
    )


def _is_smb_encrypted_payload_field(field_name: str) -> bool:
    field_name = field_name.lower()
    return "transform" in field_name


def _smb_capabilities(packet: Any) -> list[str]:
    capabilities = []
    for layer_name, fields in _SMB_CAPABILITY_FIELDS.items():
        layer = getattr(packet, layer_name, None)
        if layer is None:
            continue
        for attr_name, label in fields:
            if _truthy_layer_attr(layer, attr_name):
                capabilities.append(label)
        if layer_name == "smb2":
            capabilities.extend(_smb2_capability_mask_labels(layer))
        if layer_name == "smb2" and _smb2_encryption_capabilities(layer):
            capabilities.append("encryption")
    for label, value in (
        ("dialect", _smb_value(packet, "dialect") or _smb_value(packet, "dialect_name")),
        ("security_mode", _smb_value(packet, "sec_mode") or _smb_value(packet, "sm")),
    ):
        if value:
            capabilities.append(f"{label}={value}")
    return list(dict.fromkeys(capabilities))


def _smb2_capability_mask_labels(layer: Any) -> list[str]:
    capability_values = [
        *_layer_attr_values_from_layer(layer, "capabilities"),
        *_layer_attr_values_from_layer(layer, "server_cap"),
    ]
    labels = []
    for capability_value in capability_values:
        capability_mask = _safe_int(capability_value)
        if capability_mask is None:
            continue
        labels.extend(
            label
            for bit, label in _SMB2_CAPABILITY_MASKS.items()
            if capability_mask & bit
        )
    return labels


def _layer_attr_values_from_layer(layer: Any, attr_name: str) -> list[str]:
    value = getattr(layer, attr_name, None)
    if value not in (None, ""):
        return _string_values(value)
    return _layer_field_values(layer, attr_name)


def _smb2_encryption_capabilities(layer: Any) -> bool:
    encryption_capability_fields = (
        "encryption_capabilities",
        "encryption_capabilities_ciphers",
        "encryption_context",
        "negotiate_context_encryption_capabilities",
        "neg_context_encryption_capabilities",
    )
    if any(_truthy_layer_attr(layer, field_name) for field_name in encryption_capability_fields):
        return True
    fields = getattr(layer, "_all_fields", {})
    for key, value in fields.items():
        key_text = key.lower()
        values = " ".join(_string_values(value)).lower()
        combined = f"{key_text} {values}"
        if "encryption" in combined and ("capabil" in combined or "cipher" in combined):
            return True
        if "smb2_encryption_capabilities" in combined:
            return True
    return False


_SMB_CAPABILITY_FIELDS = {
    "smb2": (
        ("capabilities_dfs", "DFS"),
        ("capabilities_leasing", "leasing"),
        ("capabilities_large_mtu", "large MTU"),
        ("capabilities_multi_channel", "multi-channel"),
        ("capabilities_persistent_handles", "persistent handles"),
        ("capabilities_directory_leasing", "directory leasing"),
        ("capabilities_encryption", "encryption"),
        ("capabilities_notifications", "notifications"),
        ("sec_mode_sign_enabled", "signing enabled"),
        ("sec_mode_sign_required", "signing required"),
        ("ses_flags_encrypt", "session encryption"),
        ("share_flags_encrypt_data", "share encryption required"),
        ("share_flags_compress_data", "compressed IO"),
    ),
    "smb": (
        ("server_cap_large_readx", "large ReadX"),
        ("server_cap_large_writex", "large WriteX"),
        ("flags2_compressed", "compression requested"),
        ("unix_capability_large_read", "unix large read"),
        ("unix_capability_large_write", "unix large write"),
        ("unix_capability_encryption", "unix encryption"),
        ("unix_capability_mandatory_crypto", "unix mandatory encryption"),
    ),
}

_SMB2_CAPABILITY_MASKS = {
    0x0001: "DFS",
    0x0002: "leasing",
    0x0004: "large MTU",
    0x0008: "multi-channel",
    0x0010: "persistent handles",
    0x0020: "directory leasing",
    0x0040: "encryption",
    0x0080: "notifications",
}


def _issue_tags(packet: Any, protocol: str) -> list[str]:
    if protocol != "TCP":
        return []

    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return []

    analysis_issue_fields = {
        "tcp_retransmission": ("analysis_retransmission", "analysis_fast_retransmission"),
        "tcp_out_of_order": ("analysis_out_of_order",),
        "tcp_duplicate_ack": ("analysis_duplicate_ack",),
        "tcp_lost_segment": ("analysis_lost_segment",),
        "tcp_zero_window": ("analysis_zero_window", "analysis_zero_window_probe"),
    }
    issue_tags = [
        tag
        for tag, field_names in analysis_issue_fields.items()
        if any(_tcp_analysis_marker_present(tcp, field_name) for field_name in field_names)
    ]
    if _truthy_layer_attr(tcp, "flags_reset"):
        issue_tags.append("tcp_reset")
    return issue_tags


def _tcp_analysis_marker_present(layer: Any, attr_name: str) -> bool:
    if _truthy_layer_attr(layer, attr_name):
        return True

    fields = getattr(layer, "_all_fields", {})
    for candidate in _layer_field_candidates(attr_name, layer_name="tcp"):
        if candidate in fields and fields[candidate] not in ("0", "False", "false"):
            return True

    attr_text = attr_name.lower()
    dotted_attr_text = attr_name.replace("_", ".").lower()
    for key, value in fields.items():
        key_text = key.lower()
        if (
            key_text.endswith(f".{attr_text}")
            or key_text.endswith(f".{dotted_attr_text}")
        ) and value not in ("0", "False", "false"):
            return True
    return False


def _truthy_layer_attr(layer: Any, attr_name: str) -> bool:
    value = getattr(layer, attr_name, None)
    if value in (None, ""):
        values = _layer_field_values(layer, attr_name)
        return any(value not in ("0", "False", "false") for value in values)
    if value in (None, "", "0", "False", "false"):
        return False
    return True


def _tcp_rtt_seconds(packet: Any) -> float | None:
    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return None
    return _safe_float(getattr(tcp, "analysis_ack_rtt", None))


def _tcp_initial_rtt_seconds(packet: Any) -> float | None:
    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return None
    return _safe_float(getattr(tcp, "analysis_initial_rtt", None))


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
