from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import PacketObservation, TlsCertificateObservation


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
    if tls_keylog_file is None:
        return None
    if not tls_keylog_file.exists():
        raise FileNotFoundError(tls_keylog_file)
    return [
        "-o",
        f"tls.keylog_file:{tls_keylog_file}",
        "-o",
        "tls.desegment_ssl_records:TRUE",
        "-o",
        "tls.desegment_ssl_application_data:TRUE",
        "-o",
        "tcp.desegment_tcp_streams:TRUE",
    ]


def packet_to_observation(packet: Any) -> PacketObservation | None:
    src_ip, dst_ip = _ip_pair(packet)
    if not src_ip or not dst_ip:
        return None

    protocol = _transport_protocol(packet)
    src_port, dst_port = _ports(packet, protocol)

    tls_certificates = _tls_certificates(packet)
    tls_certificates = [
        certificate.model_copy(update={"presenter_ip": src_ip, "presenter_port": src_port})
        for certificate in tls_certificates
    ]

    return PacketObservation(
        timestamp=_timestamp(packet),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        length=_safe_int(getattr(packet, "length", 0)) or 0,
        rtt_seconds=_tcp_rtt_seconds(packet),
        issue_tags=_issue_tags(packet, protocol),
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
        tls_sni=_layer_attr(packet, "tls", "handshake_extensions_server_name")
        or _layer_attr(packet, "ssl", "handshake_extensions_server_name"),
        tls_certificates=tls_certificates,
        sip_call_id=_layer_attr(packet, "sip", "call_id"),
        sip_method=_layer_attr(packet, "sip", "method"),
        sip_status_code=_safe_int(_layer_attr(packet, "sip", "status_code")),
        sip_reason=_layer_attr(packet, "sip", "reason_phrase"),
        sip_from=_layer_attr(packet, "sip", "from_addr") or _layer_attr(packet, "sip", "from"),
        sip_to=_layer_attr(packet, "sip", "to_addr") or _layer_attr(packet, "sip", "to"),
        smb_command=_smb_value(packet, "cmd"),
        smb_status=_smb_value(packet, "nt_status") or _smb_value(packet, "status"),
        smb_session_id=_smb_value(packet, "sesid") or _smb_value(packet, "session_id"),
        smb_tree_id=_smb_value(packet, "tid") or _smb_value(packet, "tree_id"),
        smb_filename=_smb_value(packet, "file") or _smb_value(packet, "filename"),
        smb_read_length=_smb_int_value(
            packet,
            (
                "read_length",
                "read_count",
                "read_data_len",
                "data_len",
                "data_size",
                "file_rw_length",
                "count",
            ),
        ),
        smb_write_length=_smb_int_value(
            packet,
            (
                "write_length",
                "write_count",
                "write_data_len",
                "data_len",
                "data_size",
                "file_rw_length",
                "count",
            ),
        ),
    )


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
    layer = getattr(packet, layer_name, None)
    if layer is None:
        return None
    value = getattr(layer, attr_name, None)
    return str(value) if value else None


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


def _smb_value(packet: Any, attr_name: str) -> str | None:
    for layer_name in ("smb2", "smb"):
        value = _layer_attr(packet, layer_name, attr_name)
        if value:
            return value
    return None


def _smb_int_value(packet: Any, attr_names: tuple[str, ...]) -> int | None:
    for attr_name in attr_names:
        value = _safe_int(_smb_value(packet, attr_name))
        if value is not None:
            return value
    return None


def _tls_certificates(packet: Any) -> list[TlsCertificateObservation]:
    layer = getattr(packet, "x509sat", None) or getattr(packet, "x509if", None)
    tls = (
        getattr(packet, "tls", None)
        or getattr(packet, "ssl", None)
        or getattr(packet, "dtls", None)
    )

    certificates = _certificate_from_x509_layer(layer)
    if certificates:
        return certificates

    certificates = _certificates_from_raw_handshake(tls)
    if certificates:
        return certificates

    fallback = TlsCertificateObservation(
        subject=_first_layer_value(tls, ("x509af_subject", "handshake_certificate_subject")),
        issuer=_first_layer_value(tls, ("x509af_issuer", "handshake_certificate_issuer")),
        serial=_first_layer_value(tls, ("x509af_serialnumber", "handshake_certificate_serial")),
        not_before=_first_layer_value(
            tls,
            ("x509af_notbefore", "handshake_certificate_not_before"),
        ),
        not_after=_first_layer_value(tls, ("x509af_notafter", "handshake_certificate_not_after")),
        san_dns=_split_values(
            _first_layer_value(tls, ("x509ce_subjectaltname_dnsname", "handshake_certificate_san"))
        ),
        fingerprint_sha256=_first_layer_value(
            tls,
            ("x509af_fingerprint_sha256", "handshake_certificate_fingerprint_sha256"),
        ),
    )
    if any([fallback.subject, fallback.issuer, fallback.serial, fallback.fingerprint_sha256]):
        return [fallback]
    return []


def _certificates_from_raw_handshake(layer: Any) -> list[TlsCertificateObservation]:
    raw_certificates = _all_field_values(layer, "handshake.certificate")
    certificates = []
    for raw_certificate in raw_certificates:
        certificate = _certificate_from_der_hex(raw_certificate)
        if certificate:
            certificates.append(certificate)
    return certificates


def _certificate_from_der_hex(raw_certificate: str) -> TlsCertificateObservation | None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        return None

    try:
        certificate_bytes = bytes.fromhex(raw_certificate.replace(":", ""))
        certificate = x509.load_der_x509_certificate(certificate_bytes)
    except ValueError:
        return None

    san_dns = []
    try:
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return TlsCertificateObservation(
        presenter_ip=None,
        presenter_port=None,
        subject=certificate.subject.rfc4514_string(),
        subject_cn=_name_common_name(certificate.subject),
        issuer=certificate.issuer.rfc4514_string(),
        issuer_cn=_name_common_name(certificate.issuer),
        serial=f"{certificate.serial_number:x}",
        not_before=certificate.not_valid_before_utc.isoformat(),
        not_after=certificate.not_valid_after_utc.isoformat(),
        san_dns=san_dns,
        fingerprint_sha256=certificate.fingerprint(hashes.SHA256()).hex(),
    )


def _certificate_from_x509_layer(layer: Any) -> list[TlsCertificateObservation]:
    if layer is None:
        return []
    certificate = TlsCertificateObservation(
        presenter_ip=None,
        presenter_port=None,
        subject=_first_layer_value(layer, ("subject", "x509sat_printableString")),
        subject_cn=None,
        issuer=_first_layer_value(layer, ("issuer",)),
        issuer_cn=None,
        serial=_first_layer_value(layer, ("serialNumber", "serialnumber")),
        not_before=_first_layer_value(layer, ("utcTime", "notbefore")),
        not_after=_first_layer_value(layer, ("generalizedTime", "notafter")),
        san_dns=_split_values(_first_layer_value(layer, ("dNSName", "dnsname"))),
        fingerprint_sha256=_first_layer_value(layer, ("fingerprint_sha256",)),
    )
    if any([certificate.subject, certificate.issuer, certificate.serial, certificate.san_dns]):
        return [certificate]
    return []


def _name_common_name(name: Any) -> str | None:
    try:
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    return attributes[0].value


def _first_layer_value(layer: Any, attr_names: tuple[str, ...]) -> str | None:
    if layer is None:
        return None
    for attr_name in attr_names:
        value = getattr(layer, attr_name, None)
        if value:
            return str(value)
    return None


def _all_field_values(layer: Any, field_suffix: str) -> list[str]:
    if layer is None:
        return []
    fields = getattr(layer, "_all_fields", {})
    values = [
        value
        for key, value in fields.items()
        if key.lower().endswith(field_suffix.lower()) and isinstance(value, str)
    ]
    return values


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _issue_tags(packet: Any, protocol: str) -> list[str]:
    if protocol != "TCP":
        return []

    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return []

    issue_fields = {
        "tcp_retransmission": ("analysis_retransmission", "analysis_fast_retransmission"),
        "tcp_out_of_order": ("analysis_out_of_order",),
        "tcp_duplicate_ack": ("analysis_duplicate_ack",),
        "tcp_lost_segment": ("analysis_lost_segment",),
        "tcp_zero_window": ("analysis_zero_window", "analysis_zero_window_probe"),
        "tcp_reset": ("flags_reset",),
    }
    return [
        tag
        for tag, field_names in issue_fields.items()
        if any(_truthy_layer_attr(tcp, field_name) for field_name in field_names)
    ]


def _truthy_layer_attr(layer: Any, attr_name: str) -> bool:
    value = getattr(layer, attr_name, None)
    if value in (None, "", "0", "False", "false"):
        return False
    return True


def _tcp_rtt_seconds(packet: Any) -> float | None:
    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return None
    return _safe_float(getattr(tcp, "analysis_ack_rtt", None))


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
