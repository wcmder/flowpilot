from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from rich.console import Console
from rich.table import Table

from ..models import CaptureSummary, TlsCertificateObservation


def tls_sni(packet: Any) -> str | None:
    return _layer_attr(packet, "tls", "handshake_extensions_server_name") or _layer_attr(
        packet,
        "ssl",
        "handshake_extensions_server_name",
    )


def tls_alert(packet: Any) -> tuple[str | None, str | None]:
    layer = (
        getattr(packet, "tls", None)
        or getattr(packet, "ssl", None)
        or getattr(packet, "dtls", None)
    )
    return (
        _first_layer_value(
            layer,
            (
                "alert_message_level",
                "alert_level",
                "record_alert_level",
            ),
        ),
        _first_layer_value(
            layer,
            (
                "alert_message_desc",
                "alert_description",
                "record_alert_description",
            ),
        ),
    )


def tls_certificates(packet: Any) -> list[TlsCertificateObservation]:
    tls = (
        getattr(packet, "tls", None)
        or getattr(packet, "ssl", None)
        or getattr(packet, "dtls", None)
    )

    certificates = _deduplicate_certificates(
        [
            *_certificates_from_x509_layers(packet),
            *_certificates_from_raw_handshake(tls),
        ]
    )
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


def render_tls_details(summary: CaptureSummary, *, show_flows: int, console: Console) -> None:
    table = tls_details_table(summary, show_flows=show_flows)
    if table:
        console.print(table)


def tls_details_table(summary: CaptureSummary, *, show_flows: int) -> Table | None:
    rows = tls_detail_rows(summary, show_flows=show_flows)
    if not rows:
        return None

    table = Table(title="TLS Details Observed In Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("SNI", overflow="fold")
    table.add_column("Subject", overflow="fold")
    table.add_column("Issuer", overflow="fold")
    table.add_column("Expiration", overflow="fold")
    table.add_column("SAN", overflow="fold")
    table.add_column("Issue", overflow="fold")

    for flow_id, flow, role, endpoint, certificates in rows:
        table.add_row(
            str(flow_id),
            tls_endpoint_with_role(endpoint, role),
            tls_sni_for_endpoint(flow, endpoint),
            format_certificate_column(certificates, "subject"),
            format_certificate_column(certificates, "issuer"),
            format_certificate_column(certificates, "expiration"),
            format_certificate_column(certificates, "san"),
            tls_issue_text(flow, endpoint, certificates),
        )
    return table


def tls_endpoint_with_role(endpoint: str, role: str) -> str:
    return endpoint if role == "-" else f"{endpoint}\n({role})"


def tls_sni_for_endpoint(flow, endpoint: str) -> str:
    return "\n".join(flow.tls_sni_endpoints.get(endpoint, [])[:5]) or "-"


def tls_detail_rows(
    summary: CaptureSummary,
    *,
    show_flows: int,
) -> list[tuple[int, object, str, str, list]]:
    flow_ids = _flow_ids(summary.flows)
    certificate_flows = []
    observed_tls_rows = []
    for flow in summary.flows[:show_flows]:
        if flow.tls_certificates:
            certificate_flows.extend(_tls_certificate_rows(flow_ids[id(flow)], flow))
        elif flow.tls_snis or flow.tls_alerts or _likely_tls_flow(flow):
            observed_tls_rows.append((flow_ids[id(flow)], flow, "-", _flow_endpoint_text(flow), []))
    return [*certificate_flows, *observed_tls_rows][:show_flows]


def _tls_certificate_rows(flow_id: int, flow) -> list[tuple[int, object, str, str, list]]:
    groups: dict[tuple[str, str], list] = {}
    for certificate in flow.tls_certificates:
        role = certificate.presenter_role or "-"
        endpoint = certificate_endpoint(flow, certificate)
        groups.setdefault((role, endpoint), []).append(certificate)
    return [
        (flow_id, flow, role, endpoint, certificates)
        for (role, endpoint), certificates in groups.items()
    ]


def format_certificate_column(certificates: list, field_name: str) -> str:
    values = []
    for index, certificate in enumerate(certificates, start=1):
        values.append(f"Cert {index}: {_certificate_field(certificate, field_name)}")
    return "\n".join(values) or "-"


def _certificate_field(certificate, field_name: str) -> str:
    if field_name == "subject":
        return certificate.subject_cn or certificate.subject or "-"
    if field_name == "issuer":
        return certificate.issuer_cn or certificate.issuer or "-"
    if field_name == "expiration":
        return expiration(certificate)
    if field_name == "san":
        return ", ".join(certificate.san_dns[:5]) or "-"
    return "-"


def format_tls_certificates(flow) -> str:
    lines = []
    for index, certificate in enumerate(flow.tls_certificates, start=1):
        parts = [
            f"cert {index}",
            f"role={certificate.presenter_role or '-'}",
            f"endpoint={certificate_endpoint(flow, certificate)}",
            f"subject={certificate.subject_cn or certificate.subject or '-'}",
            f"issuer={certificate.issuer_cn or certificate.issuer or '-'}",
            f"expiration={expiration(certificate)}",
            f"san={', '.join(certificate.san_dns[:5]) or '-'}",
        ]
        certificate_issues = certificate_issue_lines(certificate)
        if certificate_issues:
            parts.append(f"issue={'; '.join(certificate_issues)}")
        lines.append(" / ".join(parts))
    return "\n".join(lines) or "-"


def tls_issue_text(flow, endpoint: str, certificates: list | None = None) -> str:
    issues = []
    is_flow_endpoint = endpoint == _flow_endpoint_text(flow)
    endpoint_alerts = (
        flow.tls_alerts
        if is_flow_endpoint
        else flow.tls_alert_endpoints.get(endpoint, {})
    )
    if endpoint_alerts:
        issues.extend(
            f"{'tls alert' if is_flow_endpoint else 'sent tls alert'}: {alert} (x{count})"
            for alert, count in endpoint_alerts.items()
        )
    for certificate in certificates or []:
        issues.extend(certificate_issue_lines(certificate))
    if not flow.tls_certificates:
        if flow.tls_alerts and not endpoint_alerts and endpoint != _flow_endpoint_text(flow):
            issues.append("tls alert sent by peer")
        issues.append("tls observed but certificate not extracted")
    return "\n".join(issues)


def certificate_issue_lines(certificate) -> list[str]:
    issues = []
    expires_at = parse_certificate_datetime(certificate.not_after)
    starts_at = parse_certificate_datetime(certificate.not_before)
    now = datetime.now(timezone.utc)
    if expires_at and expires_at < now:
        issues.append(f"certificate expired {certificate.not_after}")
    if starts_at and starts_at > now:
        issues.append(f"certificate not valid until {certificate.not_before}")
    return issues


def certificate_endpoint(flow, certificate) -> str:
    ip = certificate.presenter_ip
    port = certificate.presenter_port
    if ip:
        return _endpoint(ip, port)
    return (
        f"{_endpoint(flow.key.endpoint_a, flow.key.port_a)} or "
        f"{_endpoint(flow.key.endpoint_b, flow.key.port_b)}"
    )


def expiration(certificate) -> str:
    if not certificate.not_after:
        return "-"
    return certificate.not_after[:10] if len(certificate.not_after) >= 10 else certificate.not_after


def parse_certificate_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _likely_tls_flow(flow) -> bool:
    return flow.key.protocol == "TCP" and any(
        port in {443, 853, 8443}
        for port in (flow.key.port_a, flow.key.port_b)
    )


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip


def _flow_endpoint_text(flow) -> str:
    return (
        f"{_endpoint(flow.key.endpoint_a, flow.key.port_a)} <-> "
        f"{_endpoint(flow.key.endpoint_b, flow.key.port_b)}"
    )


def _flow_ids(flows) -> dict[object, int]:
    return {id(flow): index for index, flow in enumerate(flows, start=1)}


def _certificates_from_x509_layers(packet: Any) -> list[TlsCertificateObservation]:
    certificates = []
    for layer_name in ("x509af", "x509sat", "x509if"):
        for layer in _packet_layers(packet, layer_name):
            certificates.extend(_certificate_from_x509_layer(layer))
    return certificates


def _packet_layers(packet: Any, layer_name: str) -> list[Any]:
    get_multiple_layers = getattr(packet, "get_multiple_layers", None)
    if callable(get_multiple_layers):
        layers = get_multiple_layers(layer_name)
        if layers:
            return list(layers)
    layer = getattr(packet, layer_name, None)
    return [layer] if layer is not None else []


def _deduplicate_certificates(
    certificates: list[TlsCertificateObservation],
) -> list[TlsCertificateObservation]:
    deduplicated = []
    seen = set()
    for certificate in certificates:
        key = (
            certificate.fingerprint_sha256,
            certificate.serial,
            certificate.subject,
            certificate.issuer,
            certificate.subject_cn,
            certificate.issuer_cn,
        )
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(certificate)
    return deduplicated


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
    subjects = _layer_values(
        layer,
        ("subject", "x509af_subject", "x509sat_printableString"),
    )
    issuers = _layer_values(layer, ("issuer", "x509af_issuer"))
    serials = _layer_values(layer, ("serialNumber", "serialnumber"))
    not_befores = _layer_values(layer, ("utcTime", "notbefore", "notBefore"))
    not_afters = _layer_values(layer, ("generalizedTime", "notafter", "notAfter"))
    san_values = _layer_values(layer, ("dNSName", "dnsname"))
    fingerprints = _layer_values(layer, ("fingerprint_sha256",))
    count = max(
        len(subjects),
        len(issuers),
        len(serials),
        len(not_befores),
        len(not_afters),
        len(san_values),
        len(fingerprints),
    )
    certificates = []
    for index in range(count):
        subject = _indexed_value(subjects, index)
        issuer = _indexed_value(issuers, index)
        certificate = TlsCertificateObservation(
            presenter_ip=None,
            presenter_port=None,
            subject=subject,
            subject_cn=_common_name_from_text(subject),
            issuer=issuer,
            issuer_cn=_common_name_from_text(issuer),
            serial=_indexed_value(serials, index),
            not_before=_indexed_value(not_befores, index),
            not_after=_indexed_value(not_afters, index),
            san_dns=_split_values(_indexed_value(san_values, index)),
            fingerprint_sha256=_indexed_value(fingerprints, index),
        )
        if any([certificate.subject, certificate.issuer, certificate.serial, certificate.san_dns]):
            certificates.append(certificate)
    return certificates


def _name_common_name(name: Any) -> str | None:
    try:
        from cryptography.x509.oid import NameOID
    except ImportError:
        return None

    attributes = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return None
    return attributes[0].value


def _common_name_from_text(value: str | None) -> str | None:
    if not value:
        return None
    for part in value.split(","):
        part = part.strip()
        if part.lower().startswith("cn="):
            return part[3:].strip()
    return None


def _layer_attr(packet: Any, layer_name: str, attr_name: str) -> str | None:
    layer = getattr(packet, layer_name, None)
    if layer is None:
        return None
    value = getattr(layer, attr_name, None)
    return str(value) if value else None


def _first_layer_value(layer: Any, attr_names: tuple[str, ...]) -> str | None:
    if layer is None:
        return None
    for attr_name in attr_names:
        value = getattr(layer, attr_name, None)
        if value:
            values = _field_strings(value)
            return values[0] if values else str(value)
        values = _all_field_values(layer, attr_name)
        if values:
            return values[0]
    return None


def _layer_values(layer: Any, attr_names: tuple[str, ...]) -> list[str]:
    if layer is None:
        return []
    for attr_name in attr_names:
        value = getattr(layer, attr_name, None)
        if value:
            values = _field_strings(value)
            return values if values else [str(value)]
        values = _all_field_values(layer, attr_name)
        if values:
            return values
    return []


def _indexed_value(values: list[str], index: int) -> str | None:
    if not values:
        return None
    if index < len(values):
        return values[index]
    return None


def _all_field_values(layer: Any, field_suffix: str) -> list[str]:
    if layer is None:
        return []
    fields = getattr(layer, "_all_fields", {})
    values = []
    for key, value in fields.items():
        if key.lower().endswith(field_suffix.lower()):
            values.extend(_field_strings(value))
    return values


def _field_strings(value: Any) -> list[str]:
    if value is None:
        return []
    all_fields = getattr(value, "all_fields", None)
    if all_fields:
        values = []
        for field in all_fields:
            values.extend(_field_strings(field))
        return values
    if isinstance(value, (list, tuple)):
        values = []
        for item in value:
            values.extend(_field_strings(item))
        return values
    if isinstance(value, str):
        return [value]
    for attr_name in ("show", "showname_value", "raw_value"):
        attr_value = getattr(value, attr_name, None)
        if isinstance(attr_value, str):
            return [attr_value]
    return []


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]
