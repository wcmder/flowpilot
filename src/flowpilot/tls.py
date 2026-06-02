from __future__ import annotations

from typing import Any

from .models import TlsCertificateObservation


def tls_sni(packet: Any) -> str | None:
    return _layer_attr(packet, "tls", "handshake_extensions_server_name") or _layer_attr(
        packet, "ssl", "handshake_extensions_server_name"
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

    certificates = _certificates_from_x509_layers(packet)
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


def _certificates_from_x509_layers(packet: Any) -> list[TlsCertificateObservation]:
    certificates = []
    for layer_name in ("x509af", "x509sat", "x509if"):
        certificates.extend(_certificate_from_x509_layer(getattr(packet, layer_name, None)))
    return certificates


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
    subject = _first_layer_value(
        layer,
        ("subject", "x509af_subject", "x509sat_printableString"),
    )
    issuer = _first_layer_value(layer, ("issuer", "x509af_issuer"))
    certificate = TlsCertificateObservation(
        presenter_ip=None,
        presenter_port=None,
        subject=subject,
        subject_cn=_common_name_from_text(subject),
        issuer=issuer,
        issuer_cn=_common_name_from_text(issuer),
        serial=_first_layer_value(layer, ("serialNumber", "serialnumber")),
        not_before=_first_layer_value(layer, ("utcTime", "notbefore", "notBefore")),
        not_after=_first_layer_value(layer, ("generalizedTime", "notafter", "notAfter")),
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
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        values = []
        for item in value:
            values.extend(_field_strings(item))
        return values
    for attr_name in ("show", "showname_value", "raw_value"):
        attr_value = getattr(value, attr_name, None)
        if isinstance(attr_value, str):
            return [attr_value]
    return []


def _split_values(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]
