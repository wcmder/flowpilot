"""Match decoded protocol names without changing transport flow identity."""
from __future__ import annotations

from .models import FlowSummary, PacketObservation

ALIASES = {"ISAKMP": "IKE", "IKEV1": "IKEV1", "IKEV2": "IKEV2",
           "IPV4": "IP", "ICMP6": "ICMPV6", "BOOTP": "DHCP", "SSL": "TLS"}


def canonical(name: str) -> str:
    value = name.strip().upper()
    return ALIASES.get(value, value)


def expanded(names) -> set[str]:
    result = {canonical(name) for name in names if name}
    if result & {"IKEV1", "IKEV2"}:
        result.add("IKE")
    if "SRTP" in result:
        result.add("RTP")
    if "SMB2" in result:
        result.add("SMB")
    return result


def packet_protocols(packet: PacketObservation) -> set[str]:
    names = expanded([packet.protocol, *packet.decoded_protocols])
    if packet.ike is not None:
        names.update(("IKE", f"IKEV{packet.ike.version >> 4}"))
    if packet.rtp_ssrc is not None:
        names.add("RTP")
    if packet.srtp:
        names.update(("RTP", "SRTP"))
    fields = {
        "DNS": ("dns_query", "dns_response_code", "dns_answers"),
        "DHCP": ("dhcp_message_type", "dhcp_transaction_id"),
        "SIP": ("sip_call_id", "sip_method", "sip_status_code"),
        "SMB": ("smb_command", "smb_commands_seen", "smb_status", "smb_encrypted"),
        "DTLS" if packet.protocol == "UDP" else "TLS":
            ("tls_sni", "tls_alert_level", "tls_alert_description", "tls_certificates"),
        "HTTP": ("http_host", "http_location"),
    }
    for protocol, attrs in fields.items():
        if any(getattr(packet, attr) not in (None, "", [], False) for attr in attrs):
            names.add(protocol)
    return names


def flow_protocols(flow: FlowSummary, direction: int | None = None) -> set[str]:
    names = expanded([flow.key.protocol])
    if direction is None:
        names.update(expanded(flow.decoded_protocols))
    else:
        names.update(expanded(flow.protocols_a_to_b if direction == 0 else flow.protocols_b_to_a))
    for packet in flow.packet_details:
        packet_direction = int(not (packet.src_ip == flow.key.endpoint_a and
                                   (flow.key.port_a is None or packet.src_port == flow.key.port_a)))
        if direction is None or packet_direction == direction:
            names.update(packet_protocols(packet))
    # Older summaries can establish application presence, but not generally its direction.
    for session in flow.ike_sessions:
        if direction is None or session.packets_by_direction[direction] > 0:
            names.update(("IKE", f"IKEV{session.version >> 4}"))
    for stream in flow.rtp_streams:
        if direction is None or stream.direction == ("A_to_B" if direction == 0 else "B_to_A"):
            names.add("RTP")
            if stream.srtp_packets:
                names.add("SRTP")
    if direction is not None:
        return names
    fields = {
        "DNS": ("dns_queries", "dns_response_codes", "dns_answers"),
        "DHCP": ("dhcp_message_types", "dhcp_transaction_ids"),
        "SIP": ("sip_call_ids", "sip_methods", "sip_statuses"),
        "SMB": ("smb_commands", "smb_statuses", "smb_encrypted_packets"),
        "DTLS" if flow.key.protocol == "UDP" else "TLS":
            ("tls_snis", "tls_certificates", "tls_alerts"),
        "HTTP": ("redirect_locations",),
    }
    for protocol, attrs in fields.items():
        if any(getattr(flow, attr) for attr in attrs):
            names.add(protocol)
    return names
