from __future__ import annotations

from .base import ProtocolModule

PROTOCOLS: tuple[ProtocolModule, ...] = (
    ProtocolModule(
        name="tcp",
        display_name="TCP",
        flow_attributes=(
            "issue_counts",
            "retransmission_rate",
            "packet_loss_rate",
            "rtt_initial_ms",
        ),
        compact_metadata_key="transport",
        deep_tools=("deep_tcp_flow",),
        notes="Transport troubleshooting metadata and TCP deep header rereads.",
    ),
    ProtocolModule(
        name="udp",
        display_name="UDP",
        flow_attributes=("is_one_way", "packet_rate_per_second", "throughput_mbps"),
        compact_metadata_key="transport",
        deep_tools=("deep_udp_flow",),
        notes="UDP transport metadata plus DNS/DHCP deep transaction rereads.",
    ),
    ProtocolModule(
        name="tls",
        display_name="TLS/DTLS",
        flow_attributes=(
            "tls_snis",
            "tls_sni_endpoints",
            "tls_certificates",
            "tls_alerts",
        ),
        render_hook="flowpilot.protocols.tls.render_tls_details",
        compact_metadata_key="tls",
        deep_tools=("deep_tls_flow",),
        notes="Visible TLS/DTLS handshake, certificate, SNI, alert, and algorithm metadata.",
    ),
    ProtocolModule(
        name="smb",
        display_name="SMB",
        flow_attributes=(
            "smb_commands",
            "smb_statuses",
            "smb_read_bytes",
            "smb_write_bytes",
            "smb_diagnostic_hints",
        ),
        render_hook="flowpilot.protocols.smb.render_smb_details",
        compact_metadata_key="smb",
        notes="SMB command/status, capability, file transfer, and efficiency metadata.",
    ),
    ProtocolModule(
        name="sip",
        display_name="SIP",
        flow_attributes=("sip_calls", "sip_call_ids", "sip_methods", "sip_statuses"),
        render_hook="flowpilot.protocols.sip.render_sip_details",
        compact_metadata_key="sip",
        notes="SIP call identity, caller/callee, methods, status, issue, and trace metadata.",
    ),
    ProtocolModule(
        name="dns",
        display_name="DNS",
        flow_attributes=(
            "dns_queries",
            "dns_query_types",
            "dns_response_codes",
            "dns_answers",
        ),
        render_hook="flowpilot.protocols.dns.render_dns_details",
        compact_metadata_key="dns",
        notes="DNS query, type, response code, answer, and error metadata.",
    ),
    ProtocolModule(
        name="dhcp",
        display_name="DHCP",
        flow_attributes=(
            "dhcp_message_types",
            "dhcp_transaction_ids",
            "dhcp_client_macs",
            "dhcp_requested_ips",
            "dhcp_offered_ips",
            "dhcp_server_ids",
        ),
        render_hook="flowpilot.protocols.dhcp.render_dhcp_details",
        compact_metadata_key="dhcp",
        notes="DHCP transaction, client, requested/offered address, server, and lease metadata.",
    ),
    ProtocolModule(
        name="esp",
        display_name="ESP/IPsec",
        flow_attributes=("esp_sequences",),
        compact_metadata_key="esp",
        notes="ESP SPI and visible sequence gap/out-of-order/duplicate metadata.",
    ),
)

PROTOCOL_REGISTRY = {protocol.name: protocol for protocol in PROTOCOLS}


def protocols() -> tuple[ProtocolModule, ...]:
    return PROTOCOLS


def protocol_names() -> set[str]:
    return set(PROTOCOL_REGISTRY)
