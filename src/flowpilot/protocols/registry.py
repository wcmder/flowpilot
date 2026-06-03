from __future__ import annotations

import importlib
from collections.abc import Callable

from ..models import FlowSummary, PacketObservation
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
        extract_hook="flowpilot.protocols.tcp.extract_tcp",
        compact_metadata_key="transport",
        deep_tools=("deep_tcp_flow",),
        deep_tool_runner_hooks=("flowpilot.protocols.tcp.deep_tcp_flow",),
        deep_reason_hook="flowpilot.protocols.tcp.deep_tcp_reason",
        transport_prompt=(
            "TCP: focus on loss, retransmissions, duplicate ACKs, out-of-order delivery, "
            "resets, zero windows, initial RTT, throughput, and directionality."
        ),
        notes="Transport troubleshooting metadata and TCP deep header rereads.",
    ),
    ProtocolModule(
        name="udp",
        display_name="UDP",
        flow_attributes=("is_one_way", "packet_rate_per_second", "throughput_mbps"),
        compact_metadata_key="transport",
        deep_tools=("deep_udp_flow",),
        deep_tool_runner_hooks=("flowpilot.protocols.udp.deep_udp_flow",),
        deep_reason_hook="flowpilot.protocols.udp.deep_udp_reason",
        transport_prompt=(
            "UDP: focus on one-way visibility, packet rate, throughput, checksum status, "
            "port reachability, and request/response visibility."
        ),
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
        extract_hook="flowpilot.protocols.tls.extract_tls",
        record_hook="flowpilot.protocols.tls.record_tls",
        render_hook="flowpilot.protocols.tls.render_tls_details",
        compact_metadata_key="tls",
        deep_tools=("deep_tls_flow",),
        deep_tool_runner_hooks=("flowpilot.protocols.tls.deep_tls_flow",),
        deep_reason_hook="flowpilot.protocols.tls.deep_tls_reason",
        transport_prompt=(
            "TLS/DTLS: use SNI, certificates, cipher/hash/signature/group fields, and alerts "
            "only to explain handshake compatibility, authentication/session failure, "
            "session termination, or transfer reachability."
        ),
        security_prompt=(
            "TLS/DTLS: assess certificate validity, issuer/subject/SAN consistency, "
            "alert meaning, cipher/hash/signature/group negotiation, and authentication "
            "or session-failure evidence. Do not claim vulnerabilities beyond supplied metadata."
        ),
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
        extract_hook="flowpilot.protocols.smb.extract_smb",
        record_hook="flowpilot.protocols.smb.record_smb",
        render_hook="flowpilot.protocols.smb.render_smb_details",
        compact_metadata_key="smb",
        deep_tools=("deep_smb2_flow",),
        deep_tool_runner_hooks=("flowpilot.protocols.smb.deep_smb2_flow",),
        deep_reason_hook="flowpilot.protocols.smb.deep_smb2_reason",
        transport_prompt=(
            "SMB: assess transfer efficiency from read/write operations, bytes, files, "
            "SMB2 credit request/grant/charge, statuses, errors, TCP symptoms, duration, "
            "and transfer_mbps."
        ),
        security_prompt=(
            "SMB: assess encryption/signing/capability clues, authentication/session failures, "
            "unexpected cleartext visibility, and status values relevant to access failures."
        ),
        notes="SMB command/status, capability, file transfer, and efficiency metadata.",
    ),
    ProtocolModule(
        name="sip",
        display_name="SIP",
        flow_attributes=("sip_calls", "sip_call_ids", "sip_methods", "sip_statuses"),
        extract_hook="flowpilot.protocols.sip.extract_sip",
        record_hook="flowpilot.protocols.sip.record_sip",
        render_hook="flowpilot.protocols.sip.render_sip_details",
        compact_metadata_key="sip",
        transport_prompt=(
            "SIP: use per-call trace, caller/callee, methods, status codes, and direction "
            "to identify call setup failure, response code, and likely next network checks."
        ),
        security_prompt=(
            "SIP: assess authentication or session-failure signals visible in SIP methods, "
            "status codes, caller/callee, and trace metadata."
        ),
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
        extract_hook="flowpilot.protocols.dns.extract_dns",
        record_hook="flowpilot.protocols.dns.record_dns",
        render_hook="flowpilot.protocols.dns.render_dns_details",
        compact_metadata_key="dns",
        transport_prompt=(
            "DNS: look for NXDOMAIN, SERVFAIL, refused responses, missing answers, "
            "request/response visibility, and resolution failures that block data transfer."
        ),
        security_prompt=(
            "DNS: assess suspicious or unexpected names, NXDOMAIN/SERVFAIL/refused responses, "
            "and answer patterns only when DNS metadata is present."
        ),
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
        extract_hook="flowpilot.protocols.dhcp.extract_dhcp",
        record_hook="flowpilot.protocols.dhcp.record_dhcp",
        render_hook="flowpilot.protocols.dhcp.render_dhcp_details",
        compact_metadata_key="dhcp",
        transport_prompt=(
            "DHCP: look for incomplete discover/offer/request/ack exchanges, repeated requests, "
            "missing ACKs, server identifiers, lease details, and requested versus offered "
            "addresses."
        ),
        security_prompt=(
            "DHCP: assess unexpected server identifiers, client identity clues, repeated leases, "
            "and incomplete exchanges only when DHCP metadata is present."
        ),
        notes="DHCP transaction, client, requested/offered address, server, and lease metadata.",
    ),
    ProtocolModule(
        name="esp",
        display_name="ESP/IPsec",
        flow_attributes=("esp_sequences",),
        extract_hook="flowpilot.protocols.esp.extract_esp",
        record_hook="flowpilot.protocols.esp.record_esp",
        compact_metadata_key="esp",
        transport_prompt=(
            "ESP/IPsec: reason from duration, bytes, throughput, directionality, SPI, sequence "
            "gaps, missing or duplicate sequence numbers, out-of-order sequences, and peer "
            "behavior."
        ),
        security_prompt=(
            "ESP/IPsec: assess visible tunnel metadata such as SPI, peer behavior, sequence "
            "anomalies, and replay/duplicate indicators without claiming decrypted content."
        ),
        notes="ESP SPI and visible sequence gap/out-of-order/duplicate metadata.",
    ),
)

PROTOCOL_REGISTRY = {protocol.name: protocol for protocol in PROTOCOLS}


def protocols() -> tuple[ProtocolModule, ...]:
    return PROTOCOLS


def protocol_names() -> set[str]:
    return set(PROTOCOL_REGISTRY)


def record_hooks() -> tuple[Callable[[FlowSummary, PacketObservation], None], ...]:
    hooks = []
    for protocol in PROTOCOLS:
        if protocol.record_hook:
            hooks.append(_load_hook(protocol.record_hook))
    return tuple(hooks)


def extract_hooks() -> tuple[Callable, ...]:
    hooks = []
    for protocol in PROTOCOLS:
        if protocol.extract_hook:
            hooks.append(_load_hook(protocol.extract_hook))
    return tuple(hooks)


def deep_tool_hooks() -> tuple[tuple[str, Callable, Callable], ...]:
    hooks = []
    for protocol in PROTOCOLS:
        if not protocol.deep_tools:
            continue
        if len(protocol.deep_tools) != len(protocol.deep_tool_runner_hooks):
            raise ValueError(f"Protocol {protocol.name} deep tool metadata is inconsistent.")
        if not protocol.deep_reason_hook:
            raise ValueError(f"Protocol {protocol.name} is missing a deep reason hook.")
        reason = _load_hook(protocol.deep_reason_hook)
        for tool_name, runner_hook in zip(
            protocol.deep_tools,
            protocol.deep_tool_runner_hooks,
            strict=True,
        ):
            hooks.append((tool_name, _load_hook(runner_hook), reason))
    return tuple(hooks)


def _load_hook(path: str):
    module_name, function_name = path.rsplit(".", 1)
    module = importlib.import_module(module_name)
    return getattr(module, function_name)
