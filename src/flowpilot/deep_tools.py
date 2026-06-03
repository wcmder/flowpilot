from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .deep import deep_tcp_flow, deep_tls_flow, deep_udp_flow
from .models import FlowSummary

DeepToolRunner = Callable[..., dict[str, Any]]
DeepReason = Callable[[FlowSummary], str | None]


@dataclass(frozen=True)
class DeepTool:
    name: str
    runner: DeepToolRunner
    reason: DeepReason
    aliases: tuple[str, ...] = ()

    @property
    def name_pattern(self) -> str:
        names = (self.name, *self.aliases)
        return r"\b(?:" + "|".join(_tool_phrase_pattern(name) for name in names) + r")\b"

    def run(
        self,
        capture_path: Path,
        *,
        flow_id: int,
        flow: FlowSummary,
        reason: str,
    ) -> dict[str, Any]:
        return self.runner(capture_path, flow_id=flow_id, flow=flow, reason=reason)


def deep_tool_names() -> set[str]:
    return set(ALLOWED_DEEP_TOOL_NAMES)


def deep_tool_name_pattern(tool_name: str) -> str:
    tool = DEEP_TOOL_REGISTRY[tool_name]
    return tool.name_pattern


def deep_tool_reason(tool_name: str, flow: FlowSummary) -> str | None:
    return DEEP_TOOL_REGISTRY[tool_name].reason(flow)


def deep_tool_requests_for_flow(flow_id: int, flow: FlowSummary) -> dict[str, Any] | None:
    for tool in DEEP_TOOLS:
        reason = tool.reason(flow)
        if reason:
            return {"tool": tool.name, "flow_id": flow_id, "reason": reason}
    return None


def run_deep_tool(
    tool_name: str,
    capture_path: Path,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
) -> dict[str, Any]:
    return DEEP_TOOL_REGISTRY[tool_name].run(
        capture_path,
        flow_id=flow_id,
        flow=flow,
        reason=reason,
    )


def _tls_deep_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol not in {"TCP", "UDP"}:
        return None
    if flow.tls_alerts:
        return "TLS/DTLS alert observed; inspect TLS/DTLS handshake, alert, and transport headers."
    if flow.tls_certificates:
        return (
            "TLS certificates observed; inspect complete TLS certificate chain "
            "and handshake fields."
        )
    if flow.tls_snis:
        return "TLS SNI observed; inspect TLS ClientHello and related transport headers."
    if flow.key.protocol == "TCP" and any(port in {443, 853, 8443} for port in _flow_ports(flow)):
        return "Likely TLS flow by TCP port; inspect TLS handshake and TCP headers."
    if flow.key.protocol == "UDP" and any(port in {443, 853, 4433} for port in _flow_ports(flow)):
        return "Likely DTLS or encrypted UDP flow by port; inspect DTLS and UDP headers."
    return None


def _tcp_deep_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol != "TCP":
        return None
    tcp_issues = {
        issue: count
        for issue, count in flow.issue_counts.items()
        if issue.startswith("tcp_") and count > 0
    }
    if tcp_issues:
        return f"TCP issue counters observed: {tcp_issues}."
    if flow.is_one_way:
        return "One-way TCP flow observed; inspect headers for handshake/reset/window clues."
    if flow.packet_count >= 100 and flow.throughput_mbps < 1:
        return "Longer TCP flow has low throughput; inspect headers for transport constraints."
    return None


def _udp_deep_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol != "UDP":
        return None
    if flow.dns_error_count:
        return "DNS error responses observed; inspect UDP/DNS transaction details."
    if flow.dns_queries or flow.dns_response_codes or flow.dns_answers:
        return "DNS metadata observed; inspect UDP/DNS transaction timing and answers."
    if flow.dhcp_message_types and not any("ACK" in key.upper() for key in flow.dhcp_message_types):
        return "DHCP exchange appears incomplete; inspect UDP/DHCP transaction details."
    if flow.dhcp_message_types:
        return "DHCP metadata observed; inspect UDP/DHCP transaction, lease, and server details."
    if flow.is_one_way:
        return "One-way UDP flow observed; inspect UDP headers and response visibility."
    return None


def _flow_ports(flow: FlowSummary) -> list[int]:
    return [port for port in (flow.key.port_a, flow.key.port_b) if port is not None]


def _tool_phrase_pattern(name: str) -> str:
    return r"[\s_-]+".join(re.escape(part) for part in re.split(r"[\s_-]+", name))


DEEP_TOOLS: tuple[DeepTool, ...] = (
    DeepTool(
        name="deep_tls_flow",
        runner=deep_tls_flow,
        reason=_tls_deep_reason,
        aliases=("deep tls flow", "deep-tls-flow"),
    ),
    DeepTool(
        name="deep_tcp_flow",
        runner=deep_tcp_flow,
        reason=_tcp_deep_reason,
        aliases=("deep tcp flow", "deep-tcp-flow"),
    ),
    DeepTool(
        name="deep_udp_flow",
        runner=deep_udp_flow,
        reason=_udp_deep_reason,
        aliases=("deep udp flow", "deep-udp-flow"),
    ),
)

DEEP_TOOL_REGISTRY = {tool.name: tool for tool in DEEP_TOOLS}
ALLOWED_DEEP_TOOL_NAMES = set(DEEP_TOOL_REGISTRY)
