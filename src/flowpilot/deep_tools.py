from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import FlowSummary
from .protocols.deep_common import DEFAULT_EVIDENCE_BATCH_SIZE, evidence_batch
from .protocols.registry import deep_tool_hooks

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
        sample_offset: int = 0,
    ) -> dict[str, Any]:
        options = {"sample_offset": sample_offset} if sample_offset else {}
        return self.runner(capture_path, flow_id=flow_id, flow=flow, reason=reason, **options)


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
    capture_path: Path | None,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
    sample_offset: int = 0,
) -> dict[str, Any]:
    saved = flow.deep_details.get(tool_name)
    if saved and saved.get("status") == "ok":
        sample_key = _SAMPLE_KEYS[tool_name]
        rows = saved[sample_key]
        return {
            **saved,
            "flow_id": flow_id,
            "reason": reason,
            "source": "saved_summary",
            sample_key: rows[sample_offset:sample_offset + DEFAULT_EVIDENCE_BATCH_SIZE],
            "sample_limit": DEFAULT_EVIDENCE_BATCH_SIZE,
            "truncated": sample_offset > 0 or len(rows) > DEFAULT_EVIDENCE_BATCH_SIZE,
            "batch": evidence_batch(len(rows), sample_offset, DEFAULT_EVIDENCE_BATCH_SIZE),
        }
    if capture_path is None:
        return {"tool": tool_name, "flow_id": flow_id, "status": "unavailable",
                "message": "No saved details for this tool and no capture path supplied."}
    return DEEP_TOOL_REGISTRY[tool_name].run(
        capture_path,
        flow_id=flow_id,
        flow=flow,
        reason=reason,
        sample_offset=sample_offset,
    )


_SAMPLE_KEYS = {
    "deep_rtp_flow": "rtp_header_samples",
    "deep_tcp_flow": "tcp_header_samples",
    "deep_udp_flow": "udp_header_samples",
    "deep_tls_flow": "tls_deep_samples",
    "deep_smb2_flow": "smb2_deep_samples",
    "deep_esp_flow": "esp_deep_samples",
}


def collect_flow_details(capture_path: Path, flow: FlowSummary, flow_id: int) -> None:
    """Save all extracted rows for each supported tool, including explicit failures."""
    tools = {
        "TCP": ("deep_tcp_flow", "deep_tls_flow", "deep_smb2_flow"),
        "UDP": ("deep_udp_flow", "deep_tls_flow", "deep_rtp_flow"),
        "ESP": ("deep_esp_flow",),
    }.get(flow.key.protocol, ())
    for tool in tools:
        try:
            flow.deep_details[tool] = DEEP_TOOL_REGISTRY[tool].runner(
                capture_path, flow_id=flow_id, flow=flow, reason="Build detailed summary",
                sample_limit=None,
            )
        except Exception as exc:  # Preserve observations and other tools at this boundary.
            flow.deep_details[tool] = {
                "tool": tool, "flow_id": flow_id, "status": "error",
                "message": f"{type(exc).__name__}: {exc}",
            }
        flow.deep_details[tool]["detail_scope"] = (
            "All matching packets in the original PCAP for this tool's flow/protocol filter. "
            "Initial packet observations may be a subset if packet-level filters/limits were used."
        )


def _tool_phrase_pattern(name: str) -> str:
    return r"[\s_-]+".join(re.escape(part) for part in re.split(r"[\s_-]+", name))


def _deep_tool_aliases(tool_name: str) -> tuple[str, ...]:
    spaced = tool_name.replace("_", " ")
    hyphenated = tool_name.replace("_", "-")
    aliases = [spaced, hyphenated]
    if tool_name.startswith("deep_") and tool_name.endswith("_flow"):
        protocol = tool_name.removeprefix("deep_").removesuffix("_flow")
        aliases.extend(
            (
                f"deep {protocol} tool",
                f"deep-{protocol}-tool",
                f"deep_{protocol}_tool",
            )
        )
        if protocol == "smb2":
            aliases.extend(
                (
                    "deep smb flow",
                    "deep-smb-flow",
                    "deep_smb_flow",
                    "deep smb tool",
                    "deep-smb-tool",
                    "deep_smb_tool",
                )
            )
    return tuple(aliases)


def _deep_tool_priority(tool_name: str) -> int:
    return {
        "deep_rtp_flow": -1,
        "deep_tls_flow": 0,
        "deep_smb2_flow": 5,
        "deep_esp_flow": 8,
        "deep_tcp_flow": 10,
        "deep_udp_flow": 20,
    }.get(tool_name, 100)


DEEP_TOOLS: tuple[DeepTool, ...] = tuple(
    DeepTool(
        name=tool_name,
        runner=runner,
        reason=reason,
        aliases=_deep_tool_aliases(tool_name),
    )
    for tool_name, runner, reason in sorted(
        deep_tool_hooks(),
        key=lambda hook: _deep_tool_priority(hook[0]),
    )
)

DEEP_TOOL_REGISTRY = {tool.name: tool for tool in DEEP_TOOLS}
ALLOWED_DEEP_TOOL_NAMES = set(DEEP_TOOL_REGISTRY)
