from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import FlowSummary
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
    return tuple(aliases)


def _deep_tool_priority(tool_name: str) -> int:
    return {
        "deep_tls_flow": 0,
        "deep_smb2_flow": 5,
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
