from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProtocolModule:
    name: str
    display_name: str
    flow_attributes: tuple[str, ...] = ()
    extract_hook: str | None = None
    record_hook: str | None = None
    render_hook: str | None = None
    compact_metadata_key: str | None = None
    deep_tools: tuple[str, ...] = ()
    deep_tool_runner_hooks: tuple[str, ...] = ()
    deep_reason_hook: str | None = None
    notes: str = ""
