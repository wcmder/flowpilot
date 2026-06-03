from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ProtocolModule:
    name: str
    display_name: str
    flow_attributes: tuple[str, ...] = ()
    render_hook: str | None = None
    compact_metadata_key: str | None = None
    deep_tools: tuple[str, ...] = ()
    notes: str = ""
