from __future__ import annotations

import ipaddress
import os
import shutil
from pathlib import Path

from dotenv import load_dotenv

from ..decode_as import tshark_decode_as_parameters
from ..models import FlowSummary
from ..paths import runtime_private_dir

load_dotenv(runtime_private_dir() / ".env")
load_dotenv()


DEFAULT_EVIDENCE_BATCH_SIZE = 1000


def tshark_path() -> str | None:
    configured_path = os.getenv("FLOWPILOT_TSHARK_PATH")
    if configured_path:
        path = Path(configured_path).expanduser()
        if path.exists():
            return str(path)
    path = shutil.which("tshark")
    if path:
        return path
    macos_app_path = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    if macos_app_path.exists():
        return str(macos_app_path)
    return None


def field_command(
    tshark: str,
    capture_path: Path,
    display_filter: str,
    fields: list[str],
    *,
    occurrence: str = "f",
    aggregator: str | None = None,
) -> list[str]:
    command = [
        tshark,
        *tshark_decode_as_parameters(),
        "-r",
        str(capture_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        f"occurrence={occurrence}",
    ]
    if aggregator:
        command.extend(["-E", f"aggregator={aggregator}"])
    for field in fields:
        command.extend(["-e", field])
    return command


def parse_field_rows(output: str, fields: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        values = line.split("\t")
        row = {
            field: values[index] if index < len(values) else ""
            for index, field in enumerate(fields)
        }
        row["src"] = (row.get("ip.src") or row.get("ipv6.src") or
                      row.get("eth.src") or row.get("wlan.sa", ""))
        row["dst"] = (row.get("ip.dst") or row.get("ipv6.dst") or
                      row.get("eth.dst") or row.get("wlan.da", ""))
        rows.append({key: value for key, value in row.items() if value != ""})
    return rows


def evidence_batch(total: int, offset: int, limit: int | None) -> dict:
    """Describe a page of matching packets, not a complete packet history."""
    if limit is None:
        limit = max(total, 1)
    if offset < 0 or limit <= 0:
        raise ValueError("Evidence offset must be nonnegative and batch size must be positive.")
    returned = max(0, min(limit, total - offset))
    next_offset = offset + returned if offset + returned < total else None
    return {
        "offset": offset,
        "offset_unit": "matching packets in capture order (zero-based), not frame number",
        "limit": limit,
        "returned": returned,
        "total_matching_packets": total,
        "has_more": next_offset is not None,
        "next_offset": next_offset,
        "scope": "Packet samples are one batch; aggregate counters cover all matching packets.",
        "hint": (
            "More packet details are available. Request the same tool and flow_id with "
            "sample_offset=next_offset in evidence_requests. Do not infer that later "
            "packets are healthy from this batch alone."
            if next_offset is not None else
            "No packets remain after this batch. Earlier batches may still be needed "
            "if this offset was requested directly."
        ),
    }


def tcp_flow_filter(flow: FlowSummary) -> str:
    return f"{_bidirectional_filter(flow, 'tcp')} && tcp"


def udp_flow_filter(flow: FlowSummary) -> str:
    return f"{_bidirectional_filter(flow, 'udp')} && udp"


def endpoint_filter_for_flow(flow: FlowSummary) -> str:
    return _bidirectional_filter(flow)


def _bidirectional_filter(flow: FlowSummary, transport: str | None = None) -> str:
    """Bind each port to its address, then reverse the entire endpoint pair."""
    family = _endpoint_address_family(flow.key.endpoint_a, flow.key.endpoint_b)
    fields = ["ip"] if family == 4 else ["ipv6"] if family == 6 else ["ip", "ipv6"]
    endpoints = [(flow.key.endpoint_a, flow.key.port_a), (flow.key.endpoint_b, flow.key.port_b)]
    branches = []
    for field in fields:
        for source, destination in (endpoints, endpoints[::-1]):
            terms = [f"{field}.src == {source[0]}", f"{field}.dst == {destination[0]}"]
            if transport:
                if source[1] is not None:
                    terms.append(f"{transport}.srcport == {source[1]}")
                if destination[1] is not None:
                    terms.append(f"{transport}.dstport == {destination[1]}")
            branches.append("(" + " && ".join(terms) + ")")
    return "(" + " || ".join(branches) + ")"


def _endpoint_address_family(endpoint_a: str, endpoint_b: str) -> int | None:
    try:
        address_a = ipaddress.ip_address(endpoint_a)
        address_b = ipaddress.ip_address(endpoint_b)
    except ValueError:
        return None
    if address_a.version == address_b.version:
        return address_a.version
    return None
