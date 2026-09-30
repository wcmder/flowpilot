from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..models import FlowSummary
from .deep_common import (
    DEFAULT_EVIDENCE_BATCH_SIZE,
    evidence_batch,
    field_command,
    parse_field_rows,
    tcp_flow_filter,
    tshark_path,
)

TCP_HEADER_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.len",
    "tcp.window_size_value",
    "tcp.window_size",
    "tcp.window_size_scalefactor",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.push",
    "tcp.options.mss_val",
    "tcp.options.mss.absent",
    "tcp.options.mss.present",
    "tcp.options.mss.exceeded",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.zero_window",
    "tcp.analysis.zero_window_probe",
    "tcp.analysis.window_update",
    "tcp.analysis.window_full",
    "tcp.analysis.window_full_segment",
    "tcp.analysis.bytes_in_flight",
    "tcp.analysis.initial_rtt",
]

TCP_ANALYSIS_FIELDS = [
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.zero_window",
    "tcp.analysis.zero_window_probe",
    "tcp.analysis.window_update",
    "tcp.analysis.window_full",
    "tcp.analysis.window_full_segment",
    "tcp.options.mss.absent",
    "tcp.options.mss.present",
    "tcp.options.mss.exceeded",
]
_TSHARK_FIELD_CACHE: dict[str, set[str]] = {}


def extract_tcp(packet, helpers) -> dict:
    protocol = helpers.protocol
    return {
        "rtt_seconds": _tcp_rtt_seconds(packet, helpers),
        "initial_rtt_seconds": _tcp_initial_rtt_seconds(packet, helpers),
        "issue_tags": _issue_tags(packet, helpers, protocol),
    }


def deep_tcp_reason(flow: FlowSummary) -> str | None:
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


def deep_tcp_flow(
    capture_path: Path,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
    sample_limit: int | None = DEFAULT_EVIDENCE_BATCH_SIZE,
    sample_offset: int = 0,
    timeout: int = 120,
) -> dict[str, Any]:
    if flow.key.protocol != "TCP":
        return {
            "tool": "deep_tcp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "skipped",
            "message": f"Flow protocol is {flow.key.protocol}, not TCP.",
        }

    tshark = tshark_path()
    if not tshark:
        return {
            "tool": "deep_tcp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = tcp_flow_filter(flow)
    deep_fields = tcp_deep_fields_for_tshark(tshark)
    command = field_command(tshark, capture_path, display_filter, deep_fields)
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {
            "tool": "deep_tcp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": str(exc),
        }

    if result.returncode != 0:
        return {
            "tool": "deep_tcp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": result.stderr.strip() or f"tshark exited with {result.returncode}",
        }

    rows = parse_tcp_rows(result.stdout, fields=deep_fields)
    return {
        "tool": "deep_tcp_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "tcp_analysis_counts": tcp_analysis_counts(rows),
        "tcp_window_stats": tcp_window_stats(rows),
        "tcp_header_fields": deep_fields,
        "tcp_header_samples": rows[
            sample_offset:sample_offset + sample_limit if sample_limit is not None else None
        ],
        "sample_limit": sample_limit,
        "truncated": sample_offset > 0 or (sample_limit is not None and len(rows) > sample_limit),
        "batch": evidence_batch(len(rows), sample_offset, sample_limit),
    }


def parse_tcp_rows(
    output: str,
    *,
    fields: list[str] | None = None,
) -> list[dict[str, str]]:
    return parse_field_rows(output, fields or TCP_HEADER_FIELDS)


def tcp_deep_fields_for_tshark(tshark: str) -> list[str]:
    available_fields = _tshark_field_names(tshark)
    if not available_fields:
        return list(TCP_HEADER_FIELDS)
    return [field for field in TCP_HEADER_FIELDS if field in available_fields]


def _tshark_field_names(tshark: str) -> set[str]:
    if tshark in _TSHARK_FIELD_CACHE:
        return _TSHARK_FIELD_CACHE[tshark]
    try:
        result = subprocess.run(
            [tshark, "-G", "fields"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        _TSHARK_FIELD_CACHE[tshark] = set()
        return set()
    if result.returncode != 0:
        _TSHARK_FIELD_CACHE[tshark] = set()
        return set()
    field_names = _parse_tshark_field_names(result.stdout)
    _TSHARK_FIELD_CACHE[tshark] = field_names
    return field_names


def _parse_tshark_field_names(fields_output: str) -> set[str]:
    field_names = set()
    for line in fields_output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            field_names.add(parts[2])
    return field_names


def tcp_analysis_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        for field in TCP_ANALYSIS_FIELDS:
            value = row.get(field)
            if value is not None and value not in {"", "0", "False", "false"}:
                counts[field] = counts.get(field, 0) + 1
    return counts


def tcp_window_stats(rows: list[dict[str, str]]) -> dict[str, int | list[int]]:
    advertised_windows = [
        value
        for row in rows
        if (value := _row_int(row.get("tcp.window_size"))) is not None
    ]
    raw_advertised_windows = [
        value
        for row in rows
        if (value := _row_int(row.get("tcp.window_size_value"))) is not None
    ]
    bytes_in_flight = [
        value
        for row in rows
        if (value := _row_int(row.get("tcp.analysis.bytes_in_flight"))) is not None
    ]
    scale_factors = sorted(
        {
            value
            for row in rows
            if (value := _row_int(row.get("tcp.window_size_scalefactor"))) is not None
        }
    )
    mss_values = sorted(
        {
            value
            for row in rows
            if (value := _row_int(row.get("tcp.options.mss_val"))) is not None
        }
    )
    stats: dict[str, int | list[int]] = {}
    if advertised_windows:
        stats["advertised_window_min"] = min(advertised_windows)
        stats["advertised_window_max"] = max(advertised_windows)
    if raw_advertised_windows:
        stats["raw_advertised_window_min"] = min(raw_advertised_windows)
        stats["raw_advertised_window_max"] = max(raw_advertised_windows)
    if bytes_in_flight:
        stats["bytes_in_flight_max"] = max(bytes_in_flight)
    if scale_factors:
        stats["window_scale_factors"] = scale_factors
    if mss_values:
        stats["mss_values"] = mss_values
        stats["mss_min"] = min(mss_values)
        stats["mss_max"] = max(mss_values)
    return stats


def _row_int(value: str | None) -> int | None:
    if value in {None, "", "False", "false"}:
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        return None


def _issue_tags(packet, helpers, protocol: str) -> list[str]:
    if protocol != "TCP":
        return []

    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return []

    analysis_issue_fields = {
        "tcp_retransmission": ("analysis_retransmission", "analysis_fast_retransmission"),
        "tcp_out_of_order": ("analysis_out_of_order",),
        "tcp_duplicate_ack": ("analysis_duplicate_ack",),
        "tcp_lost_segment": ("analysis_lost_segment",),
        "tcp_zero_window": ("analysis_zero_window", "analysis_zero_window_probe"),
    }
    issue_tags = [
        tag
        for tag, field_names in analysis_issue_fields.items()
        if any(_tcp_analysis_marker_present(tcp, helpers, field_name) for field_name in field_names)
    ]
    if helpers.truthy_layer_attr(tcp, "flags_reset"):
        issue_tags.append("tcp_reset")
    return issue_tags


def _tcp_analysis_marker_present(layer, helpers, attr_name: str) -> bool:
    if helpers.truthy_layer_attr(layer, attr_name):
        return True

    fields = getattr(layer, "_all_fields", {})
    for candidate in helpers.layer_field_candidates(attr_name, layer_name="tcp"):
        if candidate in fields and fields[candidate] not in ("0", "False", "false"):
            return True

    attr_text = attr_name.lower()
    dotted_attr_text = attr_name.replace("_", ".").lower()
    for key, value in fields.items():
        key_text = key.lower()
        if (
            key_text.endswith(f".{attr_text}")
            or key_text.endswith(f".{dotted_attr_text}")
        ) and value not in ("0", "False", "false"):
            return True
    return False


def _tcp_rtt_seconds(packet, helpers) -> float | None:
    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return None
    return helpers.safe_float(getattr(tcp, "analysis_ack_rtt", None))


def _tcp_initial_rtt_seconds(packet, helpers) -> float | None:
    tcp = getattr(packet, "tcp", None)
    if tcp is None:
        return None
    return helpers.safe_float(getattr(tcp, "analysis_initial_rtt", None))
