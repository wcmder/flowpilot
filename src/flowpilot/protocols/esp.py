from __future__ import annotations

import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from ..models import EspSequenceSummary, FlowSummary, PacketObservation
from .deep_common import (
    endpoint_filter_for_flow,
    field_command,
    parse_field_rows,
    tshark_path,
    udp_flow_filter,
)

ESP_DEEP_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "frame.len",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "ip.len",
    "ipv6.plen",
    "ip.ttl",
    "ipv6.hlim",
    "ip.dsfield.dscp",
    "ipv6.tclass.dscp",
    "ip.flags.df",
    "ip.frag_offset",
    "ip.id",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "esp.spi",
    "esp.sequence",
]
_TSHARK_FIELD_CACHE: dict[str, set[str]] = {}


def extract_esp(packet, helpers) -> dict:
    return {
        "esp_spi": helpers.layer_attr(packet, "esp", "spi"),
        "esp_sequence": helpers.safe_int(helpers.layer_attr(packet, "esp", "sequence")),
    }


def record_esp(flow: FlowSummary, packet: PacketObservation) -> None:
    if packet.esp_spi and packet.esp_spi not in flow.esp_spis:
        flow.esp_spis = [*flow.esp_spis, packet.esp_spi][:25]
    if packet.esp_spi and packet.esp_sequence is not None:
        record_esp_sequence(flow, packet)


def record_esp_sequence(flow: FlowSummary, packet: PacketObservation) -> None:
    direction = (
        f"{_endpoint(packet.src_ip, packet.src_port)} -> "
        f"{_endpoint(packet.dst_ip, packet.dst_port)}"
    )
    sequence = next(
        (
            item
            for item in flow.esp_sequences
            if item.spi == packet.esp_spi and item.direction == direction
        ),
        None,
    )
    if sequence is None:
        sequence = EspSequenceSummary(spi=packet.esp_spi, direction=direction)
        flow.esp_sequences = [*flow.esp_sequences, sequence][:25]

    current = packet.esp_sequence
    sequence.packet_count += 1
    if sequence.first_sequence is None:
        sequence.first_sequence = current
    is_duplicate = current in sequence.seen_sequences
    if is_duplicate:
        sequence.duplicate_count += 1
    if sequence.highest_sequence is not None and not is_duplicate:
        if current < sequence.highest_sequence:
            sequence.out_of_order_count += 1
        elif current > sequence.highest_sequence + 1:
            gap_size = current - sequence.highest_sequence
            missing_count = gap_size - 1
            sequence.gap_occurrences = [
                *sequence.gap_occurrences,
                {
                    "after_sequence": sequence.highest_sequence,
                    "next_sequence": current,
                    "gap": missing_count,
                    "missing": missing_count,
                },
            ]
            sequence.largest_sequence_gap = max(
                sequence.largest_sequence_gap,
                missing_count,
            )
    sequence.seen_sequences.add(current)
    sequence.highest_sequence = max(sequence.highest_sequence or current, current)
    sequence.last_sequence = current


def format_esp_sequences(sequences: list[EspSequenceSummary]) -> str:
    lines = []
    for sequence in sequences[:6]:
        lines.append(
            f"{sequence.direction} "
            f"pkts={sequence.packet_count} "
            f"missing={sequence.missing_count} "
            f"ooo={sequence.out_of_order_count} "
            f"dup={sequence.duplicate_count} "
            f"gaps={format_esp_gap_distribution(sequence.gap_occurrences)}"
        )
    if len(sequences) > 6:
        lines.append(f"... {len(sequences) - 6} more ESP directions/SPIs")
    return "\n".join(lines)


def format_esp_gap_distribution(gaps: list[dict[str, int]]) -> str:
    if not gaps:
        return "none"
    counts = Counter(gap["missing"] for gap in gaps)
    return " ".join(f"gap={missing}(x{count})" for missing, count in sorted(counts.items()))


def deep_esp_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol != "ESP":
        return None
    if flow.esp_sequences:
        return (
            "ESP/IPsec flow observed; inspect fragmentation, DSCP, TTL/hop-limit, "
            "packet size, and NAT-T headers. Use the Top Flows ESP sequence summary "
            "for missing, duplicate, and out-of-order sequence findings."
        )
    if flow.packet_count >= 100 and flow.throughput_mbps < 1:
        return (
            "Longer ESP/IPsec flow has low throughput; inspect ESP/IP headers for "
            "loss, reordering, fragmentation, or NAT-T visibility."
        )
    return None


def deep_esp_flow(
    capture_path: Path,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
    sample_limit: int = 200,
    timeout: int = 120,
) -> dict[str, Any]:
    if flow.key.protocol != "ESP":
        return {
            "tool": "deep_esp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "skipped",
            "message": f"Flow protocol is {flow.key.protocol}, not ESP.",
        }

    tshark = tshark_path()
    if not tshark:
        return {
            "tool": "deep_esp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = esp_flow_filter(flow)
    deep_fields = esp_deep_fields_for_tshark(tshark)
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
            "tool": "deep_esp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": str(exc),
        }

    if result.returncode != 0:
        return {
            "tool": "deep_esp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": result.stderr.strip() or f"tshark exited with {result.returncode}",
        }

    rows = parse_esp_rows(result.stdout, fields=deep_fields)
    return {
        "tool": "deep_esp_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "esp_metadata_counts": esp_metadata_counts(rows),
        "esp_deep_fields": deep_fields,
        "esp_deep_samples": _sample_esp_rows(rows, sample_limit),
        "sample_limit": sample_limit,
        "truncated": len(rows) > sample_limit,
    }


def esp_flow_filter(flow: FlowSummary) -> str:
    if flow.key.port_a is not None or flow.key.port_b is not None:
        # UDP/4500 also carries IKE and keepalives; require an actual ESP layer.
        return f"{udp_flow_filter(flow)} && esp"
    return f"{endpoint_filter_for_flow(flow)} && esp && !udp"


def parse_esp_rows(
    output: str,
    *,
    fields: list[str] | None = None,
) -> list[dict[str, str]]:
    return parse_field_rows(output, fields or ESP_DEEP_FIELDS)


def esp_deep_fields_for_tshark(tshark: str) -> list[str]:
    available_fields = _tshark_field_names(tshark)
    if not available_fields:
        return list(ESP_DEEP_FIELDS)
    return [field for field in ESP_DEEP_FIELDS if field in available_fields]


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


def esp_metadata_counts(rows: list[dict[str, str]]) -> dict[str, Any]:
    counters = Counter()
    dscp_values = set()
    ip_lengths = []
    df_values = set()
    for row in rows:
        counters["esp_packets"] += 1
        counters["nat_t_udp_4500_packets"] += int(_has_udp_4500(row))
        df_is_set = _truthy_row_value(row.get("ip.flags.df"))
        counters["df_set_packets"] += int(df_is_set)
        if row.get("ip.flags.df") not in {None, ""}:
            df_values.add("on" if df_is_set else "off")
        counters["fragmented_packets"] += int((_row_int(row.get("ip.frag_offset")) or 0) > 0)
        if dscp := _row_value(row, "ip.dsfield.dscp", "ipv6.tclass.dscp"):
            dscp_values.add(dscp)
        if ip_length := _row_int(_row_value(row, "ip.len", "ipv6.plen")):
            ip_lengths.append(ip_length)
    result = {key: value for key, value in counters.items() if value}
    if dscp_values:
        result["dscp_value_count"] = len(dscp_values)
        result["dscp_values"] = sorted(dscp_values)
    if ip_lengths:
        result["ip_length_min"] = min(ip_lengths)
        result["ip_length_max"] = max(ip_lengths)
    if df_values:
        result["df_bit"] = df_values.pop() if len(df_values) == 1 else "mixed"
    return result


def esp_direction_stats(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    directions: dict[str, dict[str, Any]] = {}
    for row in rows:
        src = row.get("src") or row.get("ip.src") or row.get("ipv6.src") or "unknown"
        dst = row.get("dst") or row.get("ip.dst") or row.get("ipv6.dst") or "unknown"
        direction = f"{src} -> {dst}"
        stats = directions.setdefault(
            direction,
            {
                "direction": direction,
                "packets": 0,
                "bytes": 0,
                "first_sequence": None,
                "last_sequence": None,
                "highest_sequence": None,
                "largest_sequence_gap": 0,
                "gap_counts": Counter(),
                "out_of_order_count": 0,
                "duplicate_count": 0,
                "seen_sequences": set(),
                "ttl_values": [],
                "dscp_values": set(),
                "df_set_packets": 0,
                "fragmented_packets": 0,
                "nat_t_udp_4500_packets": 0,
            },
        )
        stats["packets"] += 1
        stats["bytes"] += _row_int(_row_value(row, "frame.len", "ip.len", "ipv6.plen")) or 0
        _record_esp_direction_sequence(stats, _row_int(row.get("esp.sequence")))
        if ttl := _row_int(_row_value(row, "ip.ttl", "ipv6.hlim")):
            stats["ttl_values"].append(ttl)
        if dscp := _row_value(row, "ip.dsfield.dscp", "ipv6.tclass.dscp"):
            stats["dscp_values"].add(dscp)
        stats["df_set_packets"] += int(_truthy_row_value(row.get("ip.flags.df")))
        stats["fragmented_packets"] += int((_row_int(row.get("ip.frag_offset")) or 0) > 0)
        stats["nat_t_udp_4500_packets"] += int(_has_udp_4500(row))

    return [_compact_esp_direction_stats(stats) for stats in directions.values()]


def _record_esp_direction_sequence(stats: dict[str, Any], sequence: int | None) -> None:
    if sequence is None:
        return
    if stats["first_sequence"] is None:
        stats["first_sequence"] = sequence
    is_duplicate = sequence in stats["seen_sequences"]
    if is_duplicate:
        stats["duplicate_count"] += 1
    if stats["highest_sequence"] is not None and not is_duplicate:
        if sequence < stats["highest_sequence"]:
            stats["out_of_order_count"] += 1
        elif sequence > stats["highest_sequence"] + 1:
            missing_count = sequence - stats["highest_sequence"] - 1
            stats["gap_counts"][missing_count] += 1
            stats["largest_sequence_gap"] = max(stats["largest_sequence_gap"], missing_count)
    stats["seen_sequences"].add(sequence)
    stats["highest_sequence"] = max(stats["highest_sequence"] or sequence, sequence)
    stats["last_sequence"] = sequence


def _compact_esp_direction_stats(stats: dict[str, Any]) -> dict[str, Any]:
    seen_count = len(stats["seen_sequences"])
    if stats["first_sequence"] is not None and stats["highest_sequence"] is not None:
        expected_count = stats["highest_sequence"] - stats["first_sequence"] + 1
        missing_count = max(expected_count - seen_count, 0)
    else:
        missing_count = 0
    ttl_values = stats["ttl_values"]
    compact = {
        "direction": stats["direction"],
        "packets": stats["packets"],
        "bytes": stats["bytes"],
        "first_sequence": stats["first_sequence"],
        "last_sequence": stats["last_sequence"],
        "highest_sequence": stats["highest_sequence"],
        "missing_count": missing_count,
        "largest_sequence_gap": stats["largest_sequence_gap"],
        "gap_distribution": {
            f"gap={gap}": count for gap, count in sorted(stats["gap_counts"].items())
        },
        "out_of_order_count": stats["out_of_order_count"],
        "duplicate_count": stats["duplicate_count"],
        "ttl_min": min(ttl_values) if ttl_values else None,
        "ttl_max": max(ttl_values) if ttl_values else None,
        "dscp_values": sorted(stats["dscp_values"]),
        "df_set_packets": stats["df_set_packets"],
        "fragmented_packets": stats["fragmented_packets"],
        "nat_t_udp_4500_packets": stats["nat_t_udp_4500_packets"],
    }
    return {key: value for key, value in compact.items() if value not in (None, {}, [])}


def _sample_esp_rows(rows: list[dict[str, str]], sample_limit: int) -> list[dict[str, str]]:
    sample_fields = {
        "frame.number",
        "frame.time_relative",
        "src",
        "dst",
        "frame.len",
        "ip.len",
        "ipv6.plen",
        "ip.ttl",
        "ipv6.hlim",
        "ip.dsfield.dscp",
        "ipv6.tclass.dscp",
        "ip.flags.df",
        "ip.frag_offset",
        "udp.srcport",
        "udp.dstport",
        "udp.length",
        "esp.spi",
        "esp.sequence",
    }
    return [
        {key: value for key, value in row.items() if key in sample_fields}
        for row in rows[:sample_limit]
    ]


def _row_value(row: dict[str, str], *fields: str) -> str | None:
    for field in fields:
        if value := row.get(field):
            return value
    return None


def _row_int(value: str | None) -> int | None:
    if value in {None, "", "False", "false"}:
        return None
    try:
        return int(str(value), 0)
    except ValueError:
        return None


def _has_udp_4500(row: dict[str, str]) -> bool:
    return row.get("udp.srcport") == "4500" or row.get("udp.dstport") == "4500"


def _truthy_row_value(value: str | None) -> bool:
    return value not in {None, "", "0", "False", "false"}


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip
