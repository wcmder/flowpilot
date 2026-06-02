from __future__ import annotations

import ipaddress
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .models import FlowSummary

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
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.push",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.lost_segment",
    "tcp.analysis.out_of_order",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
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
    "tcp.analysis.window_full",
]

UDP_HEADER_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "udp.checksum",
    "udp.checksum.status",
    "dns.id",
    "dns.flags.response",
    "dns.qry.name",
    "dns.qry.type",
    "dns.flags.rcode",
    "dns.resp.name",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.time",
    "bootp.id",
    "bootp.option.dhcp",
    "bootp.hw.mac_addr",
    "bootp.option.hostname",
    "bootp.option.requested_ip_address",
    "bootp.ip.your",
    "bootp.option.dhcp_server_id",
    "bootp.option.ip_address_lease_time",
]


def deep_tcp_flow(
    capture_path: Path,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
    sample_limit: int = 200,
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

    tshark = _tshark_path()
    if not tshark:
        return {
            "tool": "deep_tcp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = _tcp_flow_filter(flow)
    command = [
        tshark,
        "-r",
        str(capture_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    for field in TCP_HEADER_FIELDS:
        command.extend(["-e", field])

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

    rows = _parse_tshark_rows(result.stdout)
    return {
        "tool": "deep_tcp_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "tcp_analysis_counts": _tcp_analysis_counts(rows),
        "tcp_header_fields": TCP_HEADER_FIELDS,
        "tcp_header_samples": rows[:sample_limit],
        "sample_limit": sample_limit,
        "truncated": len(rows) > sample_limit,
    }


def deep_udp_flow(
    capture_path: Path,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
    sample_limit: int = 200,
    timeout: int = 120,
) -> dict[str, Any]:
    if flow.key.protocol != "UDP":
        return {
            "tool": "deep_udp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "skipped",
            "message": f"Flow protocol is {flow.key.protocol}, not UDP.",
        }

    tshark = _tshark_path()
    if not tshark:
        return {
            "tool": "deep_udp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = _udp_flow_filter(flow)
    command = _field_command(tshark, capture_path, display_filter, UDP_HEADER_FIELDS)
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
            "tool": "deep_udp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": str(exc),
        }

    if result.returncode != 0:
        return {
            "tool": "deep_udp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": result.stderr.strip() or f"tshark exited with {result.returncode}",
        }

    rows = _parse_field_rows(result.stdout, UDP_HEADER_FIELDS)
    return {
        "tool": "deep_udp_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "udp_metadata_counts": _udp_metadata_counts(rows),
        "udp_header_fields": UDP_HEADER_FIELDS,
        "udp_header_samples": rows[:sample_limit],
        "sample_limit": sample_limit,
        "truncated": len(rows) > sample_limit,
    }


def _tcp_flow_filter(flow: FlowSummary) -> str:
    endpoint_filter = _endpoint_filter(flow)
    ports = [port for port in (flow.key.port_a, flow.key.port_b) if port is not None]
    if not ports:
        return f"{endpoint_filter} && tcp"
    port_filter = " && ".join(f"tcp.port == {port}" for port in sorted(set(ports)))
    return f"{endpoint_filter} && {port_filter}"


def _udp_flow_filter(flow: FlowSummary) -> str:
    endpoint_filter = _endpoint_filter(flow)
    ports = [port for port in (flow.key.port_a, flow.key.port_b) if port is not None]
    if not ports:
        return f"{endpoint_filter} && udp"
    port_filter = " && ".join(f"udp.port == {port}" for port in sorted(set(ports)))
    return f"{endpoint_filter} && {port_filter}"


def _endpoint_filter(flow: FlowSummary) -> str:
    family = _endpoint_address_family(flow.key.endpoint_a, flow.key.endpoint_b)
    if family == 6:
        return f"(ipv6.addr == {flow.key.endpoint_a} && ipv6.addr == {flow.key.endpoint_b})"
    if family == 4:
        return f"(ip.addr == {flow.key.endpoint_a} && ip.addr == {flow.key.endpoint_b})"
    return (
        f"((ip.addr == {flow.key.endpoint_a} && ip.addr == {flow.key.endpoint_b}) || "
        f"(ipv6.addr == {flow.key.endpoint_a} && ipv6.addr == {flow.key.endpoint_b}))"
    )


def _endpoint_address_family(endpoint_a: str, endpoint_b: str) -> int | None:
    try:
        address_a = ipaddress.ip_address(endpoint_a)
        address_b = ipaddress.ip_address(endpoint_b)
    except ValueError:
        return None
    if address_a.version == address_b.version:
        return address_a.version
    return None


def _field_command(
    tshark: str,
    capture_path: Path,
    display_filter: str,
    fields: list[str],
) -> list[str]:
    command = [
        tshark,
        "-r",
        str(capture_path),
        "-Y",
        display_filter,
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]
    for field in fields:
        command.extend(["-e", field])
    return command


def _parse_tshark_rows(output: str) -> list[dict[str, str]]:
    return _parse_field_rows(output, TCP_HEADER_FIELDS)


def _parse_field_rows(output: str, fields: list[str]) -> list[dict[str, str]]:
    rows = []
    for line in output.splitlines():
        values = line.split("\t")
        row = {
            field: values[index] if index < len(values) else ""
            for index, field in enumerate(fields)
        }
        row["src"] = row["ip.src"] or row["ipv6.src"]
        row["dst"] = row["ip.dst"] or row["ipv6.dst"]
        rows.append({key: value for key, value in row.items() if value != ""})
    return rows


def _tcp_analysis_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        for field in TCP_ANALYSIS_FIELDS:
            value = row.get(field)
            if value is not None and value not in {"", "0", "False", "false"}:
                counts[field] = counts.get(field, 0) + 1
    return counts


def _udp_metadata_counts(rows: list[dict[str, str]]) -> dict[str, int]:
    counters = {
        "dns_packets": 0,
        "dns_responses": 0,
        "dns_error_responses": 0,
        "dhcp_packets": 0,
        "udp_bad_checksum": 0,
    }
    for row in rows:
        if row.get("dns.id"):
            counters["dns_packets"] += 1
        if row.get("dns.flags.response") in {"1", "True", "true"}:
            counters["dns_responses"] += 1
        rcode = row.get("dns.flags.rcode")
        if rcode and not rcode.startswith("0"):
            counters["dns_error_responses"] += 1
        if row.get("bootp.id") or row.get("bootp.option.dhcp"):
            counters["dhcp_packets"] += 1
        checksum_status = row.get("udp.checksum.status", "").lower()
        if checksum_status and checksum_status not in {"1", "good", "unverified"}:
            counters["udp_bad_checksum"] += 1
    return {key: value for key, value in counters.items() if value}


def _tshark_path() -> str | None:
    path = shutil.which("tshark")
    if path:
        return path
    macos_app_path = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    if macos_app_path.exists():
        return str(macos_app_path)
    return None
