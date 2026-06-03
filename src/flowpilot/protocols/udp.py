from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..models import FlowSummary
from .deep_common import field_command, parse_field_rows, tshark_path, udp_flow_filter

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


def deep_udp_reason(flow: FlowSummary) -> str | None:
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

    tshark = tshark_path()
    if not tshark:
        return {
            "tool": "deep_udp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = udp_flow_filter(flow)
    command = field_command(tshark, capture_path, display_filter, UDP_HEADER_FIELDS)
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

    rows = parse_field_rows(result.stdout, UDP_HEADER_FIELDS)
    return {
        "tool": "deep_udp_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "udp_metadata_counts": udp_metadata_counts(rows),
        "udp_header_fields": UDP_HEADER_FIELDS,
        "udp_header_samples": rows[:sample_limit],
        "sample_limit": sample_limit,
        "truncated": len(rows) > sample_limit,
    }


def udp_metadata_counts(rows: list[dict[str, str]]) -> dict[str, int]:
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
