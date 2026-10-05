from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..decode_as import srtp_udp_ports
from ..models import FlowSummary, PacketObservation, RtpStreamSummary
from .deep_common import (
    DEFAULT_EVIDENCE_BATCH_SIZE,
    evidence_batch,
    field_command,
    parse_field_rows,
    tshark_path,
    udp_flow_filter,
)

RTP_HEADER_FIELDS = [
    "frame.number", "frame.time_relative", "frame.len", "ip.src", "ipv6.src",
    "ip.dst", "ipv6.dst", "udp.srcport", "udp.dstport", "udp.length",
    "rtp.version", "rtp.ssrc", "rtp.seq", "rtp.timestamp", "rtp.p_type", "rtp.marker",
    "_ws.col.Protocol",
]


def extract_rtp(packet, helpers) -> dict:
    def get(field):
        value = getattr(getattr(packet, "rtp", None), field, None)
        return str(value) if value is not None else helpers.layer_attr(packet, "rtp", field)

    if helpers.protocol != "UDP" or get("version") != "2":
        return {}
    ports = [helpers.safe_int(helpers.layer_attr(packet, "udp", field))
             for field in ("srcport", "dstport")]
    encrypted = any(port in srtp_udp_ports() for port in ports) or any(
        get(field) is not None for field in ("srtp_enc_payload", "srtp_auth_tag")
    )
    return {
        "rtp_ssrc": get("ssrc"), "rtp_sequence": helpers.safe_int(get("seq")),
        "rtp_timestamp": helpers.safe_int(get("timestamp")),
        "rtp_payload_type": helpers.safe_int(get("p_type")),
        "rtp_marker": (int(get("marker").lower() in {"true", "1"})
                       if get("marker") is not None else None), "srtp": encrypted,
    }


def record_rtp(flow: FlowSummary, packet: PacketObservation) -> None:
    if packet.rtp_ssrc is None or packet.rtp_sequence is None:
        return
    direction = ("A_to_B" if (packet.src_ip, packet.src_port) ==
                 (flow.key.endpoint_a, flow.key.port_a) else "B_to_A")
    stream = next((s for s in flow.rtp_streams
                   if s.ssrc == packet.rtp_ssrc and s.direction == direction), None)
    if stream is None:
        stream = RtpStreamSummary(ssrc=packet.rtp_ssrc, direction=direction)
        flow.rtp_streams.append(stream)
    stream.packet_count += 1
    stream.srtp_packets += int(packet.srtp)
    if packet.rtp_payload_type is not None:
        key = str(packet.rtp_payload_type)
        stream.payload_types[key] = stream.payload_types.get(key, 0) + 1
    seq = packet.rtp_sequence
    if stream.highest_sequence is not None:
        seq = stream.highest_sequence + ((seq - stream.highest_sequence + 32768) % 65536 - 32768)
    if seq in stream.seen_sequences:
        stream.duplicate_count += 1
    elif stream.highest_sequence is not None and seq < stream.highest_sequence:
        stream.out_of_order_count += 1
    stream.seen_sequences.add(seq)
    stream.highest_sequence = max(seq, stream.highest_sequence if
                                  stream.highest_sequence is not None else seq)
    stream.lowest_sequence = min(seq, stream.lowest_sequence if
                                 stream.lowest_sequence is not None else seq)


def deep_rtp_reason(flow: FlowSummary) -> str | None:
    if flow.rtp_streams:
        return "RTP/SRTP headers observed; inspect SSRC, sequence, timestamps and payload types."
    return None


def render_rtp_details(summary, *, show_flows: int, console) -> None:
    from rich.table import Table

    table = Table(title="RTP/SRTP Streams")
    for name in ("Flow ID", "Direction", "SSRC", "Packets", "SRTP", "Holes", "Duplicates", "OOO"):
        table.add_column(name)
    for flow_id, flow in enumerate(summary.flows[:show_flows], 1):
        for stream in flow.rtp_streams:
            table.add_row(str(flow_id), stream.direction, stream.ssrc, str(stream.packet_count),
                          str(stream.srtp_packets),
                          str(stream.compact()["observed_sequence_holes"]),
                          str(stream.duplicate_count), str(stream.out_of_order_count))
    if table.row_count:
        console.print(table)


def deep_rtp_flow(
    capture_path: Path,
    *,
    flow_id: int,
    flow: FlowSummary,
    reason: str,
    sample_limit: int | None = DEFAULT_EVIDENCE_BATCH_SIZE,
    sample_offset: int = 0,
    timeout: int = 120,
) -> dict[str, Any]:
    if flow.key.protocol != "UDP":
        return {
            "tool": "deep_rtp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "skipped",
            "message": f"Flow protocol is {flow.key.protocol}, not UDP.",
        }

    tshark = tshark_path()
    if not tshark:
        return {
            "tool": "deep_rtp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = f"({udp_flow_filter(flow)}) && rtp"
    command = field_command(tshark, capture_path, display_filter, RTP_HEADER_FIELDS)
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
            "tool": "deep_rtp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": str(exc),
        }

    if result.returncode != 0:
        return {
            "tool": "deep_rtp_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": result.stderr.strip() or f"tshark exited with {result.returncode}",
        }

    rows = parse_field_rows(result.stdout, RTP_HEADER_FIELDS)
    headers = FlowSummary(key=flow.key)
    for row in rows:
        def integer(field, row=row):
            value = row.get(field)
            return int(value, 16 if value and value.startswith("0x") else 10) if value else None

        secure = (row.get("_ws.col.Protocol", "").upper() == "SRTP" or
                  any(integer(field) in srtp_udp_ports()
                      for field in ("udp.srcport", "udp.dstport")))
        row["media_security"] = "SRTP (dissector or explicit port)" if secure else "unknown"
        record_rtp(headers, PacketObservation(
            src_ip=row["src"], dst_ip=row["dst"],
            src_port=integer("udp.srcport"), dst_port=integer("udp.dstport"), protocol="UDP",
            rtp_ssrc=row.get("rtp.ssrc"), rtp_sequence=integer("rtp.seq"),
            rtp_timestamp=integer("rtp.timestamp"), rtp_payload_type=integer("rtp.p_type"),
            srtp=secure,
        ))
    return {
        "tool": "deep_rtp_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "rtp_metadata_counts": {"rtp_packets": len(rows),
                                "srtp_packets": sum(s.srtp_packets for s in headers.rtp_streams)},
        "rtp_streams": [s.compact() for s in headers.rtp_streams],
        "rtp_header_fields": RTP_HEADER_FIELDS,
        "rtp_header_samples": rows[
            sample_offset:sample_offset + sample_limit if sample_limit is not None else None
        ],
        "sample_limit": sample_limit,
        "truncated": sample_offset > 0 or (sample_limit is not None and len(rows) > sample_limit),
        "batch": evidence_batch(len(rows), sample_offset, sample_limit),
    }
