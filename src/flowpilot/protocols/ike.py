from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from ..models import FlowSummary, IkePacketMetadata, IkeSessionSummary, PacketObservation
from .deep_common import (
    DEFAULT_EVIDENCE_BATCH_SIZE,
    evidence_batch,
    field_command,
    parse_field_rows,
    tshark_path,
    udp_flow_filter,
)

IKE_ASSESSMENT = (
    "Visible IKE headers/notifications only. IKEv1 has no response flag; repeated message ID "
    "zero in Main/Aggressive Mode does not prove retransmission. IKEv2 response flags do not "
    "prove authentication or tunnel success. Encrypted payload contents remain unknown. "
    "Missing responses may reflect capture scope/loss. SPI-pair groups are observations, "
    "not a count of established SAs; initial zero responder SPI and later SPI are separate. "
    "Do not infer network latency from packet spacing or negotiation success from proposals."
)
V1_EXCHANGES = {1: "Base", 2: "Main Mode", 4: "Aggressive Mode", 5: "Informational",
                6: "Transaction", 32: "Quick Mode", 33: "New Group Mode"}
V2_EXCHANGES = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA",
                37: "INFORMATIONAL", 43: "IKE_INTERMEDIATE"}
V1_NOTIFIES = {14: "NO-PROPOSAL-CHOSEN", 24: "AUTHENTICATION-FAILED",
               36136: "R-U-THERE", 36137: "R-U-THERE-ACK"}
V2_NOTIFIES = {14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD",
               24: "AUTHENTICATION_FAILED", 38: "TS_UNACCEPTABLE",
               16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
               16390: "COOKIE", 16430: "IKEV2_FRAGMENTATION_SUPPORTED"}
PROPOSAL_FIELDS = [
    "prop.number", "prop.protoid", "prop.transforms", "trans.number", "trans.id",
    "ike.attr.encryption_algorithm", "ike.attr.hash_algorithm",
    "ike.attr.authentication_method", "ike.attr.group_description", "ike.attr.key_length",
    "key_exchange.dh_group", "tf.type", "tf.id.encr", "tf.id.prf", "tf.id.integ",
    "tf.id.dh", "tf.id.esn",
]
HEADER_NAMES = ["version", "ispi", "rspi", "exchangetype", "messageid", "flags",
                "nextpayload", "length", "notify.msgtype", "frag.number", "frag.total",
                "frag.packetid", "frag.seq", "frag.last"]
IKE_HEADER_FIELDS = [
    "frame.number", "frame.time_relative", "frame.len", "ip.src", "ipv6.src", "ip.dst",
    "ipv6.dst", "udp.srcport", "udp.dstport",
    *[f"isakmp.{name}" for name in HEADER_NAMES + PROPOSAL_FIELDS],
]


def _integer(value):
    try:
        text = str(value)
        return int(text, 16 if text.startswith("0x") else 10)
    except (TypeError, ValueError):
        return None


def metadata_from_fields(values) -> IkePacketMetadata | None:
    def first(name):
        return next((v for v in values(name) if v != ""), None)

    def spi(name):
        value = first(name)
        return value.replace(":", "").lower() if value else None

    version = _integer(first("version"))
    if version is None or version >> 4 not in (1, 2):
        return None
    return IkePacketMetadata(
        version=version, initiator_spi=spi("ispi"), responder_spi=spi("rspi"),
        exchange_type=_integer(first("exchangetype")), message_id=_integer(first("messageid")),
        flags=_integer(first("flags")), next_payload=_integer(first("nextpayload")),
        length=_integer(first("length")),
        notify_types=[n for v in values("notify.msgtype") if (n := _integer(v)) is not None],
        fragment_number=_integer(first("frag.number") or first("frag.seq")),
        fragment_total=_integer(first("frag.total")),
        fragment_id=_integer(first("frag.packetid")),
        fragment_last=_integer(first("frag.last")),
        proposal_fields={name: [v for v in values(name) if v != ""]
                         for name in PROPOSAL_FIELDS if any(values(name))},
    )


def extract_ike(packet, helpers) -> dict:
    layer = getattr(packet, "isakmp", None)
    if helpers.protocol != "UDP" or layer is None:
        return {}

    def values(name):
        # Numeric display values, not PyShark's descriptive showname labels.
        container = getattr(layer, name.replace(".", "_"), None)
        if container is None:
            return []
        fields = getattr(container, "all_fields", [container])
        return [str(getattr(field, "show", None) or field) for field in fields]

    return {"ike": metadata_from_fields(values)}


def record_ike(flow: FlowSummary, packet: PacketObservation) -> None:
    ike = packet.ike
    if ike is None:
        return
    session = next((s for s in flow.ike_sessions if
                    (s.version, s.initiator_spi, s.responder_spi) ==
                    (ike.version, ike.initiator_spi, ike.responder_spi)), None)
    if session is None:
        session = IkeSessionSummary(version=ike.version, initiator_spi=ike.initiator_spi,
                                    responder_spi=ike.responder_spi)
        flow.ike_sessions.append(session)
    direction = int((packet.src_ip, packet.src_port) != (flow.key.endpoint_a, flow.key.port_a))
    session.packets_by_direction[direction] += 1
    major = ike.version >> 4
    exchanges = V1_EXCHANGES if major == 1 else V2_EXCHANGES
    key = f"{ike.exchange_type}: {exchanges.get(ike.exchange_type, 'Unknown')}"
    session.exchanges[key] = session.exchanges.get(key, 0) + 1
    names = V1_NOTIFIES if major == 1 else V2_NOTIFIES
    for code in ike.notify_types:
        key = f"{code}: {names.get(code, 'Unknown')}"
        session.notifications[key] = session.notifications.get(key, 0) + 1
    for field, values in ike.proposal_fields.items():
        counts = session.proposal_values.setdefault(field, {})
        for value in values:
            counts[value] = counts.get(value, 0) + 1
    session.encrypted_packets += int(
        (major == 1 and bool((ike.flags or 0) & 1)) or
        (major == 2 and ike.next_payload in (46, 53))
    )
    session.fragmented_packets += int(ike.fragment_number is not None)
    if major == 2 and ike.flags is not None:
        if ike.flags & 0x20:
            session.v2_responses += 1
        else:
            session.v2_requests += 1


def deep_ike_reason(flow: FlowSummary) -> str | None:
    if flow.ike_sessions:
        return "IKEv1/IKEv2 observed; inspect headers, visible notifications and fragments."
    return None


def render_ike_details(summary, *, show_flows: int, console) -> None:
    from rich.table import Table

    table = Table(title="IKEv1/IKEv2 Exchanges", caption=IKE_ASSESSMENT)
    for name in ("Flow ID", "Version", "Initiator SPI", "Responder SPI", "Pkts A/B",
                 "Exchanges", "Notifications", "Encrypted"):
        table.add_column(name, overflow="fold")
    for flow_id, flow in enumerate(summary.flows[:show_flows], 1):
        for session in flow.ike_sessions:
            table.add_row(str(flow_id), f"{session.version >> 4}.{session.version & 15}",
                          session.initiator_spi or "-", session.responder_spi or "-",
                          "/".join(map(str, session.packets_by_direction)),
                          str(session.exchanges), str(session.notifications),
                          str(session.encrypted_packets))
    if table.row_count:
        console.print(table)


def deep_ike_flow(
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
            "tool": "deep_ike_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "skipped",
            "message": f"Flow protocol is {flow.key.protocol}, not UDP.",
        }

    tshark = tshark_path()
    if not tshark:
        return {
            "tool": "deep_ike_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "unavailable",
            "message": "tshark was not found on PATH or in the Wireshark app bundle.",
        }

    display_filter = f"({udp_flow_filter(flow)}) && isakmp && !esp"
    command = field_command(tshark, capture_path, display_filter, IKE_HEADER_FIELDS,
                            occurrence="a", aggregator=",")
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
            "tool": "deep_ike_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": str(exc),
        }

    if result.returncode != 0:
        return {
            "tool": "deep_ike_flow",
            "flow_id": flow_id,
            "reason": reason,
            "status": "error",
            "display_filter": display_filter,
            "message": result.stderr.strip() or f"tshark exited with {result.returncode}",
        }

    rows = parse_field_rows(result.stdout, IKE_HEADER_FIELDS)
    headers = FlowSummary(key=flow.key)
    for row in rows:
        metadata = metadata_from_fields(
            lambda name, row=row: row.get(f"isakmp.{name}", "").split(",")
        )
        if metadata:
            record_ike(headers, PacketObservation(
                src_ip=row["src"], dst_ip=row["dst"], protocol="UDP",
                src_port=_integer(row.get("udp.srcport")),
                dst_port=_integer(row.get("udp.dstport")), ike=metadata,
            ))
    return {
        "tool": "deep_ike_flow",
        "flow_id": flow_id,
        "reason": reason,
        "status": "ok",
        "display_filter": display_filter,
        "packet_count": len(rows),
        "ike_metadata_counts": {"ike_packets": len(rows)},
        "ike_sessions": [s.model_dump() for s in headers.ike_sessions],
        "assessment": IKE_ASSESSMENT,
        "ike_header_fields": IKE_HEADER_FIELDS,
        "ike_header_samples": rows[
            sample_offset:sample_offset + sample_limit if sample_limit is not None else None
        ],
        "sample_limit": sample_limit,
        "truncated": sample_offset > 0 or (sample_limit is not None and len(rows) > sample_limit),
        "batch": evidence_batch(len(rows), sample_offset, sample_limit),
    }
