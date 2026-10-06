from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

from ..models import FlowSummary, LinkSecuritySummary, PacketObservation
from .deep_common import (
    DEFAULT_EVIDENCE_BATCH_SIZE,
    evidence_batch,
    field_command,
    parse_field_rows,
    tshark_path,
)

MACSEC_FIELDS = [
    "macsec.TCI", "macsec.TCI.V", "macsec.TCI.ES", "macsec.TCI.SC", "macsec.TCI.SCB",
    "macsec.TCI.E", "macsec.TCI.C", "macsec.AN", "macsec.SL", "macsec.PN",
    "macsec.SCI.system_identifier", "macsec.SCI.port_identifier", "macsec.etype",
]
EAPOL_FIELDS = [
    "eapol.version", "eapol.type", "eapol.len", "eapol.keydes.type",
    "eapol.keydes.key_len", "eapol.keydes.replay_counter",
    "wlan_rsna_eapol.keydes.msgnr", "wlan_rsna_eapol.keydes.key_info",
    "eap.code", "eap.id", "eap.len", "eap.type",
    "mka.version_id", "mka.ks_prio", "mka.key_server", "mka.macsec_desired",
    "mka.macsec_capability", "mka.sci", "mka.actor_mi", "mka.actor_mn",
    "mka.algo_agility", "mka.latest_key_an", "mka.latest_key_tx", "mka.latest_key_rx",
    "mka.old_key_an", "mka.old_key_tx", "mka.old_key_rx", "mka.distributed_an",
    "mka.confidentiality_offset", "mka.macsec_cipher_suite",
]
LINK_FIELDS = ["frame.number", "frame.time_relative", "frame.len", "eth.src", "eth.dst",
               "wlan.sa", "wlan.da", "vlan.id"]
NUMBER_FIELDS = {"macsec.PN", "eapol.keydes.replay_counter", "mka.actor_mn"}
ASSESSMENT = (
    "MAC-address endpoints, not IP addresses. Counts/ranges describe observed headers, "
    "not authenticated peers, replay validation, verified integrity or proven packet loss. "
    "MACsec SCI may be omitted; do not invent it. Packet numbers may reset on rekey and "
    "XPN high bits are not reconstructed. EAP code 3/4 is an observed Success/Failure, "
    "not proof of MACsec establishment. Multicast EAPOL/MKA and unicast traffic remain "
    "separate flows. Encrypted contents and key material are not extracted."
)


def _extract(packet, fields):
    result = {}
    for name in fields:
        layer_name, attr = name.split(".", 1)
        layer = getattr(packet, layer_name, None)
        container = getattr(layer, attr.replace(".", "_").lower(), None)
        if container is not None:
            result[name] = [str(getattr(field, "show", None) or field)
                            for field in getattr(container, "all_fields", [container])]
    return result


def extract_macsec(packet, helpers):
    return {"macsec_fields": _extract(packet, MACSEC_FIELDS)}


def extract_eapol(packet, helpers):
    return {"eapol_fields": _extract(packet, EAPOL_FIELDS)} if hasattr(packet, "eapol") else {}


def _record(summary: LinkSecuritySummary, fields):
    if not fields:
        return
    summary.packet_count += 1
    for field, values in fields.items():
        if field in NUMBER_FIELDS:
            for value in values:
                try:
                    number = (int(value.replace(":", ""), 16) if field == "mka.actor_mn"
                              else int(value, 16 if value.startswith("0x") else 10))
                except ValueError:
                    continue
                limits = summary.number_ranges.setdefault(field, [number, number])
                limits[0], limits[1] = min(limits[0], number), max(limits[1], number)
        else:
            counts = summary.fields.setdefault(field, {})
            for value in values:
                counts[value] = counts.get(value, 0) + 1


def record_macsec(flow: FlowSummary, packet: PacketObservation):
    _record(flow.macsec, packet.macsec_fields)


def record_eapol(flow: FlowSummary, packet: PacketObservation):
    _record(flow.eapol, packet.eapol_fields)


def deep_macsec_reason(flow):
    return "Inspect visible MACsec SecTAG/SCI/PN headers." if flow.macsec.packet_count else None


def deep_eapol_reason(flow):
    return "Inspect EAPOL, EAP status and MKA headers." if flow.eapol.packet_count else None


def link_flow_filter(flow, protocol):
    a, b = flow.key.endpoint_a, flow.key.endpoint_b
    if not all(re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", x) for x in (a, b)):
        raise ValueError("Link-security tools require MAC-address endpoints")
    source, destination = ("wlan.sa", "wlan.da") if flow.key.link_type == "wlan" else (
        "eth.src", "eth.dst")
    return (f"(({source} == {a} && {destination} == {b}) || "
            f"({source} == {b} && {destination} == {a})) && {protocol.lower()}")


def _deep_link_flow(capture_path: Path, *, protocol: str, flow_id: int, flow: FlowSummary,
                    reason: str, sample_limit: int | None = DEFAULT_EVIDENCE_BATCH_SIZE,
                    sample_offset: int = 0, timeout: int = 120) -> dict[str, Any]:
    tool = f"deep_{protocol.lower()}_flow"
    base = {"tool": tool, "flow_id": flow_id, "reason": reason}
    if flow.key.protocol != protocol or flow.key.address_type != "mac":
        return {**base, "status": "skipped", "message": "Not a matching MAC-address flow."}
    tshark = tshark_path()
    if not tshark:
        return {**base, "status": "unavailable", "message": "TShark not found."}
    headers = MACSEC_FIELDS if protocol == "MACSEC" else EAPOL_FIELDS
    fields = LINK_FIELDS + headers
    try:
        display_filter = link_flow_filter(flow, protocol)
        result = subprocess.run(field_command(tshark, capture_path, display_filter, fields,
                                             occurrence="a", aggregator=","),
                                capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode:
            return {**base, "status": "error", "message": result.stderr.strip()}
        rows = parse_field_rows(result.stdout, fields)
        # Preserve the entire VLAN stack: identical MACs on different VLANs are distinct flows.
        rows = [row for row in rows if tuple(int(v) for v in row.get("vlan.id", "").split(",")
                                            if v) == flow.key.vlan_ids]
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        return {**base, "status": "error", "message": str(exc)}
    counts = LinkSecuritySummary()
    for row in rows:
        _record(counts, {f: row[f].split(",") for f in headers if f in row})
    return {
        **base, "status": "ok", "display_filter": display_filter,
        "vlan_ids": list(flow.key.vlan_ids), "packet_count": len(rows),
        "link_security_counts": {"packets": len(rows)},
        "header_summary": counts.model_dump(), "assessment": ASSESSMENT,
        "link_header_fields": fields,
        "link_header_samples": rows[
            sample_offset:sample_offset + sample_limit if sample_limit is not None else None
        ],
        "sample_limit": sample_limit,
        "truncated": sample_offset > 0 or (sample_limit is not None and len(rows) > sample_limit),
        "batch": evidence_batch(len(rows), sample_offset, sample_limit),
    }


def deep_macsec_flow(capture_path, **kwargs):
    return _deep_link_flow(capture_path, protocol="MACSEC", **kwargs)


def deep_eapol_flow(capture_path, **kwargs):
    return _deep_link_flow(capture_path, protocol="EAPOL", **kwargs)


def _render(summary, *, protocol, show_flows, console):
    from rich.table import Table

    table = Table(title=f"{protocol.upper()} Headers", caption=ASSESSMENT)
    for name in ("Flow ID", "MAC endpoints", "VLANs", "Packets", "Visible fields", "Number ranges"):
        table.add_column(name, overflow="fold")
    for flow_id, flow in enumerate(summary.flows[:show_flows], 1):
        metadata = getattr(flow, protocol)
        if metadata.packet_count:
            table.add_row(str(flow_id), f"{flow.key.endpoint_a} ↔ {flow.key.endpoint_b}",
                          str(flow.key.vlan_ids), str(metadata.packet_count),
                          str(metadata.fields), str(metadata.number_ranges))
    if table.row_count:
        console.print(table)


def render_macsec_details(summary, **kwargs):
    _render(summary, protocol="macsec", **kwargs)


def render_eapol_details(summary, **kwargs):
    _render(summary, protocol="eapol", **kwargs)
