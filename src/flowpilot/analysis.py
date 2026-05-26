from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .models import (
    CaptureSummary,
    FlowKey,
    FlowSummary,
    PacketObservation,
    SipCallSummary,
    counter_to_sorted_dict,
)


def summarize_capture(observations: Iterable[PacketObservation]) -> CaptureSummary:
    flows: dict[FlowKey, FlowSummary] = {}
    protocols: Counter[str] = Counter()
    ports: Counter[str] = Counter()
    issue_counts: Counter[str] = Counter()
    names: Counter[str] = Counter()
    packet_count = 0
    total_bytes = 0

    for packet in observations:
        packet_count += 1
        total_bytes += packet.length
        protocols[packet.protocol] += 1

        for port in (packet.src_port, packet.dst_port):
            if port is not None:
                ports[str(port)] += 1

        for name in (packet.dns_query, packet.http_host, packet.tls_sni):
            if name:
                names[name] += 1

        for issue_tag in packet.issue_tags:
            issue_counts[issue_tag] += 1

        key = FlowKey.from_packet(packet)
        flow = flows.setdefault(key, FlowSummary(key=key))
        previous_last_seen = flow.last_seen
        flow.packet_count += 1
        flow.byte_count += packet.length
        flow.first_seen = min(
            filter(None, [flow.first_seen, packet.timestamp]),
            default=packet.timestamp,
        )
        flow.last_seen = max(
            filter(None, [flow.last_seen, packet.timestamp]),
            default=packet.timestamp,
        )

        if packet.timestamp and previous_last_seen and packet.timestamp >= previous_last_seen:
            gap_ms = (packet.timestamp - previous_last_seen).total_seconds() * 1000
            flow.max_interarrival_ms = max(
                filter(None, [flow.max_interarrival_ms, gap_ms]),
                default=gap_ms,
            )

        if packet.rtt_seconds is not None:
            rtt_ms = packet.rtt_seconds * 1000
            flow.rtt_sample_count += 1
            flow.rtt_total_ms += rtt_ms
            flow.rtt_max_ms = max(filter(None, [flow.rtt_max_ms, rtt_ms]), default=rtt_ms)

        if packet.src_ip == key.endpoint_a and packet.src_port == key.port_a:
            flow.src_to_dst_packets += 1
        else:
            flow.dst_to_src_packets += 1

        for issue_tag in packet.issue_tags:
            flow.issue_counts[issue_tag] = flow.issue_counts.get(issue_tag, 0) + 1

        if packet.esp_spi and packet.esp_spi not in flow.esp_spis:
            flow.esp_spis = [*flow.esp_spis, packet.esp_spi][:25]

        if packet.http_location and packet.http_location not in flow.redirect_locations:
            flow.redirect_locations = [*flow.redirect_locations, packet.http_location][:25]

        if packet.sip_call_id and packet.sip_call_id not in flow.sip_call_ids:
            flow.sip_call_ids = [*flow.sip_call_ids, packet.sip_call_id][:25]
        if packet.sip_call_id:
            call = flow.sip_calls.setdefault(
                packet.sip_call_id,
                SipCallSummary(call_id=packet.sip_call_id),
            )
            if packet.sip_from and call.caller is None:
                call.caller = packet.sip_from
            if packet.sip_to and call.callee is None:
                call.callee = packet.sip_to
            if packet.sip_method:
                call.methods[packet.sip_method] = call.methods.get(packet.sip_method, 0) + 1
            if packet.sip_status_code is not None:
                status = _sip_status(packet)
                call.statuses[status] = call.statuses.get(status, 0) + 1
        if packet.sip_method:
            flow.sip_methods[packet.sip_method] = flow.sip_methods.get(packet.sip_method, 0) + 1
        if packet.sip_status_code is not None:
            status = _sip_status(packet)
            flow.sip_statuses[status] = flow.sip_statuses.get(status, 0) + 1
        for participant in (packet.sip_from, packet.sip_to):
            if participant and participant not in flow.sip_participants:
                flow.sip_participants = [*flow.sip_participants, participant][:25]

        if packet.smb_command:
            flow.smb_commands[packet.smb_command] = flow.smb_commands.get(packet.smb_command, 0) + 1
        if packet.smb_status:
            flow.smb_statuses[packet.smb_status] = flow.smb_statuses.get(packet.smb_status, 0) + 1
        if packet.smb_session_id and packet.smb_session_id not in flow.smb_session_ids:
            flow.smb_session_ids = [*flow.smb_session_ids, packet.smb_session_id][:25]
        if packet.smb_tree_id and packet.smb_tree_id not in flow.smb_tree_ids:
            flow.smb_tree_ids = [*flow.smb_tree_ids, packet.smb_tree_id][:25]
        if packet.smb_filename and packet.smb_filename not in flow.smb_filenames:
            flow.smb_filenames = [*flow.smb_filenames, packet.smb_filename][:25]

        presenter_roles = _certificate_presenter_roles(flow)
        for certificate in packet.tls_certificates:
            if certificate.presenter_role is None:
                presenter = (certificate.presenter_ip, certificate.presenter_port)
                role = presenter_roles.get(presenter) or _next_certificate_role(presenter_roles)
                presenter_roles[presenter] = role
                certificate = certificate.model_copy(update={"presenter_role": role})
            if all(
                certificate.summary_key != existing.summary_key
                for existing in flow.tls_certificates
            ):
                flow.tls_certificates = [*flow.tls_certificates, certificate][:10]

        flow_names = {packet.dns_query, packet.http_host, packet.tls_sni} - {None}
        if flow_names:
            merged = list(dict.fromkeys([*flow.names, *sorted(flow_names)]))
            flow.names = merged[:25]

    return CaptureSummary(
        packet_count=packet_count,
        total_bytes=total_bytes,
        flow_count=len(flows),
        protocols=counter_to_sorted_dict(protocols, 20),
        top_ports=counter_to_sorted_dict(ports, 20),
        issue_counts=counter_to_sorted_dict(issue_counts, 30),
        names=list(counter_to_sorted_dict(names, 50).keys()),
        flows=sorted(flows.values(), key=lambda flow: flow.byte_count, reverse=True),
    )


def _certificate_presenter_roles(flow: FlowSummary) -> dict[tuple[str | None, int | None], str]:
    return {
        (certificate.presenter_ip, certificate.presenter_port): certificate.presenter_role
        for certificate in flow.tls_certificates
        if certificate.presenter_role is not None
    }


def _next_certificate_role(roles: dict[tuple[str | None, int | None], str]) -> str:
    if "server" not in roles.values():
        return "server"
    if "client" not in roles.values():
        return "client"
    return "peer"


def _sip_status(packet: PacketObservation) -> str:
    status = str(packet.sip_status_code)
    if packet.sip_reason:
        status = f"{status} {packet.sip_reason}"
    return status
