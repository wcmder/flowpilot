from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .models import (
    CaptureSummary,
    EspSequenceSummary,
    FlowKey,
    FlowSummary,
    PacketObservation,
    SipCallSummary,
    counter_to_sorted_dict,
)
from .smb import smb_command_label


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

        if packet.src_ip == key.endpoint_a and (
            key.port_a is None or packet.src_port == key.port_a
        ):
            flow.src_to_dst_packets += 1
        else:
            flow.dst_to_src_packets += 1

        for issue_tag in packet.issue_tags:
            flow.issue_counts[issue_tag] = flow.issue_counts.get(issue_tag, 0) + 1

        if packet.esp_spi and packet.esp_spi not in flow.esp_spis:
            flow.esp_spis = [*flow.esp_spis, packet.esp_spi][:25]
        if packet.esp_spi and packet.esp_sequence is not None:
            _record_esp_sequence(flow, packet)

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
                issue = _sip_status_issue(packet.sip_status_code)
                if issue and issue not in call.issues:
                    call.issues = [*call.issues, issue]
            event = _sip_trace_event(packet)
            if event and event not in call.trace:
                call.trace = [*call.trace, event][:50]
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
        smb_command_label_value = (
            smb_command_label(packet.smb_command).lower() if packet.smb_command else ""
        )
        if "read" in smb_command_label_value:
            flow.smb_read_ops += 1
            flow.smb_read_bytes += packet.smb_read_length or 0
        if "write" in smb_command_label_value:
            flow.smb_write_ops += 1
            flow.smb_write_bytes += packet.smb_write_length or 0
        if packet.smb_status and packet.smb_status.upper() not in {
            "0",
            "0x00000000",
            "STATUS_SUCCESS",
            "SUCCESS",
        }:
            flow.smb_error_count += 1

        if packet.dns_query:
            flow.dns_queries[packet.dns_query] = flow.dns_queries.get(packet.dns_query, 0) + 1
        if packet.dns_query_type:
            flow.dns_query_types[packet.dns_query_type] = (
                flow.dns_query_types.get(packet.dns_query_type, 0) + 1
            )
        if packet.dns_response_code:
            flow.dns_response_codes[packet.dns_response_code] = (
                flow.dns_response_codes.get(packet.dns_response_code, 0) + 1
            )
            if not _is_dns_success(packet.dns_response_code):
                flow.dns_error_count += 1
        for answer in packet.dns_answers:
            if answer and answer not in flow.dns_answers:
                flow.dns_answers = [*flow.dns_answers, answer][:50]

        if packet.dhcp_message_type:
            flow.dhcp_message_types[packet.dhcp_message_type] = (
                flow.dhcp_message_types.get(packet.dhcp_message_type, 0) + 1
            )
        _append_unique(flow, "dhcp_transaction_ids", packet.dhcp_transaction_id)
        _append_unique(flow, "dhcp_client_macs", packet.dhcp_client_mac)
        _append_unique(flow, "dhcp_hostnames", packet.dhcp_hostname)
        _append_unique(flow, "dhcp_requested_ips", packet.dhcp_requested_ip)
        _append_unique(flow, "dhcp_offered_ips", packet.dhcp_your_ip)
        _append_unique(flow, "dhcp_server_ids", packet.dhcp_server_id)
        _append_unique(flow, "dhcp_lease_times", packet.dhcp_lease_time)

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


def _append_unique(flow: FlowSummary, field_name: str, value: str | None, limit: int = 25) -> None:
    if not value:
        return
    values = getattr(flow, field_name)
    if value not in values:
        setattr(flow, field_name, [*values, value][:limit])


def _is_dns_success(response_code: str) -> bool:
    normalized = response_code.lower()
    return normalized in {"0", "noerror", "no error"} or normalized.startswith("0 ")


def _record_esp_sequence(flow: FlowSummary, packet: PacketObservation) -> None:
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


def _sip_status_issue(status_code: int) -> str | None:
    if 400 <= status_code <= 699:
        if 400 <= status_code <= 499:
            return "client failure response"
        if 500 <= status_code <= 599:
            return "server failure response"
        return "global failure response"
    return None


def _sip_trace_event(packet: PacketObservation) -> dict[str, str | None]:
    if packet.sip_method:
        message = packet.sip_method
    elif packet.sip_status_code is not None:
        message = _sip_status(packet)
    else:
        return {}

    return {
        "time": packet.timestamp.isoformat() if packet.timestamp else None,
        "from_endpoint": _endpoint(packet.src_ip, packet.src_port),
        "to_endpoint": _endpoint(packet.dst_ip, packet.dst_port),
        "message": message,
    }


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip
