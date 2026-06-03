from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from .models import (
    CaptureSummary,
    FlowKey,
    FlowSummary,
    PacketObservation,
    counter_to_sorted_dict,
)
from .protocols.registry import record_hooks

PROTOCOL_RECORD_HOOKS = record_hooks()


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
            flow.rtt_samples_ms = [*flow.rtt_samples_ms, rtt_ms]
            flow.rtt_max_ms = max(filter(None, [flow.rtt_max_ms, rtt_ms]), default=rtt_ms)
        if packet.initial_rtt_seconds is not None:
            flow.initial_rtt_ms = packet.initial_rtt_seconds * 1000

        if packet.src_ip == key.endpoint_a and (
            key.port_a is None or packet.src_port == key.port_a
        ):
            flow.src_to_dst_packets += 1
            flow.src_to_dst_bytes += packet.length
        else:
            flow.dst_to_src_packets += 1
            flow.dst_to_src_bytes += packet.length

        for issue_tag in packet.issue_tags:
            flow.issue_counts[issue_tag] = flow.issue_counts.get(issue_tag, 0) + 1

        if packet.http_location and packet.http_location not in flow.redirect_locations:
            flow.redirect_locations = [*flow.redirect_locations, packet.http_location][:25]

        for record_protocol in PROTOCOL_RECORD_HOOKS:
            record_protocol(flow, packet)

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
