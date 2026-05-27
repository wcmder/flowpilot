from __future__ import annotations

from .models import FlowSummary, PacketObservation


def record_dns(flow: FlowSummary, packet: PacketObservation) -> None:
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
        if not is_dns_success(packet.dns_response_code):
            flow.dns_error_count += 1
    for answer in packet.dns_answers:
        if answer and answer not in flow.dns_answers:
            flow.dns_answers = [*flow.dns_answers, answer][:50]


def is_dns_success(response_code: str) -> bool:
    normalized = response_code.lower()
    return normalized in {"0", "noerror", "no error"} or normalized.startswith("0 ")
