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


def dns_issue_summary(response_codes: dict[str, int]) -> str:
    issues = []
    for response_code in response_codes:
        if is_dns_success(response_code):
            continue
        explanation = dns_response_explanation(response_code)
        if explanation not in issues:
            issues.append(explanation)
    return "\n".join(issues)


def dns_response_explanation(response_code: str) -> str:
    normalized = response_code.lower()
    if "nxdomain" in normalized or normalized.startswith("3"):
        return "NXDOMAIN: queried name does not exist"
    if "servfail" in normalized or normalized.startswith("2"):
        return "SERVFAIL: DNS server failed to answer"
    if "refused" in normalized or normalized.startswith("5"):
        return "REFUSED: DNS server refused the query"
    if "notimp" in normalized or normalized.startswith("4"):
        return "NOTIMP: DNS server does not support the requested operation"
    if "formerr" in normalized or normalized.startswith("1"):
        return "FORMERR: DNS server could not understand the query"
    return f"DNS error response: {response_code}"
