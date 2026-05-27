from __future__ import annotations

from .models import FlowSummary, PacketObservation, SipCallSummary


def record_sip(flow: FlowSummary, packet: PacketObservation) -> None:
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
            status = sip_status(packet)
            call.statuses[status] = call.statuses.get(status, 0) + 1
            issue = sip_status_issue(packet.sip_status_code)
            if issue and issue not in call.issues:
                call.issues = [*call.issues, issue]
        event = sip_trace_event(packet)
        if event and event not in call.trace:
            call.trace = [*call.trace, event][:50]
    if packet.sip_method:
        flow.sip_methods[packet.sip_method] = flow.sip_methods.get(packet.sip_method, 0) + 1
    if packet.sip_status_code is not None:
        status = sip_status(packet)
        flow.sip_statuses[status] = flow.sip_statuses.get(status, 0) + 1
    for participant in (packet.sip_from, packet.sip_to):
        if participant and participant not in flow.sip_participants:
            flow.sip_participants = [*flow.sip_participants, participant][:25]


def sip_status(packet: PacketObservation) -> str:
    status = str(packet.sip_status_code)
    if packet.sip_reason:
        status = f"{status} {packet.sip_reason}"
    return status


def sip_status_issue(status_code: int) -> str | None:
    if 400 <= status_code <= 699:
        if 400 <= status_code <= 499:
            return "client failure response"
        if 500 <= status_code <= 599:
            return "server failure response"
        return "global failure response"
    return None


def sip_trace_event(packet: PacketObservation) -> dict[str, str | None]:
    if packet.sip_method:
        message = packet.sip_method
    elif packet.sip_status_code is not None:
        message = sip_status(packet)
    else:
        return {}

    return {
        "time": packet.timestamp.isoformat() if packet.timestamp else None,
        "from_endpoint": _endpoint(packet.src_ip, packet.src_port),
        "to_endpoint": _endpoint(packet.dst_ip, packet.dst_port),
        "message": message,
    }


def format_sip_trace(trace: list[dict[str, str | None]]) -> str:
    return "\n".join(
        f"{event.get('from_endpoint')} -> {event.get('to_endpoint')} {event.get('message')}"
        for event in trace[:8]
    )


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip
