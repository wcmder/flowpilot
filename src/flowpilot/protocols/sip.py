from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..models import CaptureSummary, FlowSummary, PacketObservation, SipCallSummary


def extract_sip(packet, helpers) -> dict:
    return {
        "sip_call_id": helpers.layer_attr(packet, "sip", "call_id"),
        "sip_method": helpers.layer_attr(packet, "sip", "method"),
        "sip_status_code": helpers.safe_int(helpers.layer_attr(packet, "sip", "status_code")),
        "sip_reason": helpers.layer_attr(packet, "sip", "reason_phrase"),
        "sip_from": helpers.layer_attr(packet, "sip", "from_addr")
        or helpers.layer_attr(packet, "sip", "from"),
        "sip_to": helpers.layer_attr(packet, "sip", "to_addr")
        or helpers.layer_attr(packet, "sip", "to"),
    }


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


def render_sip_details(
    summary: CaptureSummary,
    *,
    show_flows: int,
    console: Console,
) -> None:
    table = sip_details_table(summary, show_flows=show_flows)
    if table:
        console.print(table)


def sip_details_table(summary: CaptureSummary, *, show_flows: int) -> Table | None:
    rows = [
        (flow_id, flow)
        for flow_id, flow in enumerate(summary.flows[:show_flows], start=1)
        if flow.sip_call_ids or flow.sip_methods or flow.sip_statuses
    ]
    if not rows:
        return None

    table = Table(title="SIP Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Call ID", overflow="fold")
    table.add_column("Caller", overflow="fold")
    table.add_column("Callee", overflow="fold")
    table.add_column("Methods", overflow="fold")
    table.add_column("Statuses", overflow="fold")
    table.add_column("Issue", overflow="fold")
    table.add_column("Trace", overflow="fold")

    for flow_id, flow in rows:
        if flow.sip_calls:
            for call in list(flow.sip_calls.values())[:10]:
                table.add_row(
                    str(flow_id),
                    call.call_id,
                    call.caller or "-",
                    call.callee or "-",
                    _format_counter_lines(call.methods),
                    _format_counter_lines(call.statuses),
                    "\n".join(call.issues),
                    format_sip_trace(call.trace),
                )
        else:
            table.add_row(
                str(flow_id),
                "\n".join(flow.sip_call_ids[:10]),
                "-",
                "-",
                _format_counter_lines(flow.sip_methods),
                _format_counter_lines(flow.sip_statuses),
                "",
                "",
            )
    return table


def _format_counter_lines(counts: dict[str, int]) -> str:
    return "\n".join(f"{key}: {value}" for key, value in counts.items()) or "-"


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip
