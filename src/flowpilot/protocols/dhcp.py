from __future__ import annotations

from rich.console import Console
from rich.table import Table

from ..models import CaptureSummary, FlowSummary, PacketObservation


def extract_dhcp(packet, helpers) -> dict:
    return {
        "dhcp_message_type": _dhcp_value(packet, helpers, "option_dhcp"),
        "dhcp_transaction_id": _dhcp_value(packet, helpers, "id"),
        "dhcp_client_mac": _dhcp_value(packet, helpers, "hw_mac_addr"),
        "dhcp_hostname": _dhcp_value(packet, helpers, "option_hostname"),
        "dhcp_requested_ip": _dhcp_value(packet, helpers, "option_requested_ip_address"),
        "dhcp_your_ip": _dhcp_value(packet, helpers, "ip_your"),
        "dhcp_server_id": _dhcp_value(packet, helpers, "option_dhcp_server_id"),
        "dhcp_lease_time": _dhcp_value(packet, helpers, "option_ip_address_lease_time"),
    }


def record_dhcp(flow: FlowSummary, packet: PacketObservation) -> None:
    if packet.dhcp_message_type:
        flow.dhcp_message_types[packet.dhcp_message_type] = (
            flow.dhcp_message_types.get(packet.dhcp_message_type, 0) + 1
        )
    append_unique(flow, "dhcp_transaction_ids", packet.dhcp_transaction_id)
    append_unique(flow, "dhcp_client_macs", packet.dhcp_client_mac)
    append_unique(flow, "dhcp_hostnames", packet.dhcp_hostname)
    append_unique(flow, "dhcp_requested_ips", packet.dhcp_requested_ip)
    append_unique(flow, "dhcp_offered_ips", packet.dhcp_your_ip)
    append_unique(flow, "dhcp_server_ids", packet.dhcp_server_id)
    append_unique(flow, "dhcp_lease_times", packet.dhcp_lease_time)


def append_unique(flow: FlowSummary, field_name: str, value: str | None, limit: int = 25) -> None:
    if not value:
        return
    values = getattr(flow, field_name)
    if value not in values:
        setattr(flow, field_name, [*values, value][:limit])


def has_dhcp_ack(message_types: dict[str, int]) -> bool:
    return any("ACK" in key.upper() for key in message_types)


def _dhcp_value(packet, helpers, attr_name: str) -> str | None:
    for layer_name in ("dhcp", "bootp"):
        value = helpers.layer_attr(packet, layer_name, attr_name)
        if value:
            return value
    return None


def render_dhcp_details(
    summary: CaptureSummary,
    *,
    show_flows: int,
    console: Console,
) -> None:
    table = dhcp_details_table(summary, show_flows=show_flows)
    if table:
        console.print(table)


def dhcp_details_table(summary: CaptureSummary, *, show_flows: int) -> Table | None:
    rows = [
        (flow_id, flow)
        for flow_id, flow in enumerate(summary.flows[:show_flows], start=1)
        if flow.dhcp_message_types or flow.dhcp_client_macs or flow.dhcp_requested_ips
    ]
    if not rows:
        return None

    table = Table(title="DHCP Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Messages", overflow="fold")
    table.add_column("Client", overflow="fold")
    table.add_column("Requested/Offered", overflow="fold")
    table.add_column("Server", overflow="fold")
    table.add_column("Lease", overflow="fold")
    table.add_column("Issue", overflow="fold")

    for flow_id, flow in rows:
        table.add_row(
            str(flow_id),
            _format_counter_lines(flow.dhcp_message_types),
            "\n".join([*flow.dhcp_client_macs[:5], *flow.dhcp_hostnames[:5]]),
            "\n".join(
                [
                    *[f"requested {ip}" for ip in flow.dhcp_requested_ips[:5]],
                    *[f"offered {ip}" for ip in flow.dhcp_offered_ips[:5]],
                ]
            ),
            "\n".join(flow.dhcp_server_ids[:10]),
            "\n".join(flow.dhcp_lease_times[:10]),
            "dhcp exchange lacks ack in observed packets"
            if flow.dhcp_message_types and not has_dhcp_ack(flow.dhcp_message_types)
            else "",
        )
    return table


def _format_counter_lines(counts: dict[str, int]) -> str:
    return "\n".join(f"{key}: {value}" for key, value in counts.items()) or "-"
