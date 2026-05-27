from __future__ import annotations

from .models import FlowSummary, PacketObservation


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
