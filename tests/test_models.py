from flowpilot.models import EspSequenceSummary, FlowKey, FlowSummary


def test_directional_throughput_distinguishes_zero_traffic_from_no_interval() -> None:
    from datetime import datetime, timedelta

    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="ESP"),
        src_to_dst_bytes=100,
        src_to_dst_packets=2,
    )
    assert flow.throughput_mbps_by_direction == (None, None)
    assert flow.packet_rate_per_second_by_direction == (None, None)
    flow.first_seen = flow.last_seen = datetime(2026, 1, 1)
    assert flow.throughput_mbps_by_direction == (None, None)
    assert flow.packet_rate_per_second_by_direction == (None, None)
    flow.last_seen += timedelta(seconds=10)
    assert flow.throughput_mbps_by_direction == (0.00008, 0.0)
    assert flow.packet_rate_per_second_by_direction == (0.2, 0.0)


def test_flow_summary_moves_legacy_protocol_fields_into_nested_metadata() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="TCP"),
        tls_snis=["api.example.com"],
        smb_commands={"SMB2read": 1},
        dns_response_codes={"3 NXDOMAIN": 1},
        dhcp_message_types={"Discover": 1},
    )

    assert flow.tls.snis == ["api.example.com"]
    assert flow.smb.commands == {"SMB2read": 1}
    assert flow.dns.response_codes == {"3 NXDOMAIN": 1}
    assert flow.dhcp.message_types == {"Discover": 1}

    assert flow.tls_snis == flow.tls.snis
    assert flow.smb_commands == flow.smb.commands
    assert flow.dns_response_codes == flow.dns.response_codes
    assert flow.dhcp_message_types == flow.dhcp.message_types


def test_flow_summary_legacy_protocol_assignment_updates_nested_metadata() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="TCP")
    )

    flow.sip_call_ids = ["call-1"]
    flow.esp_spis = ["0x1234"]
    flow.smb_read_ops = 3

    assert flow.sip.call_ids == ["call-1"]
    assert flow.esp.spis == ["0x1234"]
    assert flow.smb.read_ops == 3


def test_esp_packet_loss_rate_uses_persisted_sequence_summary_without_seen_set() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="ESP"),
        packet_count=4,
        esp_sequences=[
            EspSequenceSummary(
                spi="0x1234",
                direction="10.0.0.1 -> 10.0.0.2",
                packet_count=4,
                first_sequence=1,
                last_sequence=4,
                highest_sequence=4,
                duplicate_count=1,
            )
        ],
    )

    assert flow.esp_sequences[0].observed_unique_sequence_count == 3
    assert flow.esp_sequences[0].missing_count == 1
    assert flow.packet_loss_rate == 0.25
