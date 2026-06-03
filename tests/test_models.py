from flowpilot.models import FlowKey, FlowSummary


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
