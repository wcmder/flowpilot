from flowpilot.models import CaptureSummary, FlowKey, FlowSummary, SipCallSummary
from flowpilot.protocols.sip import sip_details_table


def test_sip_details_table_returns_none_without_sip_metadata() -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=1,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[FlowSummary(key=FlowKey(endpoint_a="a", endpoint_b="b", protocol="UDP"))],
    )

    assert sip_details_table(summary, show_flows=10) is None


def test_sip_details_table_renders_call_trace_and_issue() -> None:
    call = SipCallSummary(
        call_id="call-123",
        caller="sip:alice@example.com",
        callee="sip:bob@example.com",
        methods={"INVITE": 1},
        statuses={"486 Busy Here": 1},
        issues=["client failure response"],
        trace=[
            {
                "from_endpoint": "10.0.0.10:5060",
                "to_endpoint": "10.0.0.20:5060",
                "message": "INVITE",
            }
        ],
    )
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.20", protocol="UDP"),
        sip_call_ids=["call-123"],
        sip_methods={"INVITE": 1},
        sip_statuses={"486 Busy Here": 1},
        sip_calls={"call-123": call},
    )
    summary = CaptureSummary(
        packet_count=2,
        total_bytes=600,
        flow_count=1,
        protocols={"UDP": 2},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[flow],
    )

    table = sip_details_table(summary, show_flows=10)

    assert table is not None
    cells = [column._cells[0] for column in table.columns]
    assert cells == [
        "1",
        "call-123",
        "sip:alice@example.com",
        "sip:bob@example.com",
        "INVITE: 1",
        "486 Busy Here: 1",
        "client failure response",
        "10.0.0.10:5060 -> 10.0.0.20:5060 INVITE",
    ]


def test_sip_details_table_renders_flow_fallback_without_call_objects() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.20", protocol="UDP"),
        sip_call_ids=["call-456"],
        sip_methods={"OPTIONS": 1},
        sip_statuses={"200 OK": 1},
    )
    summary = CaptureSummary(
        packet_count=2,
        total_bytes=600,
        flow_count=1,
        protocols={"UDP": 2},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[flow],
    )

    table = sip_details_table(summary, show_flows=10)

    assert table is not None
    cells = [column._cells[0] for column in table.columns]
    assert cells[:6] == ["1", "call-456", "-", "-", "OPTIONS: 1", "200 OK: 1"]
