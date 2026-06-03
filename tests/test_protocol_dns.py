from flowpilot.models import CaptureSummary, FlowKey, FlowSummary
from flowpilot.protocols.dns import dns_details_table


def test_dns_details_table_returns_none_without_dns_metadata() -> None:
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

    assert dns_details_table(summary, show_flows=10) is None


def test_dns_details_table_renders_dns_issue_and_values() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.53", protocol="UDP"),
        dns_queries={"missing.example": 1},
        dns_query_types={"A": 1},
        dns_response_codes={"3 NXDOMAIN": 1},
        dns_answers=[],
    )
    summary = CaptureSummary(
        packet_count=1,
        total_bytes=80,
        flow_count=1,
        protocols={"UDP": 1},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[flow],
    )

    table = dns_details_table(summary, show_flows=10)

    assert table is not None
    row = table.rows[0]
    cells = [column._cells[0] for column in table.columns]
    assert row
    assert cells == [
        "1",
        "missing.example: 1",
        "A: 1",
        "3 NXDOMAIN: 1",
        "",
        "NXDOMAIN: queried name does not exist",
    ]
