from flowpilot.models import CaptureSummary, FlowKey, FlowSummary
from flowpilot.protocols.dhcp import dhcp_details_table


def test_dhcp_details_table_returns_none_without_dhcp_metadata() -> None:
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

    assert dhcp_details_table(summary, show_flows=10) is None


def test_dhcp_details_table_renders_incomplete_exchange_issue() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="0.0.0.0", endpoint_b="255.255.255.255", protocol="UDP"),
        dhcp_message_types={"Discover": 1, "Offer": 1},
        dhcp_client_macs=["aa:bb:cc:dd:ee:ff"],
        dhcp_hostnames=["host-a"],
        dhcp_requested_ips=["10.0.0.10"],
        dhcp_offered_ips=["10.0.0.20"],
        dhcp_server_ids=["10.0.0.1"],
        dhcp_lease_times=["3600"],
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

    table = dhcp_details_table(summary, show_flows=10)

    assert table is not None
    cells = [column._cells[0] for column in table.columns]
    assert cells == [
        "1",
        "Discover: 1\nOffer: 1",
        "aa:bb:cc:dd:ee:ff\nhost-a",
        "requested 10.0.0.10\noffered 10.0.0.20",
        "10.0.0.1",
        "3600",
        "dhcp exchange lacks ack in observed packets",
    ]
