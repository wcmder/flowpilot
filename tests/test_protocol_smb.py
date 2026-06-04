from flowpilot.models import CaptureSummary, FlowKey, FlowSummary
from flowpilot.protocols.smb import format_smb_transfer, smb_details_table


def test_smb_details_table_returns_none_without_smb_metadata() -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=1,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[FlowSummary(key=FlowKey(endpoint_a="a", endpoint_b="b", protocol="TCP"))],
    )

    assert smb_details_table(summary, show_flows=10) is None


def test_smb_details_table_renders_commands_statuses_and_transfer() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        byte_count=1_000_000,
        first_seen="2026-01-01T00:00:00",
        last_seen="2026-01-01T00:00:01",
        smb_commands={"8": 2, "9": 1},
        smb_statuses={"0xc0000022": 1},
        smb_client_capabilities=["DFS"],
        smb_server_capabilities=["DFS", "encryption"],
        smb_read_ops=2,
        smb_read_bytes=2_097_152,
        smb_read_bytes_by_file={"\\\\share\\download.iso": 2_097_152},
        smb_error_count=1,
    )
    summary = CaptureSummary(
        packet_count=10,
        total_bytes=1_000_000,
        flow_count=1,
        protocols={"TCP": 10},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[flow],
    )

    table = smb_details_table(summary, show_flows=10)

    assert table is not None
    cells = [column._cells[0] for column in table.columns]
    assert cells[0] == "1"
    assert cells[1] == "SMBgetatr(8): 2\nSMBsetatr(9): 1"
    assert cells[2] == "STATUS_ACCESS_DENIED: 1"
    assert cells[3] == "DFS (c,s)\nencryption (s)"
    assert "read 2 ops / 2097152 bytes" in cells[4]
    assert "download \\\\share\\download.iso (2.0 MiB)" in cells[4]
    assert cells[5] == "smb errors observed"


def test_smb_transfer_filenames_survive_json_round_trip() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        smb_read_ops=2,
        smb_read_bytes=2_097_152,
        smb_read_bytes_by_file={"\\\\share\\download.iso": 2_097_152},
    )

    loaded = FlowSummary.model_validate_json(flow.model_dump_json())

    assert loaded.smb_read_bytes_by_file == {"\\\\share\\download.iso": 2_097_152}
    assert "download \\\\share\\download.iso (2.0 MiB)" in format_smb_transfer(loaded)
