import io
import json
import shutil
import struct
from datetime import datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

import flowpilot.cli as cli
from flowpilot.cli import (
    _apply_summary_filters,
    _CachedCaptureSession,
    _count_packets_in_capture,
    _default_summary_path_for_capture,
    _direction,
    _flow_metrics,
    _format_agent_evidence_counts,
    _format_flow_issues,
    _load_summary,
    _load_summary_with_metadata,
    _local_analysis_start_message,
    _normalize_optional_json_arg,
    _packet_read_complete_message,
    _parse_capinfos_packet_count,
    _percent,
    _ProgressReporter,
    _RefreshingInfo,
    _summary_json_output_path,
    _traffic,
)
from flowpilot.filters import FlowFilter
from flowpilot.models import CaptureSummary, FlowKey, FlowSummary, TlsCertificateObservation
from flowpilot.protocols.dns import dns_issue_summary
from flowpilot.protocols.esp import format_esp_gap_distribution
from flowpilot.protocols.smb import (
    SMB1_COMMAND_NAMES,
    SMB2_COMMAND_NAMES,
    SMB_STATUS_NAMES,
    format_smb_capabilities,
    format_smb_counter_lines,
    format_smb_transfer,
    format_smb_transfer_line,
)
from flowpilot.protocols.tls import (
    expiration,
    format_certificate_column,
    format_tls_certificates,
    tls_detail_rows,
    tls_endpoint_with_role,
    tls_issue_text,
    tls_sni_for_endpoint,
)


def test_format_esp_gap_distribution_groups_missing_counts() -> None:
    gaps = [
        {"after_sequence": 1, "next_sequence": 3, "gap": 1, "missing": 1},
        {"after_sequence": 10, "next_sequence": 12, "gap": 1, "missing": 1},
        {"after_sequence": 20, "next_sequence": 23, "gap": 2, "missing": 2},
    ]

    assert format_esp_gap_distribution(gaps) == "gap=1(x2) gap=2(x1)"


def test_format_esp_gap_distribution_handles_no_gaps() -> None:
    assert format_esp_gap_distribution([]) == "none"


def test_dns_issue_summary_explains_common_rcodes() -> None:
    assert dns_issue_summary({"3 NXDOMAIN": 1, "2 SERVFAIL": 1, "0 NoError": 1}) == (
        "NXDOMAIN: queried name does not exist\n"
        "SERVFAIL: DNS server failed to answer"
    )


def test_local_analysis_start_message_includes_packet_count() -> None:
    assert _local_analysis_start_message(Path("capture.pcap"), 100) == (
        "Local analysis started: reading capture.pcap (100 packets)."
    )


def test_local_analysis_start_message_handles_unknown_packet_count() -> None:
    assert _local_analysis_start_message(Path("capture.pcap"), None) == (
        "Local analysis started: reading capture.pcap."
    )


def test_packet_read_complete_message_separates_raw_and_analyzable_counts() -> None:
    assert _packet_read_complete_message(
        pyshark_packets=1_000,
        analyzable_packets=170,
        total_packets=2_000,
    ) == (
        "Packet reading complete: 2000 packets reported by capinfos, "
        "1000 packets yielded by PyShark, 170 analyzable packets extracted, "
        "830 yielded packets skipped."
    )


def test_packet_read_complete_message_handles_unknown_total() -> None:
    assert _packet_read_complete_message(
        pyshark_packets=1_000,
        analyzable_packets=170,
        total_packets=None,
    ) == (
        "Packet reading complete: pcap packet total unavailable because capinfos was not "
        "found or could not read it, 1000 packets yielded by PyShark, "
        "170 analyzable packets extracted, 830 yielded packets skipped."
    )


def test_progress_reporter_refreshes_same_console_line(monkeypatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(cli.console, "file", output)
    reporter = _ProgressReporter(total_packets=100)

    reporter(1)
    reporter(100)
    reporter.finish()

    text = output.getvalue()
    assert "\r[info] Local analysis progress: 1% (1/100 raw packets)" in text
    assert "\r[info] Local analysis progress: 100% (100/100 raw packets)" in text
    assert "\n" not in text


def test_progress_reporter_refreshes_after_five_seconds(monkeypatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(cli.console, "file", output)
    times = iter([100.0, 104.9, 105.0])
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(times))
    reporter = _ProgressReporter(total_packets=100)

    reporter(1)
    reporter(2)
    reporter(3)

    text = output.getvalue()
    assert "1% (1/100 raw packets)" in text
    assert "2% (2/100 raw packets)" not in text
    assert "3% (3/100 raw packets)" in text


def test_analyze_json_option_without_filename_defaults_to_capture_name() -> None:
    assert _normalize_optional_json_arg(["analyze", "capture.pcap", "--json"]) == [
        "analyze",
        "capture.pcap",
        "--json",
        "capture.json",
    ]


def test_optional_esp_udp_port_normalization() -> None:
    assert _normalize_optional_json_arg(["analyze", "capture.pcap", "--esp-udp-port"]) == [
        "analyze", "capture.pcap", "--esp-udp-port", "-1",
    ]
    assert _normalize_optional_json_arg(
        ["analyze", "--esp-udp-port", "capture.pcap", "--json", "--no-llm"]
    ) == ["analyze", "--esp-udp-port", "-1", "capture.pcap", "--json", "capture.json", "--no-llm"]
    explicit = ["analyze", "capture.pcap", "--esp-udp-port", "12366", "--esp-udp-port", "12346"]
    assert _normalize_optional_json_arg(explicit) == explicit
    assert _normalize_optional_json_arg(
        ["analyze", "capture.pcap", "--esp-udp-port", "--agent"]
    ) == ["analyze", "capture.pcap", "--esp-udp-port", "-1", "--agent"]


def test_optional_json_filename_with_following_flag_and_directory() -> None:
    assert _normalize_optional_json_arg(["analyze", "capture.pcap", "--json", "--no-llm"]) == [
        "analyze",
        "capture.pcap",
        "--json",
        "capture.json",
        "--no-llm",
    ]
    assert _normalize_optional_json_arg(["analyze", "~/Downloads/dlts.pcapng", "--json"]) == [
        "analyze",
        "~/Downloads/dlts.pcapng",
        "--json",
        "dlts.json",
    ]


def test_analyze_load_summary_without_filename_defaults_to_capture_name() -> None:
    assert _normalize_optional_json_arg(["analyze", "capture.pcap", "--load-summary"]) == [
        "analyze",
        "capture.pcap",
        "--load-summary",
        "capture.json",
    ]
    assert _normalize_optional_json_arg(
        ["analyze", "capture.pcap", "--load-summary", "--agent"]
    ) == [
        "analyze",
        "capture.pcap",
        "--load-summary",
        "capture.json",
        "--agent",
    ]


def test_json_option_normalizer_preserves_explicit_filename_and_models_json() -> None:
    assert _normalize_optional_json_arg(["analyze", "capture.pcap", "--json", "mine.json"]) == [
        "analyze",
        "capture.pcap",
        "--json",
        "mine.json",
    ]
    assert _normalize_optional_json_arg(["models", "--json"]) == ["models", "--json"]


def test_json_output_path_uses_private_folder() -> None:
    assert _summary_json_output_path(Path("mine.json")) == cli.FLOWPILOT_PRIVATE_DIR / "mine.json"
    assert (
        _summary_json_output_path(Path("reports/mine.json"))
        == cli.FLOWPILOT_PRIVATE_DIR / "mine.json"
    )
    assert _summary_json_output_path(Path("flow-summary.json")) == Path(
        cli.FLOWPILOT_PRIVATE_DIR / "flow-summary.json"
    )


def test_default_summary_path_uses_capture_stem() -> None:
    assert _default_summary_path_for_capture(Path("~/Downloads/dlts.pcap")) == Path("dlts.json")
    assert _default_summary_path_for_capture(Path("capture.pcapng")) == Path("capture.json")


def test_analyze_writes_default_json_without_json_option(tmp_path, monkeypatch) -> None:
    capture_path = tmp_path / "dlts.pcap"
    capture_path.write_bytes(b"pcap")
    private_dir = tmp_path / "private"
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", private_dir)
    monkeypatch.setattr(cli, "_capture_packet_count", lambda _path: 0)
    monkeypatch.setattr(cli, "read_capture", lambda *args, **kwargs: iter(()))
    monkeypatch.setattr(cli, "summarize_capture", lambda _observations: summary)
    monkeypatch.setattr(cli, "_render_summary", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "_info", lambda _message: None)

    cli.analyze(capture_path, no_llm=True)

    output_path = private_dir / "dlts.json"
    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["summary"]["flow_count"] == 0
    assert payload["source_capture_path"] == str(capture_path)


@pytest.mark.parametrize("output", [None, "capture.json", "alias.json", "chosen.json"])
def test_loaded_summary_filter_preserves_source_and_previous_reports(tmp_path, monkeypatch, output):
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    flows = [
        FlowSummary(
            key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol=protocol),
            packet_count=1, byte_count=100,
        ) for protocol in ("TCP", "UDP")
    ]
    summary = CaptureSummary(
        packet_count=2, total_bytes=200, flow_count=2, protocols={"TCP": 1, "UDP": 1},
        top_ports={}, issue_counts={}, names=[], flows=flows,
    )
    source = tmp_path / "capture.json"
    source.write_text(json.dumps({"summary": summary.model_dump(mode="json")}))
    original = source.read_bytes()
    if output == "alias.json":
        (tmp_path / output).hardlink_to(source)
    previous = tmp_path / "capture.filtered.json"
    previous.write_text("previous report")
    args = [
        "analyze", "capture.pcap", "--load-summary", str(source),
        "--protocol", "TCP", "--no-llm",
    ]
    if output:
        args += ["--json", output]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    assert source.read_bytes() == original
    assert previous.read_text() == "previous report"
    if output is None:
        assert set(tmp_path.iterdir()) == {source, previous}
        assert "Wrote JSON report" not in result.output
        return
    name = "chosen.json" if output == "chosen.json" else "capture.filtered.2.json"
    destination = tmp_path / name
    filtered = json.loads(destination.read_text())["summary"]
    assert filtered["flow_count"] == 1
    assert filtered["flows"][0]["key"]["protocol"] == "TCP"


def test_loaded_summary_without_explicit_json_does_not_save(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    summary = CaptureSummary(
        packet_count=0, total_bytes=0, flow_count=0, protocols={}, top_ports={},
        issue_counts={}, names=[], flows=[],
    )
    source = tmp_path / "capture.json"
    source.write_text(summary.model_dump_json())
    original = source.read_bytes()
    for _ in range(2):
        result = CliRunner().invoke(cli.app, [
            "analyze", "capture.pcap", "--load-summary", str(source), "--no-llm",
        ])
        assert result.exit_code == 0, result.output
    assert source.read_bytes() == original
    assert list(tmp_path.iterdir()) == [source]
    assert "Wrote JSON report" not in result.output


def test_load_summary_accepts_json_report_envelope(tmp_path) -> None:
    summary = CaptureSummary(
        packet_count=1,
        total_bytes=100,
        flow_count=1,
        protocols={"TCP": 1},
        top_ports={"443": 1},
        issue_counts={},
        names=[],
        flows=[
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.1",
                    endpoint_b="10.0.0.2",
                    port_a=50000,
                    port_b=443,
                    protocol="TCP",
                ),
                packet_count=1,
                byte_count=100,
            )
        ],
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(
        '{"summary": ' + summary.model_dump_json() + "}",
        encoding="utf-8",
    )

    loaded = _load_summary(report_path)

    assert loaded.flow_count == 1
    assert loaded.flows[0].key.port_b == 443


def test_load_summary_reads_source_capture_path_metadata(tmp_path) -> None:
    source_capture = tmp_path / "capture.pcap"
    summary = CaptureSummary(
        packet_count=1,
        total_bytes=100,
        flow_count=1,
        protocols={"TCP": 1},
        top_ports={"443": 1},
        issue_counts={},
        names=[],
        flows=[
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.1",
                    endpoint_b="10.0.0.2",
                    port_a=50000,
                    port_b=443,
                    protocol="TCP",
                ),
                packet_count=1,
                byte_count=100,
            )
        ],
    )
    report_path = tmp_path / "report.json"
    report_path.write_text(
        '{"source_capture_path": "'
        + str(source_capture)
        + '", "summary": '
        + summary.model_dump_json()
        + "}",
        encoding="utf-8",
    )

    loaded, loaded_source_capture = _load_summary_with_metadata(report_path)

    assert loaded.flow_count == 1
    assert loaded_source_capture == source_capture


def test_apply_summary_filters_filters_loaded_flows_by_port() -> None:
    summary = CaptureSummary(
        packet_count=2,
        total_bytes=300,
        flow_count=2,
        protocols={"TCP": 2},
        top_ports={"443": 1, "445": 1},
        issue_counts={"tcp_lost_segment": 1},
        names=["api.example.com", "fileserver"],
        flows=[
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.1",
                    endpoint_b="10.0.0.2",
                    port_a=50000,
                    port_b=443,
                    protocol="TCP",
                ),
                packet_count=1,
                byte_count=100,
                names=["api.example.com"],
            ),
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.3",
                    endpoint_b="10.0.0.4",
                    port_a=50001,
                    port_b=445,
                    protocol="TCP",
                ),
                packet_count=1,
                byte_count=200,
                issue_counts={"tcp_lost_segment": 1},
                names=["fileserver"],
            ),
        ],
    )

    filtered = _apply_summary_filters(
        summary,
        flow_filter=FlowFilter(port=445),
        sip_phone=None,
        include_redirects=False,
    )

    assert filtered.flow_count == 1
    assert filtered.packet_count == 1
    assert filtered.total_bytes == 200
    assert filtered.top_ports == {"50001": 1, "445": 1}
    assert filtered.issue_counts == {"tcp_lost_segment": 1}
    assert filtered.names == ["fileserver"]
    assert filtered.flows[0].key.port_b == 445


def test_refreshing_info_refreshes_wait_messages_and_prints_normal_info(monkeypatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(cli.console, "file", output)
    printed = []
    monkeypatch.setattr(cli, "_info", printed.append)
    progress = _RefreshingInfo()

    progress("__flowpilot_refresh__:LLM reasoning waiting: 3s")
    progress("__flowpilot_refresh__:LLM reasoning waiting: 6s")
    progress("LangGraph gathered 1 deep evidence result(s).")

    text = output.getvalue()
    assert "\r[info] LLM reasoning waiting: 3s" in text
    assert "\r[info] LLM reasoning waiting: 6s" in text
    assert "\x1b[2K" not in text
    assert printed == ["LangGraph gathered 1 deep evidence result(s)."]


def test_models_command_prints_models_endpoint(monkeypatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(cli.console, "file", output)
    monkeypatch.setattr(cli, "openai_models_url", lambda: "https://llm.example/v1/models")
    monkeypatch.setattr(
        cli,
        "list_openai_models",
        lambda: [{"id": "model-a", "owned_by": "owner", "created": 123}],
    )

    cli.models_command()

    text = output.getvalue()
    assert "Models endpoint:" in text
    assert "https://llm.example/v1/models" in text
    assert "model-a" in text


def test_models_command_json_includes_models_endpoint(monkeypatch) -> None:
    output = io.StringIO()
    monkeypatch.setattr(cli.console, "file", output)
    monkeypatch.setattr(cli, "openai_models_url", lambda: "https://llm.example/v1/models")
    monkeypatch.setattr(
        cli,
        "list_openai_models",
        lambda: [{"id": "model-a", "owned_by": "owner", "created": 123}],
    )

    cli.models_command(json_output=True)

    payload = json.loads(output.getvalue())
    assert payload == {
        "url": "https://llm.example/v1/models",
        "models": [{"id": "model-a", "owned_by": "owner", "created": 123}],
    }


def test_parse_capinfos_packet_count_reads_named_count_only() -> None:
    output = "File name: capture-130mb.pcap\nPacket count: 1,234\n"

    assert _parse_capinfos_packet_count(output) == 1234
    assert _parse_capinfos_packet_count("File name: capture-130mb.pcap\n") is None


def test_count_packets_in_pcap(tmp_path) -> None:
    capture = tmp_path / "tiny.pcap"
    with capture.open("wb") as capture_file:
        capture_file.write(b"\xd4\xc3\xb2\xa1")
        capture_file.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for payload in (b"abc", b"defg"):
            capture_file.write(struct.pack("<IIII", 0, 0, len(payload), len(payload)))
            capture_file.write(payload)

    assert _count_packets_in_capture(capture) == 2


def test_count_packets_in_pcapng(tmp_path) -> None:
    capture = tmp_path / "tiny.pcapng"
    with capture.open("wb") as capture_file:
        capture_file.write(struct.pack("<II", 0x0A0D0D0A, 28))
        capture_file.write(b"\x4d\x3c\x2b\x1a")
        capture_file.write(struct.pack("<HHqI", 1, 0, -1, 28))
        for payload in (b"abc", b"defg"):
            padded_length = (len(payload) + 3) // 4 * 4
            block_length = 28 + padded_length + 4
            capture_file.write(
                struct.pack("<IIIIIII", 6, block_length, 0, 0, 0, len(payload), len(payload))
            )
            capture_file.write(payload.ljust(padded_length, b"\0"))
            capture_file.write(struct.pack("<I", block_length))

    assert _count_packets_in_capture(capture) == 2


def test_cached_capture_session_copies_and_removes_capture(tmp_path) -> None:
    capture = tmp_path / "original.pcap"
    capture.write_bytes(b"pcap bytes")

    session = _CachedCaptureSession.create(capture, keep=False)
    cached_capture = session.capture_path
    workspace = session.workspace

    assert cached_capture != capture
    assert cached_capture.read_bytes() == b"pcap bytes"
    assert workspace.exists()

    session.close()

    assert not workspace.exists()


def test_cached_capture_session_can_keep_workspace(tmp_path) -> None:
    capture = tmp_path / "original.pcap"
    capture.write_bytes(b"pcap bytes")

    session = _CachedCaptureSession.create(capture, keep=True)
    workspace = session.workspace

    session.close()

    assert workspace.exists()
    shutil.rmtree(workspace)


def test_format_smb_counter_lines_labels_numeric_commands() -> None:
    assert format_smb_counter_lines({"0": 2, "11": 1, "Read": 1}, SMB1_COMMAND_NAMES) == (
        "SMBmkdir(0): 2\nSMBwrite(11): 1\nRead: 1"
    )


def test_format_smb_counter_lines_labels_smb2_numeric_commands() -> None:
    assert format_smb_counter_lines({"8": 2, "9": 1, "11": 1}, SMB2_COMMAND_NAMES) == (
        "SMB2read(8): 2\nSMB2write(9): 1\nSMB2ioctl(11): 1"
    )


def test_format_smb_counter_lines_labels_numeric_statuses() -> None:
    assert format_smb_counter_lines(
        {
            "0x00000000": 2,
            "0xc0000022": 1,
            "0xdeadbeef": 1,
        },
        SMB_STATUS_NAMES,
    ) == (
        "STATUS_SUCCESS: 2\n"
        "STATUS_ACCESS_DENIED: 1\n"
        "NTSTATUS_UNKNOWN(0xdeadbeef): 1"
    )


def test_format_smb_counter_lines_removes_hex_from_preformatted_statuses() -> None:
    assert format_smb_counter_lines(
        {
            "STATUS_SUCCESS (0x00000000)": 2,
            "STATUS_ACCESS_DENIED(0xc0000022)": 1,
        },
        SMB_STATUS_NAMES,
    ) == "STATUS_SUCCESS: 2\nSTATUS_ACCESS_DENIED: 1"


def test_format_smb_transfer_line_shows_unavailable_lengths() -> None:
    assert format_smb_transfer_line("write", 10, 0, 10) == (
        "write 10 ops / 0 bytes (10 ops length unavailable)"
    )


def test_format_smb_transfer_line_shows_related_files() -> None:
    assert format_smb_transfer_line(
        "write",
        10,
        4096,
        0,
        0,
        ["upload \\\\share\\upload.bin"],
    ) == "write 10 ops / 4096 bytes\nupload \\\\share\\upload.bin"


def test_format_smb_transfer_line_shows_offset_inference() -> None:
    assert format_smb_transfer_line("write", 10, 36864, 1, 9) == (
        "write 10 ops / 36864 bytes "
        "(9 ops inferred from offsets, 1 ops length unavailable)"
    )


def test_format_smb_transfer_labels_payload_and_flow_rates() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        byte_count=1_000_000,
        first_seen="2026-01-01T00:00:00",
        last_seen="2026-01-01T00:00:01",
        smb_write_ops=10,
        smb_write_unknown_bytes_ops=10,
    )

    assert "smb payload 0.000 Mbps" in format_smb_transfer(flow)
    assert "flow total 8.000 Mbps" in format_smb_transfer(flow)


def test_format_smb_transfer_hides_small_walkthrough_files() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        smb_read_ops=2,
        smb_read_bytes=8192,
        smb_read_bytes_by_file={"\\\\share\\preview.docx": 8192},
    )

    assert "download" not in format_smb_transfer(flow)


def test_format_smb_transfer_shows_large_download_files() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        smb_read_ops=20,
        smb_read_bytes=2_097_152,
        smb_read_bytes_by_file={"\\\\share\\download.iso": 2_097_152},
    )

    assert "download \\\\share\\download.iso (2.0 MiB)" in format_smb_transfer(flow)


def test_format_smb_capabilities_shows_client_and_server_offers() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        smb_client_capabilities=["DFS", "dialect=0x0311", "signing enabled"],
        smb_server_capabilities=["DFS", "multi-channel", "encryption"],
    )

    assert format_smb_capabilities(flow) == (
        "DFS (c,s)\n"
        "dialect=0x0311 (c)\n"
        "signing enabled (c)\n"
        "multi-channel (s)\n"
        "encryption (s)"
    )


def test_format_flow_issues_does_not_show_informational_names() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        names=["example.com", "10.0.0.30:443"],
    )

    assert _format_flow_issues(flow) == ""


def test_format_flow_issues_shows_counts_and_diagnostics() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        packet_count=5,
        issue_counts={"tcp_retransmission": 2},
        src_to_dst_packets=5,
        dst_to_src_packets=0,
    )

    assert _format_flow_issues(flow) == (
        "tcp_retransmission=2\n"
        "one-way traffic observed\n"
        "tcp retransmission rate above 1 percent"
    )


def test_flow_metrics_includes_out_of_order_rate() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        packet_count=4,
        src_to_dst_packets=4,
        src_to_dst_issue_counts={"tcp_out_of_order": 1},
        issue_counts={"tcp_out_of_order": 1},
    )

    assert "ooo 25.0%/0%" in _flow_metrics(flow)


def test_format_agent_evidence_counts_prefers_protocol_counts() -> None:
    assert _format_agent_evidence_counts(
        {"udp_metadata_counts": {"dns_packets": 2, "dns_error_responses": 1}}
    ) == "dns_packets: 2\ndns_error_responses: 1"


def test_format_agent_evidence_counts_shows_smb_credit_counts() -> None:
    assert _format_agent_evidence_counts(
        {
            "smb2_credit_counts": {
                "smb2_packets": 10,
                "credit_charge_total": 20,
                "credit_charge_max": 4,
                "credit_request_total": 128,
                "credit_request_max": 64,
                "credit_grant_total": 96,
                "credit_grant_max": 32,
                "credit_grant_zero_packets": 1,
                "write_packets": 3,
            }
        }
    ) == (
        "smb2_packets: 10\n"
        "credit_charge_total: 20\n"
        "credit_charge_max: 4\n"
        "credit_request_total: 128\n"
        "credit_request_max: 64\n"
        "credit_grant_total: 96\n"
        "credit_grant_max: 32\n"
        "credit_grant_zero_packets: 1\n"
        "write_packets: 3"
    )


def test_format_agent_evidence_counts_shows_tcp_window_stats() -> None:
    assert _format_agent_evidence_counts(
        {
            "tcp_analysis_counts": {
                "tcp.analysis.window_full": 3,
                "tcp.analysis.zero_window": 1,
            },
            "tcp_window_stats": {
                "advertised_window_min": 0,
                "advertised_window_max": 131072,
                "bytes_in_flight_max": 262144,
                "window_scale_factors": [64],
                "mss_values": [1380, 1460],
                "mss_min": 1380,
                "mss_max": 1460,
            },
        }
    ) == (
        "tcp.analysis.window_full: 3\n"
        "tcp.analysis.zero_window: 1\n"
        "advertised_window_min: 0\n"
        "advertised_window_max: 131072\n"
        "bytes_in_flight_max: 262144\n"
        "window_scale_factors: [64]\n"
        "mss_values: [1380, 1460]\n"
        "mss_min: 1380\n"
        "mss_max: 1460"
    )


def test_format_agent_evidence_counts_shows_esp_header_findings_without_sequences() -> None:
    assert _format_agent_evidence_counts(
        {
            "esp_metadata_counts": {
                "esp_packets": 5,
                "nat_t_udp_4500_packets": 5,
                "fragmented_packets": 1,
                "dscp_values": ["46"],
                "ip_length_min": 1200,
                "ip_length_max": 1480,
                "df_bit": "on",
            },
            "esp_direction_stats": [
                {
                    "direction": "10.0.0.1 -> 10.0.0.2",
                    "packets": 5,
                    "missing_count": 2,
                    "largest_sequence_gap": 2,
                    "gap_distribution": {"gap=2": 1},
                    "out_of_order_count": 1,
                    "duplicate_count": 1,
                }
            ],
        }
    ) == (
        "esp_packets: 5\n"
        "nat_t_udp_4500_packets: 5\n"
        "fragmented_packets: 1\n"
        "dscp_values: ['46']\n"
        "ip_length_min: 1200\n"
        "ip_length_max: 1480\n"
        "df_bit: on"
    )


def test_tls_detail_rows_respect_top_flow_slice() -> None:
    cert_flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        byte_count=10,
        tls_certificates=[
            TlsCertificateObservation(
                presenter_ip="203.0.113.10",
                presenter_port=443,
                subject_cn="api.example.com",
            )
        ],
    )
    larger_flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="198.51.100.10",
            port_a=50001,
            port_b=80,
            protocol="TCP",
        ),
        byte_count=1_000,
    )
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=2,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[larger_flow, cert_flow],
    )

    rows = tls_detail_rows(summary, show_flows=1)

    assert rows == []


def test_tls_detail_rows_include_sni_without_certificate() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        tls_snis=["api.example.com"],
    )
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=1,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[flow],
    )

    rows = tls_detail_rows(summary, show_flows=10)

    assert rows == [(1, flow, "-", "10.0.0.10:50000 <-> 203.0.113.10:443", [])]


def test_tls_detail_rows_include_alert_without_certificate() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        tls_alerts={"Fatal (2) Close Notify (0)": 1},
        issue_counts={"tls_alert": 1, "tls_fatal_alert": 1},
    )
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=1,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[flow],
    )

    rows = tls_detail_rows(summary, show_flows=10)

    assert rows == [(1, flow, "-", "10.0.0.10:50000 <-> 203.0.113.10:443", [])]


def test_tls_endpoint_with_role_adds_role_on_second_line() -> None:
    assert tls_endpoint_with_role("1.1.1.1:443", "server") == "1.1.1.1:443\n(server)"
    assert tls_endpoint_with_role("1.1.1.1:443", "-") == "1.1.1.1:443"


def test_tls_sni_for_endpoint_only_shows_sender_sni() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        tls_snis=["api.example.com"],
        tls_sni_endpoints={"10.0.0.10:50000": ["api.example.com"]},
    )

    assert tls_sni_for_endpoint(flow, "10.0.0.10:50000") == "api.example.com"
    assert tls_sni_for_endpoint(flow, "203.0.113.10:443") == "-"


def test_tls_expiration_shows_only_not_after() -> None:
    certificate = TlsCertificateObservation(
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
    )

    assert expiration(certificate) == "2027-01-01"


def test_tls_issue_text_lists_flow_issues_on_new_lines() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        issue_counts={"tls_alert": 1, "tls_fatal_alert": 1},
        tls_alerts={"fatal (2) close_notify (0)": 1},
        tls_alert_endpoints={"203.0.113.10:443": {"fatal (2) close_notify (0)": 1}},
        tls_certificates=[
            TlsCertificateObservation(
                presenter_ip="203.0.113.10",
                presenter_port=443,
                subject_cn="api.example.com",
            )
        ],
    )

    assert tls_issue_text(flow, "10.0.0.10:50000") == ""
    assert tls_issue_text(flow, "203.0.113.10:443") == (
        "sent tls alert: fatal (2) close_notify (0) (x1)"
    )
    assert tls_issue_text(flow, "10.0.0.10:50000 <-> 203.0.113.10:443") == (
        "tls alert: fatal (2) close_notify (0) (x1)"
    )


def test_format_tls_certificates_lists_chain_one_cert_per_line() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        tls_certificates=[
            TlsCertificateObservation(
                presenter_role="server",
                presenter_ip="203.0.113.10",
                presenter_port=443,
                subject_cn="api.example.com",
                issuer_cn="Example Issuing CA",
                not_after="2027-01-01T00:00:00+00:00",
                san_dns=["api.example.com"],
            ),
            TlsCertificateObservation(
                presenter_role="server",
                presenter_ip="203.0.113.10",
                presenter_port=443,
                subject_cn="Example Issuing CA",
                issuer_cn="Example Root CA",
                not_after="2000-01-01T00:00:00+00:00",
            ),
        ],
    )

    assert format_tls_certificates(flow) == (
        "cert 1 / role=server / endpoint=203.0.113.10:443 / "
        "subject=api.example.com / issuer=Example Issuing CA / "
        "expiration=2027-01-01 / san=api.example.com\n"
        "cert 2 / role=server / endpoint=203.0.113.10:443 / "
        "subject=Example Issuing CA / issuer=Example Root CA / "
        "expiration=2000-01-01 / san=- / "
        "issue=certificate expired 2000-01-01T00:00:00+00:00"
    )


def test_format_certificate_column_lists_all_certs_per_line() -> None:
    certificates = [
        TlsCertificateObservation(
            subject_cn="api.example.com",
            issuer_cn="Example Issuing CA",
            not_after="2027-01-01T00:00:00+00:00",
            san_dns=["api.example.com"],
        ),
        TlsCertificateObservation(
            subject_cn="Example Issuing CA",
            issuer_cn="Example Root CA",
            not_after="2030-01-01T00:00:00+00:00",
        ),
    ]

    assert format_certificate_column(certificates, "subject") == (
        "Cert 1: api.example.com\n"
        "Cert 2: Example Issuing CA"
    )
    assert format_certificate_column(certificates, "issuer") == (
        "Cert 1: Example Issuing CA\n"
        "Cert 2: Example Root CA"
    )
    assert format_certificate_column(certificates, "expiration") == (
        "Cert 1: 2027-01-01\n"
        "Cert 2: 2030-01-01"
    )
    assert format_certificate_column(certificates, "san") == (
        "Cert 1: api.example.com\n"
        "Cert 2: -"
    )


def test_tls_detail_rows_use_object_position_when_flow_keys_repeat() -> None:
    key = FlowKey(
        endpoint_a="10.0.0.10",
        endpoint_b="203.0.113.10",
        port_a=50000,
        port_b=443,
        protocol="TCP",
    )
    first_flow = FlowSummary(
        key=key,
        tls_certificates=[
            TlsCertificateObservation(
                presenter_ip="203.0.113.10",
                presenter_port=443,
                subject_cn="api.example.com",
            )
        ],
    )
    later_duplicate = FlowSummary(key=key, tls_snis=["api.example.com"])
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=2,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[first_flow, later_duplicate],
    )

    rows = tls_detail_rows(summary, show_flows=1)

    assert rows[0][0] == 1
    assert rows[0][2] == "-"


def test_tls_detail_rows_prioritize_certificates_within_top_flow_slice() -> None:
    placeholder_flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="198.51.100.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        byte_count=1_000,
    )
    cert_flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=53150,
            port_b=443,
            protocol="TCP",
        ),
        byte_count=10,
        tls_certificates=[
            TlsCertificateObservation(
                presenter_ip="203.0.113.10",
                presenter_port=443,
                subject_cn="api.example.com",
            )
        ],
    )
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=2,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[placeholder_flow, cert_flow],
    )

    rows = tls_detail_rows(summary, show_flows=2)

    assert rows[0][0] == 2
    assert rows[0][1] == cert_flow


def test_percent_keeps_small_nonzero_rates_visible() -> None:
    assert _percent(48 / 100_000) == "0.048%"


def test_direction_shows_packet_and_byte_split() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        src_to_dst_packets=5,
        dst_to_src_packets=2,
        src_to_dst_bytes=10_000,
        dst_to_src_bytes=500,
    )

    assert _direction(flow) == "pkts 5/2\nbytes 10000/500\nthr n/a/n/a Mbps"
    flow.first_seen = datetime(2026, 1, 1)
    flow.last_seen = datetime(2026, 1, 1, 0, 0, 2)
    assert _direction(flow) == "pkts 5/2\nbytes 10000/500\nthr 0.040/0.002 Mbps"


def test_traffic_matches_direction_label_style() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        packet_count=7,
        byte_count=10_500,
    )

    assert _traffic(flow) == "pkts 7\nbytes 10500"


@pytest.mark.parametrize("limit", [0, 1, 10])
def test_request_limit_reaches_analysis_and_chat(tmp_path, monkeypatch, limit):
    from flowpilot.models import ReasoningReport

    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "_capture_packet_count", lambda _: 0)
    monkeypatch.setattr(cli, "read_capture", lambda *args, **kwargs: iter([]))
    seen = []
    report = ReasoningReport(executive_summary="Done", risk_level="unknown",
                             findings=[], next_questions=[])

    def reasoning(summary, **kwargs):
        seen.append(kwargs["max_tool_rereads"])
        assert kwargs["sample_offset"] == 5000
        return {"report": report, "deep_evidence": []}

    def chat(summary, question, **kwargs):
        seen.append(kwargs["max_tool_rereads"])
        assert kwargs["sample_offset"] == 5000
        return {"answer": "Done"}

    monkeypatch.setattr(cli, "run_agent_reasoning_state", reasoning)
    monkeypatch.setattr(cli, "run_agent_chat_state", chat)
    questions = iter(["inspect flow 1", "exit"])
    monkeypatch.setattr(cli.Prompt, "ask", lambda *args, **kwargs: next(questions))
    result = CliRunner().invoke(cli.app, [
        "analyze", "capture.pcap", "--agent", "--chat", "--max-request", str(limit),
        "--offset", "5000",
    ])
    assert result.exit_code == 0, result.output
    assert seen == [limit, limit]


def test_request_limit_rejects_negative():
    result = CliRunner().invoke(cli.app, ["analyze", "capture.pcap", "--max-request", "-1"])
    assert result.exit_code == 2


def test_offset_rejects_negative():
    result = CliRunner().invoke(cli.app, ["analyze", "capture.pcap", "--offset", "-1"])
    assert result.exit_code == 2
