import struct
from pathlib import Path

from flowpilot.cli import (
    _count_packets_in_capture,
    _direction,
    _format_flow_issues,
    _format_smb_capabilities,
    _format_smb_counter_lines,
    _format_smb_transfer,
    _format_smb_transfer_line,
    _local_analysis_start_message,
    _packet_read_complete_message,
    _parse_capinfos_packet_count,
    _percent,
)
from flowpilot.dns import dns_issue_summary
from flowpilot.esp import format_esp_gap_distribution
from flowpilot.models import FlowKey, FlowSummary
from flowpilot.smb import SMB1_COMMAND_NAMES, SMB2_COMMAND_NAMES, SMB_STATUS_NAMES


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


def test_format_smb_counter_lines_labels_numeric_commands() -> None:
    assert _format_smb_counter_lines({"0": 2, "11": 1, "Read": 1}, SMB1_COMMAND_NAMES) == (
        "SMBmkdir(0): 2\nSMBwrite(11): 1\nRead: 1"
    )


def test_format_smb_counter_lines_labels_smb2_numeric_commands() -> None:
    assert _format_smb_counter_lines({"8": 2, "9": 1, "11": 1}, SMB2_COMMAND_NAMES) == (
        "SMB2read(8): 2\nSMB2write(9): 1\nSMB2ioctl(11): 1"
    )


def test_format_smb_counter_lines_labels_numeric_statuses() -> None:
    assert _format_smb_counter_lines(
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
    assert _format_smb_counter_lines(
        {
            "STATUS_SUCCESS (0x00000000)": 2,
            "STATUS_ACCESS_DENIED(0xc0000022)": 1,
        },
        SMB_STATUS_NAMES,
    ) == "STATUS_SUCCESS: 2\nSTATUS_ACCESS_DENIED: 1"


def test_format_smb_transfer_line_shows_unavailable_lengths() -> None:
    assert _format_smb_transfer_line("write", 10, 0, 10) == (
        "write 10 ops / 0 bytes (10 ops length unavailable)"
    )


def test_format_smb_transfer_line_shows_related_files() -> None:
    assert _format_smb_transfer_line(
        "write",
        10,
        4096,
        0,
        0,
        ["upload \\\\share\\upload.bin"],
    ) == "write 10 ops / 4096 bytes\nupload \\\\share\\upload.bin"


def test_format_smb_transfer_line_shows_offset_inference() -> None:
    assert _format_smb_transfer_line("write", 10, 36864, 1, 9) == (
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

    assert "smb payload 0.000 Mbps" in _format_smb_transfer(flow)
    assert "flow total 8.000 Mbps" in _format_smb_transfer(flow)


def test_format_smb_transfer_hides_small_walkthrough_files() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        smb_read_ops=2,
        smb_read_bytes=8192,
        smb_read_bytes_by_file={"\\\\share\\preview.docx": 8192},
    )

    assert "download" not in _format_smb_transfer(flow)


def test_format_smb_transfer_shows_large_download_files() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        smb_read_ops=20,
        smb_read_bytes=2_097_152,
        smb_read_bytes_by_file={"\\\\share\\download.iso": 2_097_152},
    )

    assert "download \\\\share\\download.iso (2.0 MiB)" in _format_smb_transfer(flow)


def test_format_smb_capabilities_shows_client_and_server_offers() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        smb_client_capabilities=["DFS", "dialect=0x0311", "signing enabled"],
        smb_server_capabilities=["DFS", "multi-channel", "encryption"],
    )

    assert _format_smb_capabilities(flow) == (
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

    assert _direction(flow) == "pkts 5/2\nbytes 10000/500"
