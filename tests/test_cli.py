from pathlib import Path

from flowpilot.cli import (
    _SMB_COMMAND_NAMES,
    _SMB_STATUS_NAMES,
    _format_esp_gap_distribution,
    _format_smb_counter_lines,
    _local_analysis_start_message,
    _packet_read_complete_message,
    _parse_capinfos_packet_count,
)


def test_format_esp_gap_distribution_groups_missing_counts() -> None:
    gaps = [
        {"after_sequence": 1, "next_sequence": 3, "gap": 1, "missing": 1},
        {"after_sequence": 10, "next_sequence": 12, "gap": 1, "missing": 1},
        {"after_sequence": 20, "next_sequence": 23, "gap": 2, "missing": 2},
    ]

    assert _format_esp_gap_distribution(gaps) == "gap=1(x2) gap=2(x1)"


def test_format_esp_gap_distribution_handles_no_gaps() -> None:
    assert _format_esp_gap_distribution([]) == "none"


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


def test_format_smb_counter_lines_labels_numeric_commands() -> None:
    assert _format_smb_counter_lines({"0": 2, "Read": 1}, _SMB_COMMAND_NAMES) == (
        "SMBmkdir(0): 2\nRead: 1"
    )


def test_format_smb_counter_lines_labels_numeric_statuses() -> None:
    assert _format_smb_counter_lines({"0x00000000": 2}, _SMB_STATUS_NAMES) == (
        "STATUS_SUCCESS(0x00000000): 2"
    )
