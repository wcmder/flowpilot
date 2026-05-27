from pathlib import Path

from flowpilot.cli import (
    _SMB_COMMAND_NAMES,
    _SMB_STATUS_NAMES,
    _format_esp_gap_distribution,
    _format_smb_counter_lines,
    _local_analysis_start_message,
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


def test_format_smb_counter_lines_labels_numeric_commands() -> None:
    assert _format_smb_counter_lines({"0": 2, "Read": 1}, _SMB_COMMAND_NAMES) == (
        "SMBmkdir(0): 2\nRead: 1"
    )


def test_format_smb_counter_lines_labels_numeric_statuses() -> None:
    assert _format_smb_counter_lines({"0x00000000": 2}, _SMB_STATUS_NAMES) == (
        "STATUS_SUCCESS(0x00000000): 2"
    )
