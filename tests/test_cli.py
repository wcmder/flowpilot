import struct
from pathlib import Path

from flowpilot.cli import (
    _SMB_COMMAND_NAMES,
    _SMB_STATUS_NAMES,
    _count_packets_in_capture,
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
    assert _format_smb_counter_lines({"0": 2, "Read": 1}, _SMB_COMMAND_NAMES) == (
        "SMBmkdir(0): 2\nRead: 1"
    )


def test_format_smb_counter_lines_labels_numeric_statuses() -> None:
    assert _format_smb_counter_lines({"0x00000000": 2}, _SMB_STATUS_NAMES) == (
        "STATUS_SUCCESS(0x00000000): 2"
    )
