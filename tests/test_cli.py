import shutil
import struct
from pathlib import Path

from flowpilot.cli import (
    _CachedCaptureSession,
    _count_packets_in_capture,
    _direction,
    _expiration,
    _format_agent_evidence_counts,
    _format_certificate_column,
    _format_flow_issues,
    _format_smb_capabilities,
    _format_smb_counter_lines,
    _format_smb_transfer,
    _format_smb_transfer_line,
    _format_tls_certificates,
    _local_analysis_start_message,
    _packet_read_complete_message,
    _parse_capinfos_packet_count,
    _percent,
    _tls_detail_rows,
    _tls_endpoint_with_role,
    _tls_issue_text,
    _tls_sni_for_endpoint,
    _traffic,
)
from flowpilot.dns import dns_issue_summary
from flowpilot.esp import format_esp_gap_distribution
from flowpilot.models import CaptureSummary, FlowKey, FlowSummary, TlsCertificateObservation
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


def test_format_agent_evidence_counts_prefers_protocol_counts() -> None:
    assert _format_agent_evidence_counts(
        {"udp_metadata_counts": {"dns_packets": 2, "dns_error_responses": 1}}
    ) == "dns_packets: 2\ndns_error_responses: 1"


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

    rows = _tls_detail_rows(summary, show_flows=1)

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

    rows = _tls_detail_rows(summary, show_flows=10)

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

    rows = _tls_detail_rows(summary, show_flows=10)

    assert rows == [(1, flow, "-", "10.0.0.10:50000 <-> 203.0.113.10:443", [])]


def test_tls_endpoint_with_role_adds_role_on_second_line() -> None:
    assert _tls_endpoint_with_role("1.1.1.1:443", "server") == "1.1.1.1:443\n(server)"
    assert _tls_endpoint_with_role("1.1.1.1:443", "-") == "1.1.1.1:443"


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

    assert _tls_sni_for_endpoint(flow, "10.0.0.10:50000") == "api.example.com"
    assert _tls_sni_for_endpoint(flow, "203.0.113.10:443") == "-"


def test_tls_expiration_shows_only_not_after() -> None:
    certificate = TlsCertificateObservation(
        not_before="2026-01-01T00:00:00+00:00",
        not_after="2027-01-01T00:00:00+00:00",
    )

    assert _expiration(certificate) == "2027-01-01"


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

    assert _tls_issue_text(flow, "10.0.0.10:50000") == ""
    assert _tls_issue_text(flow, "203.0.113.10:443") == (
        "sent tls alert: fatal (2) close_notify (0) (x1)"
    )
    assert _tls_issue_text(flow, "10.0.0.10:50000 <-> 203.0.113.10:443") == (
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

    assert _format_tls_certificates(flow) == (
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

    assert _format_certificate_column(certificates, "subject") == (
        "Cert 1: api.example.com\n"
        "Cert 2: Example Issuing CA"
    )
    assert _format_certificate_column(certificates, "issuer") == (
        "Cert 1: Example Issuing CA\n"
        "Cert 2: Example Root CA"
    )
    assert _format_certificate_column(certificates, "expiration") == (
        "Cert 1: 2027-01-01\n"
        "Cert 2: 2030-01-01"
    )
    assert _format_certificate_column(certificates, "san") == (
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

    rows = _tls_detail_rows(summary, show_flows=1)

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

    rows = _tls_detail_rows(summary, show_flows=2)

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

    assert _direction(flow) == "pkts 5/2\nbytes 10000/500"


def test_traffic_matches_direction_label_style() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.30", protocol="TCP"),
        packet_count=7,
        byte_count=10_500,
    )

    assert _traffic(flow) == "pkts 7\nbytes 10500"
