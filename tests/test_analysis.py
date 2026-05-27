from datetime import datetime, timedelta

from flowpilot.analysis import summarize_capture
from flowpilot.capture import _tshark_custom_parameters
from flowpilot.filters import (
    FlowFilter,
    filter_observations,
    filter_sip_calls_by_phone,
    include_redirect_related_flows,
)
from flowpilot.models import PacketObservation, TlsCertificateObservation


def test_summarize_capture_groups_bidirectional_flow() -> None:
    start = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        PacketObservation(
            timestamp=start,
            src_ip="10.0.0.5",
            dst_ip="93.184.216.34",
            src_port=54000,
            dst_port=443,
            protocol="TCP",
            length=120,
            rtt_seconds=0.025,
            issue_tags=["tcp_retransmission"],
            tls_sni="example.com",
        ),
        PacketObservation(
            timestamp=start + timedelta(seconds=1),
            src_ip="93.184.216.34",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=54000,
            protocol="TCP",
            length=300,
            rtt_seconds=0.075,
        ),
    ]

    summary = summarize_capture(packets)

    assert summary.packet_count == 2
    assert summary.total_bytes == 420
    assert summary.flow_count == 1
    assert summary.protocols == {"TCP": 2}
    assert summary.top_ports["443"] == 2
    assert summary.issue_counts == {"tcp_retransmission": 1}
    assert summary.names == ["example.com"]
    assert summary.flows[0].packet_count == 2
    assert summary.flows[0].issue_counts == {"tcp_retransmission": 1}
    assert summary.flows[0].duration_seconds == 1.0
    assert summary.flows[0].packet_rate_per_second == 2.0
    assert summary.flows[0].byte_rate_per_second == 420.0
    assert summary.flows[0].retransmission_rate == 0.5
    assert summary.flows[0].avg_rtt_ms == 50.0
    assert summary.flows[0].rtt_max_ms == 75.0
    assert summary.flows[0].max_interarrival_ms == 1000.0
    assert summary.flows[0].is_one_way is False
    assert summary.compact()["top_flows"][0]["avg_rtt_ms"] == 50.0


def test_summarize_capture_tracks_esp_spi_without_ports() -> None:
    packets = [
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            protocol="ESP",
            length=900,
            esp_spi="0x0000abcd",
        ),
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 2, 0),
            src_ip="198.51.100.20",
            dst_ip="192.0.2.10",
            protocol="ESP",
            length=900,
            esp_spi="0x0000abcd",
        )
    ]

    summary = summarize_capture(packets)

    assert summary.protocols == {"ESP": 2}
    assert summary.top_ports == {}
    assert summary.flows[0].esp_spis == ["0x0000abcd"]
    assert summary.flows[0].is_one_way is False
    assert summary.flows[0].throughput_mbps == 0.00012
    assert "low average throughput for long-lived flow" in summary.flows[0].diagnostic_hints
    assert summary.compact()["top_flows"][0]["esp_spis"] == ["0x0000abcd"]
    assert "diagnostic_hints" in summary.compact()["top_flows"][0]


def test_summarize_capture_tracks_esp_sequence_anomalies() -> None:
    start = datetime(2026, 1, 1, 12, 0, 0)
    packets = [
        PacketObservation(
            timestamp=start,
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            protocol="ESP",
            length=900,
            esp_spi="0x0000abcd",
            esp_sequence=1,
        ),
        PacketObservation(
            timestamp=start + timedelta(seconds=1),
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            protocol="ESP",
            length=900,
            esp_spi="0x0000abcd",
            esp_sequence=3,
        ),
        PacketObservation(
            timestamp=start + timedelta(seconds=2),
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            protocol="ESP",
            length=900,
            esp_spi="0x0000abcd",
            esp_sequence=2,
        ),
        PacketObservation(
            timestamp=start + timedelta(seconds=3),
            src_ip="192.0.2.10",
            dst_ip="198.51.100.20",
            protocol="ESP",
            length=900,
            esp_spi="0x0000abcd",
            esp_sequence=2,
        ),
    ]

    summary = summarize_capture(packets)
    sequence = summary.flows[0].esp_sequences[0]
    compact_sequence = summary.compact()["top_flows"][0]["esp_sequences"][0]

    assert sequence.first_sequence == 1
    assert sequence.last_sequence == 2
    assert sequence.highest_sequence == 3
    assert sequence.missing_count == 0
    assert sequence.largest_sequence_gap == 1
    assert sequence.gap_occurrences == [
        {"after_sequence": 1, "next_sequence": 3, "gap": 1, "missing": 1}
    ]
    assert sequence.out_of_order_count == 1
    assert sequence.duplicate_count == 1
    assert "esp sequence anomaly observed" in summary.flows[0].diagnostic_hints
    assert compact_sequence["largest_sequence_gap"] == 1
    assert compact_sequence["gap_occurrences"] == [
        {"after_sequence": 1, "next_sequence": 3, "gap": 1, "missing": 1}
    ]
    assert compact_sequence["out_of_order_count"] == 1
    assert compact_sequence["duplicate_count"] == 1


def test_filter_observations_isolates_host_peer_protocol_and_port() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.5",
            dst_ip="198.51.100.20",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
        ),
        PacketObservation(
            src_ip="10.0.0.5",
            dst_ip="203.0.113.10",
            src_port=50001,
            dst_port=443,
            protocol="TCP",
        ),
        PacketObservation(
            src_ip="10.0.0.5",
            dst_ip="198.51.100.20",
            src_port=50002,
            dst_port=53,
            protocol="UDP",
        ),
    ]

    filtered = list(
        filter_observations(
            packets,
            FlowFilter(
                host="10.0.0.5",
                peer="198.51.100.20",
                protocol="tcp",
                port=443,
            ),
        )
    )

    assert len(filtered) == 1
    assert filtered[0].dst_ip == "198.51.100.20"
    assert filtered[0].dst_port == 443


def test_filter_sip_calls_by_phone_keeps_matching_call_trace() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=5060,
            dst_port=5060,
            protocol="UDP",
            sip_call_id="call-123",
            sip_method="INVITE",
            sip_from="sip:+1-555-0100@example.com",
            sip_to="sip:15550101@example.com",
        ),
        PacketObservation(
            src_ip="10.0.0.20",
            dst_ip="10.0.0.10",
            src_port=5060,
            dst_port=5060,
            protocol="UDP",
            sip_call_id="call-123",
            sip_status_code=486,
            sip_reason="Busy Here",
        ),
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.10",
            src_port=5060,
            dst_port=5060,
            protocol="UDP",
            sip_call_id="call-456",
            sip_method="INVITE",
            sip_from="sip:15550102@example.com",
            sip_to="sip:15550103@example.com",
        ),
    ]

    filtered = filter_sip_calls_by_phone(packets, "0100")

    assert [packet.sip_call_id for packet in filtered] == ["call-123", "call-123"]


def test_filter_sip_calls_by_phone_matches_partial_digits_inside_uri() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=5060,
            dst_port=5060,
            protocol="UDP",
            sip_call_id="call-789",
            sip_method="INVITE",
            sip_from="sip:14152799913@something",
            sip_to="sip:15550101@example.com",
        )
    ]

    filtered = filter_sip_calls_by_phone(packets, "2799913")

    assert [packet.sip_call_id for packet in filtered] == ["call-789"]


def test_tshark_custom_parameters_include_tls_keylog(tmp_path) -> None:
    keylog_file = tmp_path / "sslkeys.log"
    keylog_file.write_text("CLIENT_RANDOM placeholder placeholder\n", encoding="utf-8")

    params = _tshark_custom_parameters(keylog_file)

    assert params is not None
    assert f"tls.keylog_file:{keylog_file}" in params
    assert "tcp.desegment_tcp_streams:TRUE" in params


def test_include_redirect_related_flows_adds_redirect_target_flow() -> None:
    seed = PacketObservation(
        src_ip="10.0.0.5",
        dst_ip="198.51.100.20",
        src_port=50000,
        dst_port=443,
        protocol="TCP",
        http_location="https://cdn.example.net/file.bin",
    )
    dns = PacketObservation(
        src_ip="10.0.0.5",
        dst_ip="192.0.2.53",
        src_port=53000,
        dst_port=53,
        protocol="UDP",
        dns_query="cdn.example.net",
        dns_answers=["203.0.113.44"],
    )
    redirected = PacketObservation(
        src_ip="10.0.0.5",
        dst_ip="203.0.113.44",
        src_port=50001,
        dst_port=443,
        protocol="TCP",
        tls_sni="cdn.example.net",
    )
    unrelated = PacketObservation(
        src_ip="10.0.0.5",
        dst_ip="203.0.113.99",
        src_port=50002,
        dst_port=443,
        protocol="TCP",
    )

    expanded = include_redirect_related_flows(
        [seed, dns, redirected, unrelated],
        [seed],
    )

    assert expanded == [seed, dns, redirected]


def test_summarize_capture_tracks_tls_certificates() -> None:
    certificate = TlsCertificateObservation(
        presenter_ip="198.51.100.20",
        presenter_port=443,
        subject="CN=api.example.com",
        subject_cn="api.example.com",
        issuer="CN=Example Intermediate CA",
        issuer_cn="Example Intermediate CA",
        serial="01:02:03",
        not_before="2026-01-01",
        not_after="2027-01-01",
        san_dns=["api.example.com"],
        fingerprint_sha256="abc123",
    )
    packets = [
        PacketObservation(
            src_ip="198.51.100.20",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=50000,
            protocol="TCP",
            tls_certificates=[certificate],
        )
    ]

    summary = summarize_capture(packets)

    assert summary.flows[0].tls_certificates[0].presenter_role == "server"
    assert summary.flows[0].tls_certificates[0].subject == certificate.subject
    assert summary.compact()["top_flows"][0]["tls_certificates"][0]["subject"] == (
        "CN=api.example.com"
    )
    assert summary.compact()["top_flows"][0]["tls_certificates"][0]["presenter_ip"] == (
        "198.51.100.20"
    )
    assert summary.compact()["top_flows"][0]["tls_certificates"][0]["issuer_cn"] == (
        "Example Intermediate CA"
    )


def test_summarize_capture_marks_second_cert_presenter_as_client() -> None:
    server_certificate = TlsCertificateObservation(
        presenter_ip="198.51.100.20",
        presenter_port=443,
        subject_cn="server.example.com",
        issuer_cn="Example CA",
        serial="01",
    )
    client_certificate = TlsCertificateObservation(
        presenter_ip="10.0.0.5",
        presenter_port=50000,
        subject_cn="client.example.com",
        issuer_cn="Example CA",
        serial="02",
    )
    packets = [
        PacketObservation(
            src_ip="198.51.100.20",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=50000,
            protocol="TCP",
            tls_certificates=[server_certificate],
        ),
        PacketObservation(
            src_ip="10.0.0.5",
            dst_ip="198.51.100.20",
            src_port=50000,
            dst_port=443,
            protocol="TCP",
            tls_certificates=[client_certificate],
        ),
    ]

    summary = summarize_capture(packets)

    assert [cert.presenter_role for cert in summary.flows[0].tls_certificates] == [
        "server",
        "client",
    ]


def test_summarize_capture_tracks_sip_call_metadata() -> None:
    packets = [
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=5060,
            dst_port=5060,
            protocol="UDP",
            sip_call_id="call-123",
            sip_method="INVITE",
            sip_from="sip:alice@example.com",
            sip_to="sip:bob@example.com",
        ),
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 0, 1),
            src_ip="10.0.0.20",
            dst_ip="10.0.0.10",
            src_port=5060,
            dst_port=5060,
            protocol="UDP",
            sip_call_id="call-123",
            sip_status_code=486,
            sip_reason="Busy Here",
        ),
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.20",
            src_port=5060,
            dst_port=5060,
            protocol="UDP",
            sip_call_id="call-456",
            sip_method="INVITE",
            sip_from="sip:carol@example.com",
            sip_to="sip:dave@example.com",
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.sip_call_ids == ["call-123", "call-456"]
    assert flow.sip_methods == {"INVITE": 2}
    assert flow.sip_statuses == {"486 Busy Here": 1}
    assert flow.sip_participants == [
        "sip:alice@example.com",
        "sip:bob@example.com",
        "sip:carol@example.com",
        "sip:dave@example.com",
    ]
    assert flow.sip_calls["call-123"].caller == "sip:alice@example.com"
    assert flow.sip_calls["call-123"].callee == "sip:bob@example.com"
    assert flow.sip_calls["call-123"].statuses == {"486 Busy Here": 1}
    assert flow.sip_calls["call-123"].issues == ["client failure response"]
    assert flow.sip_calls["call-123"].trace == [
        {
            "time": "2026-01-01T12:00:00",
            "from_endpoint": "10.0.0.10:5060",
            "to_endpoint": "10.0.0.20:5060",
            "message": "INVITE",
        },
        {
            "time": "2026-01-01T12:00:01",
            "from_endpoint": "10.0.0.20:5060",
            "to_endpoint": "10.0.0.10:5060",
            "message": "486 Busy Here",
        },
    ]
    assert flow.sip_calls["call-456"].caller == "sip:carol@example.com"
    assert flow.sip_calls["call-456"].callee == "sip:dave@example.com"
    assert summary.compact()["top_flows"][0]["sip"]["statuses"] == {"486 Busy Here": 1}
    assert summary.compact()["top_flows"][0]["sip"]["calls"][0]["caller"] == (
        "sip:alice@example.com"
    )
    assert summary.compact()["top_flows"][0]["sip"]["calls"][0]["issues"] == [
        "client failure response"
    ]


def test_summarize_capture_tracks_smb_metadata() -> None:
    packets = [
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="Create",
            smb_status="STATUS_ACCESS_DENIED",
            smb_session_id="0x111",
            smb_tree_id="0x222",
            smb_filename="\\\\share\\blocked.docx",
            smb_capabilities=["dialect=0x0311", "signing enabled"],
        ),
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 2, 0),
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="Read",
            smb_status="STATUS_SUCCESS",
            smb_read_length=32768,
            smb_filename="\\\\share\\slow.bin",
            smb_capabilities=["multi-channel"],
        )
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_commands == {"Create": 1, "Read": 1}
    assert flow.smb_statuses == {"STATUS_ACCESS_DENIED": 1, "STATUS_SUCCESS": 1}
    assert flow.smb_read_ops == 1
    assert flow.smb_read_bytes == 32768
    assert flow.smb_read_unknown_bytes_ops == 0
    assert flow.smb_error_count == 1
    assert "smb errors observed" in flow.smb_diagnostic_hints
    assert "small average smb read/write size" in flow.smb_diagnostic_hints
    assert flow.smb_session_ids == ["0x111"]
    assert flow.smb_tree_ids == ["0x222"]
    assert flow.smb_filenames == ["\\\\share\\blocked.docx", "\\\\share\\slow.bin"]
    assert flow.smb_read_filenames == ["\\\\share\\slow.bin"]
    assert flow.smb_write_filenames == []
    assert flow.smb_client_capabilities == ["dialect=0x0311", "signing enabled"]
    assert flow.smb_server_capabilities == ["multi-channel"]
    assert summary.compact()["top_flows"][0]["smb"]["statuses"] == {
        "STATUS_ACCESS_DENIED": 1,
        "STATUS_SUCCESS": 1,
    }
    assert summary.compact()["top_flows"][0]["smb"]["transfer_bytes"] == 32768


def test_summarize_capture_counts_numeric_smb_write_command() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="11",
            smb_status="0",
            smb_write_length=4096,
            smb_filename="\\\\share\\upload.bin",
        )
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_commands == {"11": 1}
    assert flow.smb_write_ops == 1
    assert flow.smb_write_bytes == 4096
    assert flow.smb_write_unknown_bytes_ops == 0
    assert flow.smb_write_filenames == ["\\\\share\\upload.bin"]


def test_summarize_capture_tracks_smb_write_unknown_length() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="11",
            smb_status="0",
        )
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_write_ops == 1
    assert flow.smb_write_bytes == 0
    assert flow.smb_write_unknown_bytes_ops == 1


def test_summarize_capture_infers_smb_write_bytes_from_offsets() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="11",
            smb_status="0",
            smb_filename="\\\\share\\upload.bin",
            smb_file_offset=0,
        ),
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="11",
            smb_status="0",
            smb_filename="\\\\share\\upload.bin",
            smb_file_offset=4096,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_write_ops == 2
    assert flow.smb_write_bytes == 4096
    assert flow.smb_write_offset_inferred_ops == 1
    assert flow.smb_write_unknown_bytes_ops == 1


def test_summarize_capture_tracks_dns_metadata() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="192.0.2.53",
            src_port=53000,
            dst_port=53,
            protocol="UDP",
            dns_query="missing.example",
            dns_query_type="A",
            dns_response_code="3 NXDOMAIN",
        ),
        PacketObservation(
            src_ip="192.0.2.53",
            dst_ip="10.0.0.10",
            src_port=53,
            dst_port=53000,
            protocol="UDP",
            dns_query="www.example",
            dns_query_type="AAAA",
            dns_response_code="0 NoError",
            dns_answers=["2001:db8::10"],
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.dns_queries == {"missing.example": 1, "www.example": 1}
    assert flow.dns_query_types == {"A": 1, "AAAA": 1}
    assert flow.dns_response_codes == {"3 NXDOMAIN": 1, "0 NoError": 1}
    assert flow.dns_answers == ["2001:db8::10"]
    assert flow.dns_error_count == 1
    assert "dns error responses observed" in flow.diagnostic_hints
    assert summary.compact()["top_flows"][0]["dns"]["error_count"] == 1


def test_summarize_capture_tracks_dhcp_metadata() -> None:
    packets = [
        PacketObservation(
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            src_port=68,
            dst_port=67,
            protocol="UDP",
            dhcp_message_type="Discover",
            dhcp_transaction_id="0x1234",
            dhcp_client_mac="00:11:22:33:44:55",
            dhcp_hostname="laptop-1",
            dhcp_requested_ip="10.0.0.50",
        ),
        PacketObservation(
            src_ip="0.0.0.0",
            dst_ip="255.255.255.255",
            src_port=67,
            dst_port=68,
            protocol="UDP",
            dhcp_message_type="Offer",
            dhcp_transaction_id="0x1234",
            dhcp_your_ip="10.0.0.51",
            dhcp_server_id="10.0.0.1",
            dhcp_lease_time="3600",
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.dhcp_message_types == {"Discover": 1, "Offer": 1}
    assert flow.dhcp_transaction_ids == ["0x1234"]
    assert flow.dhcp_client_macs == ["00:11:22:33:44:55"]
    assert flow.dhcp_hostnames == ["laptop-1"]
    assert flow.dhcp_requested_ips == ["10.0.0.50"]
    assert flow.dhcp_offered_ips == ["10.0.0.51"]
    assert flow.dhcp_server_ids == ["10.0.0.1"]
    assert flow.dhcp_lease_times == ["3600"]
    assert "dhcp exchange lacks ack in observed packets" in flow.diagnostic_hints
    assert summary.compact()["top_flows"][0]["dhcp"]["offered_ips"] == ["10.0.0.51"]
