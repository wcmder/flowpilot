from datetime import datetime, timedelta
from types import SimpleNamespace

from flowpilot.analysis import summarize_capture
from flowpilot.capture import _tshark_custom_parameters, packet_to_observation
from flowpilot.cli import _rtt
from flowpilot.filters import (
    FlowFilter,
    filter_observations,
    filter_sip_calls_by_phone,
    include_redirect_related_flows,
)
from flowpilot.models import PacketObservation, TlsCertificateObservation
from flowpilot.protocols.tls import _all_field_values, tls_alert, tls_certificates


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
            initial_rtt_seconds=0.02,
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
    assert summary.flows[0].tls_snis == ["example.com"]
    assert summary.flows[0].tls_sni_endpoints == {"10.0.0.5:54000": ["example.com"]}
    assert summary.flows[0].duration_seconds == 1.0
    assert summary.flows[0].packet_rate_per_second == 2.0
    assert summary.flows[0].byte_rate_per_second == 420.0
    assert summary.flows[0].retransmission_rate == 0.5
    assert summary.flows[0].packet_loss_rate == 0.0
    assert summary.flows[0].avg_rtt_ms == 50.0
    assert summary.flows[0].median_rtt_ms == 25.0
    assert summary.flows[0].p95_rtt_ms == 75.0
    assert summary.flows[0].rtt_max_ms == 75.0
    assert summary.flows[0].initial_rtt_ms == 20.0
    assert summary.flows[0].max_interarrival_ms == 1000.0
    assert summary.flows[0].is_one_way is False
    assert "avg_rtt_ms" not in summary.compact()["top_flows"][0]
    assert "median_rtt_ms" not in summary.compact()["top_flows"][0]
    assert "p95_rtt_ms" not in summary.compact()["top_flows"][0]
    assert "max_rtt_ms" not in summary.compact()["top_flows"][0]
    assert summary.compact()["top_flows"][0]["initial_rtt_ms"] == 20.0
    assert summary.compact()["top_flows"][0]["tls_snis"] == ["example.com"]
    assert summary.compact()["top_flows"][0]["tls_sni_endpoints"] == {
        "10.0.0.5:54000": ["example.com"]
    }
    assert summary.compact()["top_flows"][0]["packet_loss_rate"] == 0.0
    assert summary.compact()["analysis_focus"] == "network transport troubleshooting"
    assert summary.compact()["top_flows"][0]["transport"] == {
        "duration_seconds": 1.0,
        "throughput_mbps": 0.003,
        "packet_rate_per_second": 2.0,
        "retransmission_rate": 0.5,
        "packet_loss_rate": 0.0,
        "tcp_issue_counts": {"tcp_retransmission": 1},
        "rtt": {
            "initial_ms": 20.0,
            "ack_rtt_excluded": True,
        },
        "directionality": {
            "src_to_dst_packets": 1,
            "dst_to_src_packets": 1,
            "src_to_dst_bytes": 120,
            "dst_to_src_bytes": 300,
            "one_way": False,
        },
    }


def test_rtt_display_uses_median_p95_max_and_initial_rtt() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.5",
            dst_ip="93.184.216.34",
            src_port=54000,
            dst_port=443,
            protocol="TCP",
            rtt_seconds=0.0002,
            initial_rtt_seconds=0.02,
        ),
        PacketObservation(
            src_ip="93.184.216.34",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=54000,
            protocol="TCP",
            rtt_seconds=0.02,
        ),
        PacketObservation(
            src_ip="93.184.216.34",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=54000,
            protocol="TCP",
            rtt_seconds=0.0928,
        ),
    ]

    summary = summarize_capture(packets)

    assert _rtt(summary.flows[0]) == "init 20.0 ms\nack med/p95/max 20.0/92.8/92.8 ms"


def test_rtt_display_shows_init_na_when_missing() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.5",
            dst_ip="93.184.216.34",
            src_port=54000,
            dst_port=443,
            protocol="TCP",
            rtt_seconds=0.02,
        ),
    ]

    summary = summarize_capture(packets)

    assert _rtt(summary.flows[0]) == "init n/a\nack med/p95/max 20.0/20.0/20.0 ms"


def test_summarize_capture_tracks_tcp_lost_segment_rate() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.5",
            dst_ip="93.184.216.34",
            src_port=54000,
            dst_port=443,
            protocol="TCP",
            issue_tags=["tcp_lost_segment"],
        ),
        PacketObservation(
            src_ip="93.184.216.34",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=54000,
            protocol="TCP",
        ),
    ]

    summary = summarize_capture(packets)

    assert summary.flows[0].packet_loss_rate == 0.5
    assert summary.compact()["top_flows"][0]["packet_loss_rate"] == 0.5


def test_packet_to_observation_counts_presence_only_tcp_lost_segment() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.5", dst="93.184.216.34"),
        tcp=SimpleNamespace(
            srcport="54000",
            dstport="443",
            _all_fields={"tcp.analysis.lost_segment": ""},
        ),
        layers=[],
        length="100",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.issue_tags == ["tcp_lost_segment"]


def test_compact_metadata_keeps_protocol_detail_for_llm() -> None:
    answers = [f"192.0.2.{index}" for index in range(30)]
    packets = [
        PacketObservation(
            src_ip="192.0.2.53",
            dst_ip="10.0.0.10",
            src_port=53,
            dst_port=53000,
            protocol="UDP",
            dns_query="files.example.com",
            dns_response_code="0 NoError",
            dns_answers=answers,
        ),
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2read",
            smb_filename="\\\\share\\download.iso",
            smb_read_length=2_097_152,
        ),
    ]

    summary = summarize_capture(packets)
    compact = summary.compact(max_flows=2)
    compact_flows = compact["top_flows"]
    dns_flow = next(flow for flow in compact_flows if flow["protocol"] == "UDP")
    smb_flow = next(flow for flow in compact_flows if flow["protocol"] == "TCP")

    assert compact["flow_endpoint_inventory"] == {
        "endpoints": ["10.0.0.10", "10.0.0.30", "192.0.2.53"],
        "endpoint_ports": [
            "10.0.0.10:53000",
            "10.0.0.10:55000",
            "10.0.0.30:445",
            "192.0.2.53:53",
        ],
        "flow_labels": [
            "UDP 10.0.0.10:53000 <-> 192.0.2.53:53",
            "TCP 10.0.0.10:55000 <-> 10.0.0.30:445",
        ],
    }
    assert dns_flow["flow_id"] == 1
    assert dns_flow["flow_label"] == "UDP 10.0.0.10:53000 <-> 192.0.2.53:53"
    assert smb_flow["flow_id"] == 2
    assert smb_flow["flow_label"] == "TCP 10.0.0.10:55000 <-> 10.0.0.30:445"
    assert dns_flow["dns"]["answers"] == answers
    assert smb_flow["smb"]["read_bytes_by_file"] == {"\\\\share\\download.iso": 2_097_152}


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
            timestamp=datetime(2026, 1, 1, 12, 3, 1),
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
    assert summary.flows[0].throughput_mbps < 0.001
    assert "low average throughput for long-lived flow" in summary.flows[0].diagnostic_hints
    assert summary.compact()["top_flows"][0]["esp_spis"] == ["0x0000abcd"]
    assert "diagnostic_hints" in summary.compact()["top_flows"][0]


def test_summarize_capture_does_not_flag_two_minute_flow_as_long_lived() -> None:
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
        ),
    ]

    summary = summarize_capture(packets)

    assert "low average throughput for long-lived flow" not in summary.flows[0].diagnostic_hints
    assert "encrypted or datagram flow limits direct loss/latency proof" not in (
        summary.flows[0].diagnostic_hints
    )


def test_summarize_capture_does_not_flag_large_interpacket_gap() -> None:
    packets = [
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 0, 0),
            src_ip="10.0.0.5",
            dst_ip="93.184.216.34",
            src_port=54000,
            dst_port=443,
            protocol="TCP",
            length=120,
        ),
        PacketObservation(
            timestamp=datetime(2026, 1, 1, 12, 0, 10),
            src_ip="93.184.216.34",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=54000,
            protocol="TCP",
            length=120,
        ),
    ]

    summary = summarize_capture(packets)

    assert summary.flows[0].max_interarrival_ms == 10_000
    assert "large inter-packet gap observed" not in summary.flows[0].diagnostic_hints
    assert "max_interarrival_ms" not in summary.compact()["top_flows"][0]


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


def test_tshark_custom_parameters_enable_tls_reassembly_without_keylog() -> None:
    params = _tshark_custom_parameters(None)

    assert params is not None
    assert "tcp.desegment_tcp_streams:TRUE" in params
    assert "tls.desegment_ssl_records:TRUE" in params
    assert "tls.desegment_ssl_application_data:TRUE" in params


def test_tls_field_values_include_reassembled_field_objects() -> None:
    layer = SimpleNamespace(
        _all_fields={
            "tls.handshake.certificate": [
                SimpleNamespace(show="aa:bb"),
                SimpleNamespace(showname_value="cc:dd"),
            ]
        }
    )

    assert _all_field_values(layer, "handshake.certificate") == ["aa:bb", "cc:dd"]


def test_tls_field_values_include_all_pyshark_layer_field_container_values() -> None:
    from pyshark.packet.fields import LayerField, LayerFieldsContainer

    container = LayerFieldsContainer(
        LayerField(name="tls.handshake.certificate", value="aa")
    )
    container.add_field(LayerField(name="tls.handshake.certificate", value="bb"))
    container.add_field(LayerField(name="tls.handshake.certificate", value="cc"))
    layer = SimpleNamespace(_all_fields={"tls.handshake.certificate": container})

    assert _all_field_values(layer, "handshake.certificate") == ["aa", "bb", "cc"]


def test_tls_certificates_include_x509af_layer_fields() -> None:
    packet = SimpleNamespace(
        x509af=SimpleNamespace(
            _all_fields={
                "x509af.subject": "CN=server.example.com,O=Example",
                "x509af.issuer": "CN=Example Issuing CA,O=Example",
                "x509af.serialNumber": "01:02",
                "x509af.validity.notBefore": "2026-01-01",
                "x509af.validity.notAfter": "2027-01-01",
            }
        )
    )

    certificates = tls_certificates(packet)

    assert len(certificates) == 1
    assert certificates[0].subject_cn == "server.example.com"
    assert certificates[0].issuer_cn == "Example Issuing CA"


def test_tls_certificates_include_all_x509af_repeated_certificates() -> None:
    packet = SimpleNamespace(
        x509af=SimpleNamespace(
            _all_fields={
                "x509af.subject": [
                    "CN=server.example.com,O=Example",
                    "CN=Example Issuing CA,O=Example",
                    "CN=Example Root CA,O=Example",
                ],
                "x509af.issuer": [
                    "CN=Example Issuing CA,O=Example",
                    "CN=Example Root CA,O=Example",
                    "CN=Example Root CA,O=Example",
                ],
                "x509af.serialNumber": ["01", "02", "03"],
                "x509af.validity.notAfter": [
                    "2027-01-01",
                    "2028-01-01",
                    "2030-01-01",
                ],
            }
        )
    )

    certificates = tls_certificates(packet)

    assert [certificate.subject_cn for certificate in certificates] == [
        "server.example.com",
        "Example Issuing CA",
        "Example Root CA",
    ]
    assert [certificate.issuer_cn for certificate in certificates] == [
        "Example Issuing CA",
        "Example Root CA",
        "Example Root CA",
    ]
    assert [certificate.serial for certificate in certificates] == ["01", "02", "03"]


def test_tls_certificates_include_all_x509af_packet_layers() -> None:
    layers = [
        SimpleNamespace(
            _all_fields={
                "x509af.subject": "CN=server.example.com,O=Example",
                "x509af.issuer": "CN=Example Issuing CA,O=Example",
                "x509af.serialNumber": "01",
            }
        ),
        SimpleNamespace(
            _all_fields={
                "x509af.subject": "CN=Example Issuing CA,O=Example",
                "x509af.issuer": "CN=Example Root CA,O=Example",
                "x509af.serialNumber": "02",
            }
        ),
        SimpleNamespace(
            _all_fields={
                "x509af.subject": "CN=Example Root CA,O=Example",
                "x509af.issuer": "CN=Example Root CA,O=Example",
                "x509af.serialNumber": "03",
            }
        ),
    ]

    class PacketWithLayers:
        def get_multiple_layers(self, layer_name: str):
            return layers if layer_name == "x509af" else []

    certificates = tls_certificates(PacketWithLayers())

    assert [certificate.subject_cn for certificate in certificates] == [
        "server.example.com",
        "Example Issuing CA",
        "Example Root CA",
    ]


def test_tls_alert_reads_level_and_description() -> None:
    packet = SimpleNamespace(
        tls=SimpleNamespace(
            alert_message_level="Fatal (2)",
            alert_message_desc="Certificate Unknown (46)",
        )
    )

    assert tls_alert(packet) == ("Fatal (2)", "Certificate Unknown (46)")


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


def test_summarize_capture_tracks_tls_alerts_for_llm_metadata() -> None:
    packets = [
        PacketObservation(
            src_ip="198.51.100.20",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=50000,
            protocol="TCP",
            tls_alert_level="Fatal (2)",
            tls_alert_description="Close Notify (0)",
            issue_tags=["tls_alert", "tls_fatal_alert"],
        )
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.tls_alerts == {"fatal (2) close_notify (0)": 1}
    assert flow.tls_alert_endpoints == {
        "198.51.100.20:443": {"fatal (2) close_notify (0)": 1}
    }
    assert flow.issue_counts == {"tls_alert": 1, "tls_fatal_alert": 1}
    assert "tls fatal alert observed" in flow.diagnostic_hints
    assert summary.compact()["top_flows"][0]["tls_alerts"] == {
        "fatal (2) close_notify (0)": 1
    }
    assert summary.compact()["top_flows"][0]["tls_alert_endpoints"] == {
        "198.51.100.20:443": {"fatal (2) close_notify (0)": 1}
    }


def test_summarize_capture_translates_numeric_tls_alert_codes() -> None:
    packets = [
        PacketObservation(
            src_ip="198.51.100.20",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=50000,
            protocol="TCP",
            tls_alert_level="2",
            tls_alert_description="40",
            issue_tags=["tls_alert", "tls_fatal_alert"],
        )
    ]

    summary = summarize_capture(packets)

    assert summary.flows[0].tls_alerts == {"fatal (2) handshake_failure (40)": 1}


def test_summarize_capture_sends_all_tls_certificates_to_compact_metadata() -> None:
    certificates = [
        TlsCertificateObservation(
            presenter_ip="198.51.100.20",
            presenter_port=443,
            subject=f"CN=cert-{index}.example.com",
            serial=str(index),
        )
        for index in range(12)
    ]
    packets = [
        PacketObservation(
            src_ip="198.51.100.20",
            dst_ip="10.0.0.5",
            src_port=443,
            dst_port=50000,
            protocol="TCP",
            tls_certificates=certificates,
        )
    ]

    summary = summarize_capture(packets)
    compact_certificates = summary.compact()["top_flows"][0]["tls_certificates"]

    assert len(summary.flows[0].tls_certificates) == 12
    assert len(compact_certificates) == 12
    assert compact_certificates[-1]["subject"] == "CN=cert-11.example.com"


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


def test_summarize_capture_maps_smb_transfer_filename_from_file_id() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="Create",
            smb_status="0",
            smb_file_id="0xabc",
            smb_filename="\\\\share\\upload.bin",
            smb_create_desired_access=0x00000002,
            smb_create_file_attributes=0x00000020,
        ),
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="11",
            smb_status="0",
            smb_file_id="0xabc",
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
            smb_file_id="0xabc",
            smb_file_offset=4096,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_write_filenames == ["\\\\share\\upload.bin"]
    assert flow.smb_write_ops == 2
    assert flow.smb_write_bytes == 4096
    assert flow.smb_write_offset_inferred_ops == 1
    assert flow.smb_write_unknown_bytes_ops == 1


def test_summarize_capture_maps_smb2_create_response_file_id_to_filename() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2create",
            smb_status="0",
            smb_message_id="42",
            smb_filename="\\\\share\\upload.bin",
            smb_create_desired_access=0x00000002,
            smb_create_file_attributes=0x00000020,
        ),
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="SMB2create",
            smb_status="0",
            smb_message_id="42",
            smb_file_id="0xabc",
        ),
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2write",
            smb_status="0",
            smb_file_id="0xabc",
            smb_write_length=4096,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_write_filenames == ["\\\\share\\upload.bin"]
    assert flow.smb_write_ops == 1
    assert flow.smb_write_bytes == 4096


def test_summarize_capture_does_not_map_read_intent_create_as_upload() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2create",
            smb_status="0",
            smb_message_id="42",
            smb_filename="\\\\share\\opened-for-read.txt",
            smb_create_desired_access=0x00000001,
            smb_create_file_attributes=0x00000020,
        ),
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="SMB2create",
            smb_status="0",
            smb_message_id="42",
            smb_file_id="0xabc",
        ),
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2write",
            smb_status="0",
            smb_file_id="0xabc",
            smb_write_length=2_097_152,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_write_bytes == 2_097_152
    assert flow.smb_write_bytes_by_file == {}


def test_summarize_capture_does_not_map_directory_create_as_download() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2create",
            smb_status="0",
            smb_message_id="42",
            smb_filename="\\\\share\\folder",
            smb_create_desired_access=0x00000001,
            smb_create_file_attributes=0x00000010,
        ),
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="SMB2create",
            smb_status="0",
            smb_message_id="42",
            smb_file_id="0xabc",
        ),
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="SMB2read",
            smb_status="0",
            smb_file_id="0xabc",
            smb_read_length=2_097_152,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_read_bytes == 2_097_152
    assert flow.smb_read_bytes_by_file == {}


def test_summarize_capture_counts_all_smb_commands_seen() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_commands_seen=["SMB2create", "SMB2write"],
            smb_write_length=4096,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_commands == {"SMB2create": 1, "SMB2write": 1}
    assert flow.smb_write_ops == 1
    assert flow.smb_write_bytes == 4096


def test_summarize_capture_does_not_mark_create_filename_as_download() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_commands_seen=["SMB2create", "SMB2read"],
            smb_filename="\\\\share\\opened-not-downloaded.txt",
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_commands == {"SMB2create": 1, "SMB2read": 1}
    assert flow.smb_read_ops == 0
    assert flow.smb_read_filenames == []


def test_summarize_capture_counts_multi_command_read_without_create_filename() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_commands_seen=["SMB2create", "SMB2read"],
            smb_filename="\\\\share\\opened-not-downloaded.txt",
            smb_read_length=4096,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_read_ops == 1
    assert flow.smb_read_bytes == 4096
    assert flow.smb_read_filenames == []


def test_summarize_capture_does_not_list_unknown_length_read_filename() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2read",
            smb_filename="\\\\share\\opened-not-downloaded.txt",
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_read_ops == 1
    assert flow.smb_read_unknown_bytes_ops == 1
    assert flow.smb_read_filenames == []


def test_summarize_capture_does_not_count_error_read_response_as_unknown_length() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="SMB2read",
            smb_status="STATUS_END_OF_FILE",
            smb_is_response=True,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_read_ops == 0
    assert flow.smb_read_bytes == 0
    assert flow.smb_read_unknown_bytes_ops == 0
    assert flow.smb_error_count == 1


def test_summarize_capture_does_not_count_success_response_as_operation() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_command="SMB2read",
            smb_status="0",
            smb_message_id="42",
            smb_is_response=False,
            smb_read_length=4096,
        ),
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="SMB2read",
            smb_status="0",
            smb_message_id="42",
            smb_is_response=True,
            smb_read_length=4096,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_read_ops == 1
    assert flow.smb_read_unknown_bytes_ops == 0


def test_summarize_capture_counts_visible_success_response_as_operation() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_command="SMB2read",
            smb_status="0",
            smb_message_id="42",
            smb_is_response=True,
            smb_read_length=4096,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_read_ops == 1
    assert flow.smb_read_bytes == 4096
    assert flow.smb_read_unknown_bytes_ops == 0


def test_packet_to_observation_reads_smb2_write_fields() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(
            cmd="9",
            msg_id="42",
            file_id="0xabc",
            offset="8192",
            write_length="4096",
            data_length="4096",
        ),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_command == "SMB2write"
    assert observation.smb_message_id == "42"
    assert observation.smb_file_id == "0xabc"
    assert observation.smb_file_offset == 8192
    assert observation.smb_write_length == 4096


def test_packet_to_observation_reads_smb2_create_intent_fields() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(
            _all_fields={
                "smb2.cmd": "5",
                "smb2.filename": "\\\\share\\download.bin",
                "smb2.create.desired_access": "0x00000001",
                "smb2.create.file_attributes": "0x00000020",
            }
        ),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_command == "SMB2create"
    assert observation.smb_filename == "\\\\share\\download.bin"
    assert observation.smb_create_desired_access == 0x00000001
    assert observation.smb_create_file_attributes == 0x00000020


def test_packet_to_observation_maps_smb2_ioctl_command() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(cmd="11", msg_id="43"),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="256",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_command == "SMB2ioctl"


def test_packet_to_observation_reads_smb2_command_from_all_fields() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(_all_fields={"smb2.cmd": "9", "smb2.msg_id": "44"}),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="256",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_command == "SMB2write"
    assert observation.smb_commands_seen == ["SMB2write"]
    assert observation.smb_message_id == "44"


def test_packet_to_observation_reads_multiple_smb2_commands_from_all_fields() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(
            _all_fields={
                "smb2.cmd": ["5", "9", "11"],
                "smb2.write.length": "4096",
            }
        ),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_command == "SMB2create"
    assert observation.smb_commands_seen == ["SMB2create", "SMB2write", "SMB2ioctl"]
    assert observation.smb_write_length == 4096


def test_packet_to_observation_detects_smb_encrypted_transform() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(_all_fields={"smb2.transform.session_id": "0x1234"}),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="1024",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_encrypted is True


def test_packet_to_observation_does_not_mark_encryption_capability_as_encrypted_payload() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(_all_fields={"smb2.capabilities.encryption": "1"}),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_encrypted is False
    assert "encryption" in observation.smb_capabilities


def test_packet_to_observation_does_not_mark_generic_encrypted_flag_as_transform() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(_all_fields={"smb2.flags.encrypted": "1"}),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_encrypted is False


def test_packet_to_observation_reads_smb2_encryption_capabilities() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="55000", dstport="445"),
        smb2=SimpleNamespace(
            _all_fields={
                "smb2.negotiate_context.type": "SMB2_ENCRYPTION_CAPABILITIES",
                "smb2.encryption_capabilities.cipher": "AES-128-GCM",
            }
        ),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert "encryption" in observation.smb_capabilities


def test_packet_to_observation_reads_smb2_dotted_encryption_capability() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="445", dstport="55000"),
        smb2=SimpleNamespace(_all_fields={"smb2.capabilities.encryption": "1"}),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert "encryption" in observation.smb_capabilities


def test_packet_to_observation_expands_smb2_capability_mask() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="445", dstport="55000"),
        smb2=SimpleNamespace(_all_fields={"smb2.capabilities": "0x0017"}),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_capabilities == [
        "DFS",
        "leasing",
        "large MTU",
        "persistent handles",
    ]


def test_packet_to_observation_expands_full_smb3_capability_mask() -> None:
    packet = SimpleNamespace(
        ip=SimpleNamespace(src="10.0.0.10", dst="10.0.0.30"),
        tcp=SimpleNamespace(srcport="445", dstport="55000"),
        smb2=SimpleNamespace(_all_fields={"smb2.capabilities": "0x007f"}),
        layers=[
            SimpleNamespace(layer_name="ip"),
            SimpleNamespace(layer_name="tcp"),
            SimpleNamespace(layer_name="smb2"),
        ],
        length="512",
    )

    observation = packet_to_observation(packet)

    assert observation is not None
    assert observation.smb_capabilities == [
        "DFS",
        "leasing",
        "large MTU",
        "multi-channel",
        "persistent handles",
        "directory leasing",
        "encryption",
    ]


def test_summarize_capture_reports_smb_encryption_capability_on_both_sides() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_capabilities=["encryption"],
        ),
        PacketObservation(
            src_ip="10.0.0.30",
            dst_ip="10.0.0.10",
            src_port=445,
            dst_port=55000,
            protocol="TCP",
            smb_capabilities=["encryption"],
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_client_capabilities == ["encryption"]
    assert flow.smb_server_capabilities == ["encryption"]


def test_summarize_capture_reports_smb_encrypted_visibility_limit() -> None:
    packets = [
        PacketObservation(
            src_ip="10.0.0.10",
            dst_ip="10.0.0.30",
            src_port=55000,
            dst_port=445,
            protocol="TCP",
            smb_encrypted=True,
        ),
    ]

    summary = summarize_capture(packets)
    flow = summary.flows[0]

    assert flow.smb_encrypted_packets == 1
    assert flow.smb_read_ops == 0
    assert flow.smb_write_ops == 0
    assert (
        "smb encrypted transform traffic observed; filenames and read/write details are hidden"
        in flow.smb_diagnostic_hints
    )
    assert summary.compact()["top_flows"][0]["smb"]["encrypted_packets"] == 1


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

    assert summary.flow_count == 1
    assert flow.key.port_a == 67
    assert flow.key.port_b == 68
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
