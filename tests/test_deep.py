from flowpilot.decode_as import set_esp_udp_ports
from flowpilot.models import FlowKey, FlowSummary
from flowpilot.protocols.deep_common import (
    endpoint_filter_for_flow,
    field_command,
    parse_field_rows,
    tshark_path,
)
from flowpilot.protocols.esp import (
    ESP_DEEP_FIELDS,
    esp_deep_fields_for_tshark,
    esp_direction_stats,
    esp_metadata_counts,
    parse_esp_rows,
)
from flowpilot.protocols.esp import (
    _parse_tshark_field_names as parse_esp_tshark_field_names,
)
from flowpilot.protocols.smb import (
    SMB2_CREDIT_CHARGE_FIELD,
    SMB2_CREDIT_REQUEST_RESPONSE_FIELD,
    SMB2_DEEP_FIELDS,
    _parse_tshark_field_names,
    smb2_credit_counts,
    smb2_deep_fields_for_tshark,
)
from flowpilot.protocols.tcp import (
    TCP_HEADER_FIELDS,
    parse_tcp_rows,
    tcp_analysis_counts,
    tcp_deep_fields_for_tshark,
    tcp_window_stats,
)
from flowpilot.protocols.tcp import (
    _parse_tshark_field_names as parse_tcp_tshark_field_names,
)
from flowpilot.protocols.tls import TLS_DEEP_FIELDS, tls_flow_filter, tls_metadata_counts
from flowpilot.protocols.udp import UDP_HEADER_FIELDS, udp_metadata_counts


def test_parse_tshark_rows_includes_tcp_headers_and_analysis_markers() -> None:
    values = {field: "" for field in TCP_HEADER_FIELDS}
    values.update(
        {
            "frame.number": "10",
            "frame.time_relative": "1.0",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "tcp.srcport": "12345",
            "tcp.dstport": "443",
            "tcp.seq": "100",
            "tcp.ack": "200",
            "tcp.len": "1460",
            "tcp.window_size_value": "65535",
            "tcp.window_size": "65535",
            "tcp.flags": "0x0018",
            "tcp.options.mss_val": "1460",
            "tcp.analysis.retransmission": "1",
            "tcp.analysis.window_full": "1",
            "tcp.analysis.bytes_in_flight": "32768",
        }
    )
    output = "\t".join(values[field] for field in TCP_HEADER_FIELDS)

    rows = parse_tcp_rows(output)

    assert rows[0]["frame.number"] == "10"
    assert rows[0]["src"] == "10.0.0.1"
    assert rows[0]["dst"] == "10.0.0.2"
    assert rows[0]["tcp.seq"] == "100"
    assert rows[0]["tcp.ack"] == "200"
    assert rows[0]["tcp.len"] == "1460"
    assert rows[0]["tcp.window_size_value"] == "65535"
    assert rows[0]["tcp.flags"] == "0x0018"
    assert rows[0]["tcp.analysis.retransmission"] == "1"


def test_field_command_includes_configured_esp_udp_decode_as(tmp_path) -> None:
    try:
        set_esp_udp_ports([12346])

        command = field_command(
            "tshark",
            tmp_path / "capture.pcap",
            "esp",
            ["frame.number"],
        )

        assert command[:5] == [
            "tshark",
            "-d",
            "udp.port==12346,udpencap",
            "-r",
            str(tmp_path / "capture.pcap"),
        ]
    finally:
        set_esp_udp_ports(None)


def test_tshark_path_uses_configured_env_path(tmp_path, monkeypatch) -> None:
    configured_tshark = tmp_path / "tshark.exe"
    configured_tshark.write_text("", encoding="utf-8")
    monkeypatch.setenv("FLOWPILOT_TSHARK_PATH", str(configured_tshark))

    assert tshark_path() == str(configured_tshark)


def test_tcp_analysis_counts_counts_presence_markers() -> None:
    rows = [
        {"tcp.analysis.lost_segment": "1"},
        {"tcp.analysis.lost_segment": "", "tcp.analysis.retransmission": "1"},
        {"tcp.analysis.lost_segment": "0"},
        {
            "tcp.analysis.window_full": "1",
            "tcp.analysis.window_update": "1",
            "tcp.analysis.zero_window_probe": "1",
            "tcp.options.mss.exceeded": "1",
        },
    ]

    assert tcp_analysis_counts(rows) == {
        "tcp.analysis.lost_segment": 1,
        "tcp.analysis.retransmission": 1,
        "tcp.analysis.zero_window_probe": 1,
        "tcp.analysis.window_update": 1,
        "tcp.analysis.window_full": 1,
        "tcp.options.mss.exceeded": 1,
    }


def test_tcp_window_stats_summarizes_window_pressure_values() -> None:
    rows = [
        {
            "tcp.window_size": "65536",
            "tcp.window_size_value": "1024",
            "tcp.window_size_scalefactor": "64",
            "tcp.analysis.bytes_in_flight": "32768",
            "tcp.options.mss_val": "1460",
        },
        {
            "tcp.window_size": "131072",
            "tcp.window_size_value": "2048",
            "tcp.window_size_scalefactor": "64",
            "tcp.analysis.bytes_in_flight": "262144",
            "tcp.options.mss_val": "1380",
        },
    ]

    assert tcp_window_stats(rows) == {
        "advertised_window_min": 65536,
        "advertised_window_max": 131072,
        "raw_advertised_window_min": 1024,
        "raw_advertised_window_max": 2048,
        "bytes_in_flight_max": 262144,
        "window_scale_factors": [64],
        "mss_values": [1380, 1460],
        "mss_min": 1380,
        "mss_max": 1460,
    }


def test_tcp_deep_fields_filter_invalid_tshark_fields(monkeypatch) -> None:
    fields_output = "\n".join(
        [
            "F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0",
            "F\tSource\tip.src\tFT_IPv4\tip\t\t0x0",
            "F\tDestination\tip.dst\tFT_IPv4\tip\t\t0x0",
            "F\tCalculated window size\ttcp.window_size\tFT_UINT32\ttcp\tBASE_DEC\t0x0",
            "F\tMSS Value\ttcp.options.mss_val\tFT_UINT16\ttcp\tBASE_DEC\t0x0",
            "F\tTCP window update\ttcp.analysis.window_update\tFT_NONE\ttcp\t\t0x0",
            "F\tTCP window full\ttcp.analysis.window_full\tFT_NONE\ttcp\t\t0x0",
        ]
    )
    monkeypatch.setattr(
        "flowpilot.protocols.tcp._tshark_field_names",
        lambda _tshark: parse_tcp_tshark_field_names(fields_output),
    )

    fields = tcp_deep_fields_for_tshark("fake-tshark")

    assert "tcp.window_size" in fields
    assert "tcp.options.mss_val" in fields
    assert "tcp.analysis.window_update" in fields
    assert "tcp.analysis.window_full" in fields
    assert "tcp.analysis.window_full_segment" not in fields


def test_parse_esp_rows_includes_ip_udp_and_sequence_metadata() -> None:
    values = {field: "" for field in ESP_DEEP_FIELDS}
    values.update(
        {
            "frame.number": "40",
            "frame.time_relative": "4.0",
            "frame.len": "1500",
            "ip.src": "10.0.0.1",
            "ip.dst": "10.0.0.2",
            "ip.len": "1480",
            "ip.ttl": "63",
            "ip.dsfield.dscp": "46",
            "ip.flags.df": "1",
            "udp.srcport": "4500",
            "udp.dstport": "4500",
            "udp.length": "1472",
            "esp.spi": "0x1234",
            "esp.sequence": "100",
        }
    )
    output = "\t".join(values[field] for field in ESP_DEEP_FIELDS)

    rows = parse_esp_rows(output)

    assert rows[0]["src"] == "10.0.0.1"
    assert rows[0]["dst"] == "10.0.0.2"
    assert rows[0]["esp.spi"] == "0x1234"
    assert rows[0]["esp.sequence"] == "100"


def test_esp_metadata_counts_and_direction_stats_track_tunnel_signals() -> None:
    rows = [
        {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "frame.len": "1500",
            "ip.len": "1480",
            "ip.ttl": "63",
            "ip.dsfield.dscp": "46",
            "ip.flags.df": "1",
            "udp.dstport": "4500",
            "esp.sequence": "1",
        },
        {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "frame.len": "1500",
            "ip.len": "1400",
            "ip.ttl": "62",
            "ip.dsfield.dscp": "46",
            "ip.frag_offset": "1",
            "esp.sequence": "4",
        },
        {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "frame.len": "1500",
            "ip.len": "1200",
            "esp.sequence": "3",
        },
        {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "frame.len": "1500",
            "ip.len": "1480",
            "esp.sequence": "4",
        },
    ]

    assert esp_metadata_counts(rows) == {
        "esp_packets": 4,
        "nat_t_udp_4500_packets": 1,
        "df_set_packets": 1,
        "fragmented_packets": 1,
        "dscp_value_count": 1,
        "dscp_values": ["46"],
        "ip_length_min": 1200,
        "ip_length_max": 1480,
        "df_bit": "on",
    }
    assert esp_direction_stats(rows) == [
        {
            "direction": "10.0.0.1 -> 10.0.0.2",
            "packets": 4,
            "bytes": 6000,
            "first_sequence": 1,
            "last_sequence": 4,
            "highest_sequence": 4,
            "missing_count": 1,
            "largest_sequence_gap": 2,
            "gap_distribution": {"gap=2": 1},
            "out_of_order_count": 1,
            "duplicate_count": 1,
            "ttl_min": 62,
            "ttl_max": 63,
            "dscp_values": ["46"],
            "df_set_packets": 1,
            "fragmented_packets": 1,
            "nat_t_udp_4500_packets": 1,
        }
    ]


def test_esp_deep_fields_filter_invalid_tshark_fields(monkeypatch) -> None:
    fields_output = "\n".join(
        [
            "F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0",
            "F\tESP SPI\tesp.spi\tFT_UINT32\tesp\tBASE_HEX_DEC\t0x0",
            "F\tESP Sequence\tesp.sequence\tFT_UINT32\tesp\tBASE_DEC\t0x0",
            "F\tTTL\tip.ttl\tFT_UINT8\tip\tBASE_DEC\t0x0",
        ]
    )
    monkeypatch.setattr(
        "flowpilot.protocols.esp._tshark_field_names",
        lambda _tshark: parse_esp_tshark_field_names(fields_output),
    )

    fields = esp_deep_fields_for_tshark("fake-tshark")

    assert "frame.number" in fields
    assert "esp.spi" in fields
    assert "esp.sequence" in fields
    assert "ip.ttl" in fields
    assert "udp.length" not in fields


def test_esp_flow_filter_uses_ipv4_field_for_ipv4_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.20", protocol="ESP")
    )

    from flowpilot.protocols.esp import esp_flow_filter

    assert esp_flow_filter(flow) == (
        "((ip.src == 10.0.0.10 && ip.dst == 10.0.0.20) || "
        "(ip.src == 10.0.0.20 && ip.dst == 10.0.0.10)) && esp && !udp"
    )


def test_esp_flow_filter_uses_ipv6_field_for_ipv6_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="2001:db8::1", endpoint_b="2001:db8::2", protocol="ESP")
    )

    from flowpilot.protocols.esp import esp_flow_filter

    assert esp_flow_filter(flow) == (
        "((ipv6.src == 2001:db8::1 && ipv6.dst == 2001:db8::2) || "
        "(ipv6.src == 2001:db8::2 && ipv6.dst == 2001:db8::1)) && esp && !udp"
    )


def test_esp_flow_filter_includes_nat_t_ports_when_present() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="10.0.0.20",
            port_a=4500,
            port_b=4500,
            protocol="ESP",
        )
    )

    from flowpilot.protocols.esp import esp_flow_filter

    assert esp_flow_filter(flow) == (
        "((ip.src == 10.0.0.10 && ip.dst == 10.0.0.20 && "
        "udp.srcport == 4500 && udp.dstport == 4500) || "
        "(ip.src == 10.0.0.20 && ip.dst == 10.0.0.10 && "
        "udp.srcport == 4500 && udp.dstport == 4500)) && udp && esp"
    )


def test_parse_udp_rows_includes_dns_and_dhcp_metadata() -> None:
    values = {field: "" for field in UDP_HEADER_FIELDS}
    values.update(
        {
            "frame.number": "20",
            "frame.time_relative": "2.5",
            "ip.src": "10.0.0.10",
            "ip.dst": "10.0.0.53",
            "udp.srcport": "53000",
            "udp.dstport": "53",
            "udp.length": "80",
            "udp.checksum.status": "good",
            "dns.id": "0x1234",
            "dns.qry.name": "missing.example",
            "dns.flags.rcode": "3",
            "dns.time": "0.020",
            "bootp.id": "0xabc",
            "bootp.option.dhcp": "Discover",
        }
    )
    output = "\t".join(values[field] for field in UDP_HEADER_FIELDS)

    rows = parse_field_rows(output, UDP_HEADER_FIELDS)

    assert rows[0]["src"] == "10.0.0.10"
    assert rows[0]["dst"] == "10.0.0.53"
    assert rows[0]["udp.srcport"] == "53000"
    assert rows[0]["dns.qry.name"] == "missing.example"
    assert rows[0]["bootp.option.dhcp"] == "Discover"


def test_udp_metadata_counts_tracks_dns_dhcp_and_checksum() -> None:
    rows = [
        {"dns.id": "0x1", "dns.flags.response": "1", "dns.flags.rcode": "3"},
        {"bootp.id": "0x2", "bootp.option.dhcp": "Offer"},
        {"udp.checksum.status": "bad"},
    ]

    assert udp_metadata_counts(rows) == {
        "dns_packets": 1,
        "dns_responses": 1,
        "dns_error_responses": 1,
        "dhcp_packets": 1,
        "udp_bad_checksum": 1,
    }


def test_parse_smb2_rows_includes_credit_and_transfer_headers() -> None:
    values = {field: "" for field in SMB2_DEEP_FIELDS}
    values.update(
        {
            "frame.number": "25",
            "frame.time_relative": "2.9",
            "ip.src": "10.0.0.10",
            "ip.dst": "10.0.0.20",
            "tcp.srcport": "55000",
            "tcp.dstport": "445",
            "tcp.seq": "1000",
            "smb2.cmd": "8",
            "smb2.flags.response": "0",
            "smb2.msg_id": "42",
            SMB2_CREDIT_CHARGE_FIELD: "1",
            SMB2_CREDIT_REQUEST_RESPONSE_FIELD: "128",
            "smb2.read.length": "1048576",
            "smb2.offset": "0",
            "smb2.file_id": "abcd",
            "smb2.filename": r"share\large.bin",
        }
    )
    output = "\t".join(values[field] for field in SMB2_DEEP_FIELDS)

    rows = parse_field_rows(output, SMB2_DEEP_FIELDS)

    assert rows[0]["src"] == "10.0.0.10"
    assert rows[0]["tcp.dstport"] == "445"
    assert rows[0][SMB2_CREDIT_CHARGE_FIELD] == "1"
    assert rows[0][SMB2_CREDIT_REQUEST_RESPONSE_FIELD] == "128"
    assert rows[0]["smb2.filename"] == r"share\large.bin"


def test_smb2_credit_counts_splits_request_grant_and_charge() -> None:
    rows = [
        {
            "smb2.cmd": "8",
            "smb2.flags.response": "0",
            SMB2_CREDIT_CHARGE_FIELD: "2",
            SMB2_CREDIT_REQUEST_RESPONSE_FIELD: "128",
        },
        {
            "smb2.cmd": "8",
            "smb2.flags.response": "1",
            SMB2_CREDIT_CHARGE_FIELD: "2",
            SMB2_CREDIT_REQUEST_RESPONSE_FIELD: "64",
            "smb2.nt_status": "0x00000000",
        },
        {
            "smb2.cmd": "9",
            "smb2.flags.response": "1",
            SMB2_CREDIT_CHARGE_FIELD: "1",
            SMB2_CREDIT_REQUEST_RESPONSE_FIELD: "0",
            "smb2.nt_status": "0xc0000022",
            "tcp.analysis.retransmission": "1",
            "tcp.analysis.zero_window": "1",
        },
    ]

    assert smb2_credit_counts(rows) == {
        "smb2_packets": 3,
        "smb2_requests": 1,
        "smb2_responses": 2,
        "credit_charge_total": 5,
        "credit_charge_max": 2,
        "credit_request_total": 128,
        "credit_request_max": 128,
        "credit_grant_total": 64,
        "credit_grant_max": 64,
        "credit_grant_zero_packets": 1,
        "read_packets": 2,
        "write_packets": 1,
        "status_error_packets": 1,
        "tcp_loss_or_retransmission_packets": 1,
        "tcp_zero_window_packets": 1,
    }


def test_smb2_credit_counts_accepts_split_request_and_grant_fields() -> None:
    rows = [
        {
            "smb2.cmd": "8",
            "smb2.flags.response": "0",
            SMB2_CREDIT_CHARGE_FIELD: "2",
            "smb2.credits.requested": "128",
        },
        {
            "smb2.cmd": "8",
            "smb2.flags.response": "1",
            SMB2_CREDIT_CHARGE_FIELD: "2",
            "smb2.credits.granted": "64",
            "smb2.nt_status": "0x00000000",
        },
    ]

    assert smb2_credit_counts(rows) == {
        "smb2_packets": 2,
        "smb2_requests": 1,
        "smb2_responses": 1,
        "credit_charge_total": 4,
        "credit_charge_max": 2,
        "credit_request_total": 128,
        "credit_request_max": 128,
        "credit_grant_total": 64,
        "credit_grant_max": 64,
        "read_packets": 2,
    }


def test_smb2_deep_fields_filter_invalid_tshark_fields(monkeypatch) -> None:
    fields_output = "\n".join(
        [
            "F\tFrame Number\tframe.number\tFT_UINT32\tframe\tBASE_DEC\t0x0",
            "F\tSource\tip.src\tFT_IPv4\tip\t\t0x0",
            "F\tDestination\tip.dst\tFT_IPv4\tip\t\t0x0",
            "F\tCommand\tsmb2.cmd\tFT_UINT16\tsmb2\tBASE_DEC\t0x0",
            "F\tWrite Length\tsmb2.write_length\tFT_UINT32\tsmb2\tBASE_DEC\t0x0",
            "F\tFile Offset\tsmb2.file_offset\tFT_UINT64\tsmb2\tBASE_DEC\t0x0",
            "F\tCredits requested\tsmb2.credits.requested\tFT_UINT16\tsmb2\tBASE_DEC\t0x0",
        ]
    )
    monkeypatch.setattr(
        "flowpilot.protocols.smb._tshark_field_names",
        lambda _tshark: _parse_tshark_field_names(fields_output),
    )

    fields = smb2_deep_fields_for_tshark("fake-tshark")

    assert "smb2.write_length" in fields
    assert "smb2.file_offset" in fields
    assert "smb2.credits.requested" in fields
    assert "smb2.write.length" not in fields
    assert "smb2.offset" not in fields


def test_parse_tls_rows_includes_transport_and_tls_metadata() -> None:
    values = {field: "" for field in TLS_DEEP_FIELDS}
    values.update(
        {
            "frame.number": "30",
            "frame.time_relative": "3.5",
            "ip.src": "10.0.0.10",
            "ip.dst": "203.0.113.10",
            "tcp.srcport": "50000",
            "tcp.dstport": "443",
            "tcp.seq": "100",
            "tls.handshake.type": "1|11",
            "tls.handshake.extensions_server_name": "api.example.com",
            "tls.handshake.ciphersuites": "0x1301|0x1302",
            "tls.handshake.ciphersuite": "0x1301",
            "tls.handshake.sig_hash_hash": "4",
            "tls.handshake.sig_hash_sig": "3",
            "tls.handshake.extensions_supported_group": "29",
            "tls.handshake.extensions_key_share_group": "29",
            "tls.handshake.certificate": "aa|bb|cc",
            "tls.alert_message.level": "2",
            "tls.alert_message.desc": "40",
            "x509af.subject": "CN=api.example.com|CN=Example CA",
        }
    )
    output = "\t".join(values[field] for field in TLS_DEEP_FIELDS)

    rows = parse_field_rows(output, TLS_DEEP_FIELDS)

    assert rows[0]["src"] == "10.0.0.10"
    assert rows[0]["tcp.srcport"] == "50000"
    assert rows[0]["tls.handshake.ciphersuites"] == "0x1301|0x1302"
    assert rows[0]["tls.handshake.sig_hash_hash"] == "4"
    assert rows[0]["tls.handshake.extensions_key_share_group"] == "29"
    assert rows[0]["tls.handshake.certificate"] == "aa|bb|cc"
    assert rows[0]["x509af.subject"] == "CN=api.example.com|CN=Example CA"


def test_tls_metadata_counts_tracks_tls_dtls_and_transport_markers() -> None:
    rows = [
        {
            "tcp.srcport": "50000",
            "tls.handshake.type": "1",
            "tls.handshake.certificate": "aa|bb|cc",
            "tls.handshake.ciphersuite": "0x1301",
            "tls.handshake.sig_hash_hash": "4",
            "tls.alert_message.level": "2",
            "tcp.analysis.retransmission": "1",
        },
        {
            "udp.srcport": "4433",
            "dtls.handshake.type": "1",
            "dtls.handshake.certificate": "dd|ee",
            "dtls.alert_message.desc": "40",
        },
    ]

    assert tls_metadata_counts(rows) == {
        "tls_packets": 1,
        "dtls_packets": 1,
        "tls_handshake_packets": 1,
        "dtls_handshake_packets": 1,
        "tls_certificate_fields": 5,
        "tls_alert_packets": 1,
        "dtls_alert_packets": 1,
        "tcp_transport_packets": 1,
        "udp_transport_packets": 1,
        "tcp_loss_or_retransmission_packets": 1,
        "algorithm_field_packets": 1,
    }


def test_tls_flow_filter_uses_tcp_or_udp_transport() -> None:
    tcp_flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        )
    )
    udp_flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=4433,
            protocol="UDP",
        )
    )

    assert "tcp.dstport == 443" in tls_flow_filter(tcp_flow)
    assert "udp.dstport == 4433" in tls_flow_filter(udp_flow)
    assert "(tls || dtls)" in tls_flow_filter(tcp_flow)


def test_endpoint_filter_uses_ipv4_field_for_ipv4_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.53", protocol="UDP")
    )

    assert endpoint_filter_for_flow(flow) == (
        "((ip.src == 10.0.0.10 && ip.dst == 10.0.0.53) || "
        "(ip.src == 10.0.0.53 && ip.dst == 10.0.0.10))"
    )


def test_endpoint_filter_uses_ipv6_field_for_ipv6_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="2001:db8::1", endpoint_b="2001:db8::2", protocol="UDP")
    )

    assert endpoint_filter_for_flow(flow) == (
        "((ipv6.src == 2001:db8::1 && ipv6.dst == 2001:db8::2) || "
        "(ipv6.src == 2001:db8::2 && ipv6.dst == 2001:db8::1))"
    )
