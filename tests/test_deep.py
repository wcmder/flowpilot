from flowpilot.deep import (
    TLS_DEEP_FIELDS,
    UDP_HEADER_FIELDS,
    _endpoint_filter,
    _parse_field_rows,
    _parse_tshark_rows,
    _tcp_analysis_counts,
    _tls_flow_filter,
    _tls_metadata_counts,
    _udp_metadata_counts,
)
from flowpilot.models import FlowKey, FlowSummary


def test_parse_tshark_rows_includes_tcp_headers_and_analysis_markers() -> None:
    output = (
        "10\t1.0\t10.0.0.1\t\t10.0.0.2\t\t12345\t443\t100\t200\t1460\t65535\t"
        "65535\t0x0018\t\t1\t\t\t1\t1\t\t\t\t\t\t\t\n"
    )

    rows = _parse_tshark_rows(output)

    assert rows[0]["frame.number"] == "10"
    assert rows[0]["src"] == "10.0.0.1"
    assert rows[0]["dst"] == "10.0.0.2"
    assert rows[0]["tcp.seq"] == "100"
    assert rows[0]["tcp.ack"] == "200"
    assert rows[0]["tcp.len"] == "1460"
    assert rows[0]["tcp.window_size_value"] == "65535"
    assert rows[0]["tcp.flags"] == "0x0018"
    assert rows[0]["tcp.analysis.retransmission"] == "1"


def test_tcp_analysis_counts_counts_presence_markers() -> None:
    rows = [
        {"tcp.analysis.lost_segment": "1"},
        {"tcp.analysis.lost_segment": "", "tcp.analysis.retransmission": "1"},
        {"tcp.analysis.lost_segment": "0"},
    ]

    assert _tcp_analysis_counts(rows) == {
        "tcp.analysis.lost_segment": 1,
        "tcp.analysis.retransmission": 1,
    }


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

    rows = _parse_field_rows(output, UDP_HEADER_FIELDS)

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

    assert _udp_metadata_counts(rows) == {
        "dns_packets": 1,
        "dns_responses": 1,
        "dns_error_responses": 1,
        "dhcp_packets": 1,
        "udp_bad_checksum": 1,
    }


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

    rows = _parse_field_rows(output, TLS_DEEP_FIELDS)

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

    assert _tls_metadata_counts(rows) == {
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

    assert "tcp.port == 443" in _tls_flow_filter(tcp_flow)
    assert "udp.port == 4433" in _tls_flow_filter(udp_flow)
    assert "(tls || dtls)" in _tls_flow_filter(tcp_flow)


def test_endpoint_filter_uses_ipv4_field_for_ipv4_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.53", protocol="UDP")
    )

    assert _endpoint_filter(flow) == "(ip.addr == 10.0.0.10 && ip.addr == 10.0.0.53)"


def test_endpoint_filter_uses_ipv6_field_for_ipv6_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="2001:db8::1", endpoint_b="2001:db8::2", protocol="UDP")
    )

    assert _endpoint_filter(flow) == "(ipv6.addr == 2001:db8::1 && ipv6.addr == 2001:db8::2)"
