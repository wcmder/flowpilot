from flowpilot.models import FlowKey, FlowSummary
from flowpilot.protocols.deep_common import endpoint_filter_for_flow, parse_field_rows
from flowpilot.protocols.smb import (
    SMB2_CREDIT_CHARGE_FIELD,
    SMB2_CREDIT_REQUEST_RESPONSE_FIELD,
    SMB2_DEEP_FIELDS,
    _parse_tshark_field_names,
    smb2_credit_counts,
    smb2_deep_fields_for_tshark,
)
from flowpilot.protocols.tcp import parse_tcp_rows, tcp_analysis_counts
from flowpilot.protocols.tls import TLS_DEEP_FIELDS, tls_flow_filter, tls_metadata_counts
from flowpilot.protocols.udp import UDP_HEADER_FIELDS, udp_metadata_counts


def test_parse_tshark_rows_includes_tcp_headers_and_analysis_markers() -> None:
    output = (
        "10\t1.0\t10.0.0.1\t\t10.0.0.2\t\t12345\t443\t100\t200\t1460\t65535\t"
        "65535\t0x0018\t\t1\t\t\t1\t1\t\t\t\t\t\t\t\n"
    )

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


def test_tcp_analysis_counts_counts_presence_markers() -> None:
    rows = [
        {"tcp.analysis.lost_segment": "1"},
        {"tcp.analysis.lost_segment": "", "tcp.analysis.retransmission": "1"},
        {"tcp.analysis.lost_segment": "0"},
    ]

    assert tcp_analysis_counts(rows) == {
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

    assert "tcp.port == 443" in tls_flow_filter(tcp_flow)
    assert "udp.port == 4433" in tls_flow_filter(udp_flow)
    assert "(tls || dtls)" in tls_flow_filter(tcp_flow)


def test_endpoint_filter_uses_ipv4_field_for_ipv4_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.10", endpoint_b="10.0.0.53", protocol="UDP")
    )

    assert endpoint_filter_for_flow(flow) == "(ip.addr == 10.0.0.10 && ip.addr == 10.0.0.53)"


def test_endpoint_filter_uses_ipv6_field_for_ipv6_endpoints() -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="2001:db8::1", endpoint_b="2001:db8::2", protocol="UDP")
    )

    assert endpoint_filter_for_flow(flow) == (
        "(ipv6.addr == 2001:db8::1 && ipv6.addr == 2001:db8::2)"
    )
