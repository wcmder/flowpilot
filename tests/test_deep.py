from flowpilot.deep import (
    UDP_HEADER_FIELDS,
    _parse_field_rows,
    _parse_tshark_rows,
    _tcp_analysis_counts,
    _udp_metadata_counts,
)


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
