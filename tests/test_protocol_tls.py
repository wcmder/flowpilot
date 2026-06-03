from flowpilot.models import CaptureSummary, FlowKey, FlowSummary, TlsCertificateObservation
from flowpilot.protocols.tls import tls_details_table


def test_tls_details_table_returns_none_without_tls_metadata() -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=1,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[FlowSummary(key=FlowKey(endpoint_a="a", endpoint_b="b", protocol="TCP"))],
    )

    assert tls_details_table(summary, show_flows=10) is None


def test_tls_details_table_renders_certificate_chain_and_alerts() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="203.0.113.10",
            port_a=50000,
            port_b=443,
            protocol="TCP",
        ),
        tls_sni_endpoints={"10.0.0.10:50000": ["api.example.com"]},
        tls_alert_endpoints={"203.0.113.10:443": {"fatal (2) handshake_failure (40)": 1}},
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
                not_after="2030-01-01T00:00:00+00:00",
            ),
        ],
    )
    summary = CaptureSummary(
        packet_count=10,
        total_bytes=1_000,
        flow_count=1,
        protocols={"TCP": 10},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[flow],
    )

    table = tls_details_table(summary, show_flows=10)

    assert table is not None
    cells = [column._cells[0] for column in table.columns]
    assert cells[0] == "1"
    assert cells[1] == "203.0.113.10:443\n(server)"
    assert cells[2] == "-"
    assert cells[3] == "Cert 1: api.example.com\nCert 2: Example Issuing CA"
    assert cells[4] == "Cert 1: Example Issuing CA\nCert 2: Example Root CA"
    assert cells[5] == "Cert 1: 2027-01-01\nCert 2: 2030-01-01"
    assert cells[6] == "Cert 1: api.example.com\nCert 2: -"
    assert cells[7] == "sent tls alert: fatal (2) handshake_failure (40) (x1)"
