import io

import pytest
from rich.console import Console
from typer.testing import CliRunner

from flowpilot.analysis import summarize_capture
from flowpilot.cli import app
from flowpilot.filters import FlowFilter
from flowpilot.models import CaptureSummary, FlowKey, FlowSummary, PacketObservation


def packet(**kwargs):
    return PacketObservation(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000,
                             dst_port=2000, protocol="UDP", length=100, **kwargs)


@pytest.mark.parametrize("query,fields,expected", [
    ("IKE", {"ike": {"version": 32}}, True),
    ("isakmp", {"ike": {"version": 16}}, True),
    ("ikev1", {"ike": {"version": 16}}, True),
    ("ikev2", {"ike": {"version": 16}}, False),
    ("srtp", {"rtp_ssrc": "1", "srtp": True}, True),
    ("rtp", {"rtp_ssrc": "1", "srtp": True}, True),
    ("srtp", {"rtp_ssrc": "1"}, False),
    ("dns", {"dns_query": "example.test"}, True),
    ("bootp", {"dhcp_message_type": "DISCOVER"}, True),
    ("sip", {"sip_method": "INVITE"}, True),
    ("dtls", {"tls_sni": "example.test"}, True),
    ("tls", {"tls_sni": "example.test"}, False),
    ("smb", {"decoded_protocols": ["SMB2"]}, True),
    ("smb2", {"decoded_protocols": ["SMB"]}, False),
    ("quic", {"decoded_protocols": ["ETH", "IP", "UDP", "QUIC"]}, True),
    ("ipv4", {"decoded_protocols": ["IP"]}, True),
    ("udp", {"decoded_protocols": ["QUIC"]}, True),
    ("dns", {}, False),
])
def test_direct_protocols_round_trip(query, fields, expected):
    observation = packet(**fields)
    selected = FlowFilter(protocol=query)
    assert selected.matches(observation) is expected
    summary = summarize_capture([observation])
    saved = CaptureSummary.model_validate_json(summary.model_dump_json())
    assert selected.matches_flow(saved.flows[0]) is expected


def test_loaded_protocol_and_direction_must_match_together():
    a = packet(decoded_protocols=["UDP", "QUIC"])
    b = a.model_copy(update={"src_ip": "10.0.0.2", "dst_ip": "10.0.0.1",
                             "src_port": 2000, "dst_port": 1000,
                             "decoded_protocols": ["UDP", "DNS"]})
    summary = summarize_capture([a, b])
    saved = CaptureSummary.model_validate_json(summary.model_dump_json()).flows[0]
    assert FlowFilter(protocol="quic", src="10.0.0.1").matches_flow(saved)
    assert not FlowFilter(protocol="quic", src="10.0.0.2").matches_flow(saved)
    assert FlowFilter(protocol="dns", src="10.0.0.2").matches_flow(saved)
    assert not FlowFilter(protocol="dns", src="10.0.0.1").matches_flow(saved)
    assert saved.packet_count == 2
    assert saved.byte_count == 200


def test_legacy_summary_uses_metadata_without_port_guessing():
    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2",
                                   protocol="UDP", port_a=53, port_b=1234),
                       packet_count=2, src_to_dst_packets=1, dst_to_src_packets=1)
    assert not FlowFilter(protocol="dns").matches_flow(flow)
    flow.dns_queries = {"example.test": 1}
    assert FlowFilter(protocol="dns").matches_flow(flow)
    assert not FlowFilter(protocol="dns", src="10.0.0.1").matches_flow(flow)
    flow.packet_details = [packet(dns_query="example.test").model_copy(
        update={"src_port": 53, "dst_port": 1234}
    )]
    assert FlowFilter(protocol="dns", src="10.0.0.1").matches_flow(flow)


def test_protocol_rejects_display_filter_expression():
    result = CliRunner().invoke(app, ["analyze", "capture.pcap", "--protocol", "tcp or udp"])
    assert result.exit_code == 2
    assert "one decoded protocol name" in result.output


def test_udp_filter_keeps_esp_transport_identity():
    observation = packet(decoded_protocols=["IP", "UDP", "ESP"]).model_copy(
        update={"protocol": "ESP"}
    )
    assert FlowFilter(protocol="udp").matches(observation)
    flow = summarize_capture([observation]).flows[0]
    assert flow.key.protocol == "ESP"
    assert FlowFilter(protocol="esp").matches_flow(flow)
    assert FlowFilter(protocol="udp").matches_flow(flow)


def test_cli_fresh_and_loaded_protocol_scope(tmp_path, monkeypatch):
    import flowpilot.cli as cli

    output = io.StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=120))
    observations = [packet(decoded_protocols=["QUIC"]), packet(decoded_protocols=["DNS"])]
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "_capture_packet_count", lambda _: None)
    monkeypatch.setattr(cli, "read_capture", lambda *args, **kwargs: iter(observations))
    result = CliRunner().invoke(app, [
        "analyze", "capture.pcap", "--protocol", "quic", "--no-llm",
    ])
    assert result.exit_code == 0, result.output
    assert cli._load_summary(tmp_path / "capture.json").packet_count == 1
    complete = summarize_capture(observations)
    source = tmp_path / "complete.json"
    source.write_text(complete.model_dump_json())
    before = source.read_bytes()
    result = CliRunner().invoke(app, [
        "analyze", "capture.pcap", "--load-summary", str(source),
        "--protocol", "quic", "--no-llm",
    ])
    assert result.exit_code == 0, result.output
    assert "whole saved flows" in output.getvalue()
    assert source.read_bytes() == before
    assert cli._load_summary(source).packet_count == 2
