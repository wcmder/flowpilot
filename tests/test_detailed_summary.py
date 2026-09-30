import json
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

import flowpilot.cli as cli
import flowpilot.reasoning as reasoning
from flowpilot.deep_tools import DEEP_TOOL_REGISTRY
from flowpilot.models import CaptureSummary, PacketObservation


@pytest.mark.parametrize("protocol,fields", [
    ("TCP", {}), ("TCP", {"tls_sni": "example.test"}),
    ("TCP", {"smb_command": "READ"}), ("TCP", {"sip_method": "INVITE"}),
    ("UDP", {}), ("UDP", {"tls_sni": "dtls.example.test"}),
    ("UDP", {"dns_query": "example.test"}), ("UDP", {"dhcp_message_type": "DISCOVER"}),
    ("UDP", {"sip_method": "INVITE"}), ("ESP", {"esp_spi": "0x1234", "esp_sequence": 7}),
    ("ICMP", {}), ("ICMPV6", {}), ("AH", {}), ("GRE", {}), ("UNKNOWN", {}),
])
def test_detailed_summary_preserves_every_analyzed_flow_type(
    tmp_path, monkeypatch, protocol, fields,
):
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "_capture_packet_count", lambda _: None)
    observation = PacketObservation(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol=protocol, length=100, **fields,
    )
    monkeypatch.setattr(cli, "read_capture", lambda *args, **kwargs: iter([observation]))
    calls = []

    def runner(path, *, flow_id, flow, reason, sample_limit):
        assert sample_limit is None
        calls.append(flow.key.protocol)
        return {"status": "ok", "packet_count": 1}

    for tool in DEEP_TOOL_REGISTRY:
        monkeypatch.setitem(DEEP_TOOL_REGISTRY, tool, SimpleNamespace(runner=runner))
    result = CliRunner().invoke(cli.app, [
        "analyze", "capture.pcap", "--detailed-summary", "--no-llm",
    ])
    assert result.exit_code == 0, result.output
    loaded = cli._load_summary(tmp_path / "capture-detailed.json")
    assert loaded.flows[0].packet_details == [observation]
    expected = {
        "TCP": {"deep_tcp_flow", "deep_tls_flow", "deep_smb2_flow"},
        "UDP": {"deep_udp_flow", "deep_tls_flow"}, "ESP": {"deep_esp_flow"},
    }.get(protocol, set())
    assert set(loaded.flows[0].deep_details) == expected
    assert len(calls) == len(expected)
    if not expected:
        coverage = loaded.compact()["top_flows"][0]["saved_packet_details"]["coverage"]
        assert "observations only" in coverage


def test_deep_extraction_failure_keeps_observations_and_other_tools(tmp_path, monkeypatch):
    from flowpilot.deep_tools import collect_flow_details
    from flowpilot.models import FlowKey, FlowSummary

    observation = PacketObservation(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="TCP")
    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="TCP"),
                       packet_details=[observation])

    def failed(*args, **kwargs):
        raise RuntimeError("TShark extraction failed")

    def success(*args, **kwargs):
        return {"status": "ok", "packet_count": 0}

    monkeypatch.setitem(DEEP_TOOL_REGISTRY, "deep_tcp_flow", SimpleNamespace(runner=failed))
    for tool in ("deep_tls_flow", "deep_smb2_flow"):
        monkeypatch.setitem(DEEP_TOOL_REGISTRY, tool, SimpleNamespace(runner=success))
    collect_flow_details(tmp_path / "capture.pcap", flow, 1)
    loaded = FlowSummary.model_validate_json(flow.model_dump_json())
    assert loaded.packet_details == [observation]
    assert loaded.deep_details["deep_tcp_flow"]["status"] == "error"
    assert "extraction failed" in loaded.deep_details["deep_tcp_flow"]["message"]
    assert loaded.deep_details["deep_tls_flow"]["status"] == "ok"
    assert loaded.deep_details["deep_smb2_flow"]["status"] == "ok"


def test_cli_saves_selected_packet_details_and_loads_without_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "_capture_packet_count", lambda _: None)
    monkeypatch.setattr(cli, "read_capture", lambda *args, **kwargs: iter([
        PacketObservation(src_ip="10.0.0.1", dst_ip="10.0.0.2", protocol="ESP", length=100),
        PacketObservation(src_ip="10.0.0.3", dst_ip="10.0.0.4", protocol="ESP", length=200),
    ]))

    def collect(path, flow, flow_id):
        assert flow.key.endpoint_a == "10.0.0.1"
        flow.deep_details["deep_esp_flow"] = {
            "tool": "deep_esp_flow", "flow_id": flow_id, "status": "ok", "packet_count": 1,
            "esp_deep_samples": [{"frame.number": "1", "esp.sequence": "7"}],
        }

    monkeypatch.setattr(cli, "collect_flow_details", collect)
    result = CliRunner().invoke(cli.app, [
        "analyze", "capture.pcap", "--host", "10.0.0.1", "--detailed-summary", "--no-llm",
    ])
    assert result.exit_code == 0, result.output
    saved = tmp_path / "capture-detailed.json"
    loaded = cli._load_summary(saved)
    assert loaded.flow_count == 1
    assert len(loaded.flows[0].packet_details) == 1
    assert loaded.flows[0].packet_details[0].length == 100
    assert loaded.flows[0].deep_details["deep_esp_flow"]["status"] == "ok"
    before = saved.read_bytes()

    def no_capture(*args, **kwargs):
        raise AssertionError("Loading detailed summaries must not read the PCAP")

    monkeypatch.setattr(cli, "read_capture", no_capture)
    result = CliRunner().invoke(cli.app, [
        "analyze", "capture.pcap", "--load-detailed-summary", str(saved), "--no-llm",
    ])
    assert result.exit_code == 0, result.output
    assert saved.read_bytes() == before


def test_provider_receives_saved_preview_not_entire_large_snapshot(monkeypatch):
    from flowpilot.models import FlowKey, FlowSummary

    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="ESP"))
    flow.deep_details["deep_esp_flow"] = {
        "tool": "deep_esp_flow", "flow_id": 99, "status": "ok", "packet_count": 2005,
        "esp_deep_samples": [{"frame.number": str(i)} for i in range(1, 2006)],
    }
    summary = CaptureSummary(packet_count=2005, total_bytes=2005, flow_count=1,
                             protocols={"ESP": 2005}, top_ports={}, issue_counts={}, names=[],
                             flows=[flow])
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(output_text="Saved details received.")

    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)
    client = SimpleNamespace(responses=SimpleNamespace(create=create))
    reasoning._chat_with_responses(client, summary, "inspect flow id 1", model="test",
                                   max_flows=1, report=None, history=None)
    content = calls[0]["input"][-1]["content"]
    context, _ = json.JSONDecoder().raw_decode(content.split("\n\n", 1)[1])
    evidence = context["additional_tool_evidence"][0]
    assert evidence["source"] == "saved_summary"
    assert evidence["flow_id"] == 1
    assert evidence["target_flow"]["flow_id"] == 1
    assert len(evidence["esp_deep_samples"]) == 1000
    assert evidence["batch"]["next_offset"] == 1000
    assert "deep_details" not in context["summary"]["top_flows"][0]
    assert len(flow.deep_details["deep_esp_flow"]["esp_deep_samples"]) == 2005


@pytest.mark.parametrize("filename,expected", [
    ("chosen.json", "chosen-detailed.json"),
    ("chosen-detailed.json", "chosen-detailed.json"),
])
def test_custom_detailed_filename_preserves_regular_summary(
    tmp_path, monkeypatch, filename, expected,
):
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "_capture_packet_count", lambda _: None)
    monkeypatch.setattr(cli, "read_capture", lambda *args, **kwargs: iter([]))
    regular = tmp_path / "capture.json"
    regular.write_text("original")
    result = CliRunner().invoke(cli.app, [
        "analyze", "capture.pcap", "--detailed-summary", "--json", filename, "--no-llm",
    ])
    assert result.exit_code == 0, result.output
    assert (tmp_path / expected).exists()
    assert regular.read_text() == "original"


@pytest.mark.parametrize("flags", [
    ["--load-summary", "regular.json", "--load-detailed-summary", "details.json"],
    ["--detailed-summary", "--load-detailed-summary", "details.json"],
    ["--detailed-summary", "--load-summary", "regular.json"],
])
def test_summary_modes_reject_conflicting_flags(flags):
    result = CliRunner().invoke(cli.app, ["analyze", "capture.pcap", *flags, "--no-llm"])
    assert result.exit_code == 2


def test_bare_detailed_loader_selects_detailed_file_without_writing(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    summary = CaptureSummary(packet_count=0, total_bytes=0, flow_count=0,
                             protocols={}, top_ports={}, issue_counts={}, names=[], flows=[])
    saved = tmp_path / "capture-detailed.json"
    saved.write_text(summary.model_dump_json())
    before = saved.read_bytes()
    (tmp_path / "capture.json").write_text("not the detailed file")
    args = cli._normalize_optional_json_arg([
        "analyze", "capture.pcap", "--load-detailed-summary", "--no-llm",
    ])
    assert args == ["analyze", "capture.pcap", "--load-detailed-summary",
                    "capture-detailed.json", "--no-llm"]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    assert saved.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["capture-detailed.json", "capture.json"]
