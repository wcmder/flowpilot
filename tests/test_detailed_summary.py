import json
from types import SimpleNamespace

from typer.testing import CliRunner

import flowpilot.cli as cli
import flowpilot.reasoning as reasoning
from flowpilot.models import CaptureSummary, PacketObservation


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
    saved = tmp_path / "capture.json"
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
        "analyze", "capture.pcap", "--load-summary", str(saved), "--no-llm",
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
