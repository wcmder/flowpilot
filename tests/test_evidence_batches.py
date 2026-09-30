import importlib
import struct
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import flowpilot.workflow as workflow
from flowpilot.deep_tools import DEEP_TOOL_REGISTRY, collect_flow_details, run_deep_tool
from flowpilot.models import (
    AgentChatResponse,
    CaptureSummary,
    EvidenceRequest,
    FlowKey,
    FlowSummary,
)
from flowpilot.protocols.deep_common import evidence_batch, tshark_path


@pytest.mark.parametrize("module,tool,protocol,sample_key", [
    ("tcp", "deep_tcp_flow", "TCP", "tcp_header_samples"),
    ("udp", "deep_udp_flow", "UDP", "udp_header_samples"),
    ("tls", "deep_tls_flow", "TCP", "tls_deep_samples"),
    ("smb", "deep_smb2_flow", "TCP", "smb2_deep_samples"),
    ("esp", "deep_esp_flow", "ESP", "esp_deep_samples"),
])
def test_all_deep_tools_deliver_every_packet_in_order(monkeypatch, tmp_path, module, tool,
                                                     protocol, sample_key):
    implementation = importlib.import_module(f"flowpilot.protocols.{module}")
    monkeypatch.setattr(implementation, "tshark_path", lambda: "tshark")
    for name in ("tcp_deep_fields_for_tshark", "smb2_deep_fields_for_tshark",
                 "esp_deep_fields_for_tshark"):
        if hasattr(implementation, name):
            monkeypatch.setattr(implementation, name, lambda _: [
                "frame.number", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
                "tcp.analysis.retransmission",
            ])

    def run(command, **kwargs):
        fields = [command[i + 1] for i, part in enumerate(command) if part == "-e"]
        rows = []
        for number in range(1, 2006):
            values = {"frame.number": str(number), "ip.src": "10.0.0.1", "ip.dst": "10.0.0.2"}
            if number == 2005:
                values["tcp.analysis.retransmission"] = "1"
            rows.append("\t".join(values.get(field, "") for field in fields))
        return SimpleNamespace(returncode=0, stdout="\n".join(rows), stderr="")

    monkeypatch.setattr(implementation.subprocess, "run", run)
    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol=protocol))
    packets = []
    for offset, returned, next_offset in [(0, 1000, 1000), (1000, 1000, 2000), (2000, 5, None)]:
        result = run_deep_tool(tool, tmp_path / "capture.pcap", flow_id=1, flow=flow,
                               reason="Review details", sample_offset=offset)
        assert result["status"] == "ok"
        assert result["packet_count"] == 2005
        assert result["batch"]["total_matching_packets"] == 2005
        assert result["batch"]["returned"] == returned
        assert result["batch"]["next_offset"] == next_offset
        assert result["batch"]["has_more"] == (next_offset is not None)
        if module == "tcp":
            assert result["tcp_analysis_counts"]["tcp.analysis.retransmission"] == 1
        packets.extend(int(row["frame.number"]) for row in result[sample_key])
    assert packets == list(range(1, 2006))
    full = DEEP_TOOL_REGISTRY[tool].runner(
        tmp_path / "capture.pcap", flow_id=1, flow=flow, reason="Save all", sample_limit=None,
    )
    assert len(full[sample_key]) == 2005
    flow.deep_details[tool] = full
    loaded = FlowSummary.model_validate_json(flow.model_dump_json())

    def no_reread(*args, **kwargs):
        pytest.fail("Saved details must not reread TShark")

    monkeypatch.setattr(implementation.subprocess, "run", no_reread)
    cached = run_deep_tool(
        tool, None, flow_id=7, flow=loaded, reason="Saved page", sample_offset=2000,
    )
    assert cached["source"] == "saved_summary"
    assert cached["flow_id"] == 7
    assert [int(row["frame.number"]) for row in cached[sample_key]] == list(range(2001, 2006))
    assert len(loaded.deep_details[tool][sample_key]) == 2005


def test_real_tshark_can_retrieve_esp_details_after_first_1000_packets(tmp_path):
    if not tshark_path():
        pytest.skip("TShark is required for the pagination integration test")
    payload = struct.pack("!II", 0x12345678, 7) + bytes(range(32))
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, 50, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2])) + payload
    frame = bytes.fromhex("00112233445566778899aabb0800") + ip
    capture = tmp_path / "batches.pcap"
    capture.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + b"".join(struct.pack("<IIII", n, 0, len(frame), len(frame)) + frame
                   for n in range(1, 2006))
    )
    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="ESP"))
    collect_flow_details(capture, flow, 1)
    flow = FlowSummary.model_validate_json(flow.model_dump_json())
    assert len(flow.deep_details["deep_esp_flow"]["esp_deep_samples"]) == 2005
    capture.unlink()
    frames = []
    for offset in (0, 1000, 2000):
        result = run_deep_tool("deep_esp_flow", capture, flow_id=1, flow=flow,
                               reason="Inspect all details", sample_offset=offset)
        assert result["status"] == "ok"
        assert result["packet_count"] == 2005
        frames.extend(int(row["frame.number"]) for row in result["esp_deep_samples"])
    assert frames == list(range(1, 2006))
    assert result["batch"]["next_offset"] is None


def test_batch_boundaries_and_invalid_offsets():
    assert evidence_batch(0, 0, 1000)["returned"] == 0
    assert evidence_batch(1000, 0, 1000)["next_offset"] is None
    assert evidence_batch(1000, 1500, 1000)["returned"] == 0
    with pytest.raises(ValidationError):
        EvidenceRequest(tool="deep_tcp_flow", flow_id=1, reason="test", sample_offset=-1)
    with pytest.raises(ValueError):
        evidence_batch(1000, 0, 0)


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_requests_later_batches_and_resumes_after_turn_limit(monkeypatch, tmp_path):
    summary = CaptureSummary(
        packet_count=5000, total_bytes=5000, flow_count=1, protocols={"UDP": 5000},
        top_ports={}, issue_counts={}, names=[], flows=[FlowSummary(
            key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="UDP"),
        )],
    )
    offsets = []

    def tool(name, path, *, sample_offset=0, **kwargs):
        offsets.append(sample_offset)
        return {"tool": name, "flow_id": 1, "status": "ok",
                "batch": evidence_batch(5000, sample_offset, 1000)}

    def chat(*args, **kwargs):
        evidence = kwargs["additional_evidence"]
        batch = evidence[-1]["batch"] if evidence else None
        next_offset = batch["next_offset"] if batch else 0
        return AgentChatResponse(answer="Reviewed supplied batches.", evidence_requests=(
            [EvidenceRequest(tool="deep_udp_flow", flow_id=1, reason="More details",
                             sample_offset=next_offset)] if next_offset is not None else []
        ))

    monkeypatch.setattr(workflow, "run_deep_tool", tool)
    monkeypatch.setattr(workflow, "agent_chat_about_capture", chat)
    first = workflow.run_agent_chat_state(
        summary, "run deep_udp_flow for flow id 1", capture_path=tmp_path / "capture.pcap",
    )
    assert offsets == [0, 1000, 2000]
    assert "More details remain available" in first["answer"]
    second = workflow.run_agent_chat_state(
        summary, "continue reviewing the next batch", capture_path=tmp_path / "capture.pcap",
        additional_evidence=first["deep_evidence"],
        completed_tool_requests=first["completed_tool_requests"],
    )
    assert offsets == [0, 1000, 2000, 3000, 4000]
    assert len(second["completed_tool_requests"]) == 5
    assert second["deep_evidence"][-1]["batch"]["has_more"] is False
