import struct
from datetime import datetime, timedelta, timezone

import pytest
from test_deep_filters import _frame

from flowpilot.analysis import summarize_capture
from flowpilot.capture import read_capture
from flowpilot.decode_as import set_esp_udp_ports, set_rtp_udp_ports
from flowpilot.deep_tools import collect_flow_details, deep_tool_requests_for_flow, run_deep_tool
from flowpilot.filters import FlowFilter
from flowpilot.models import CaptureSummary, FlowKey, FlowSummary, PacketObservation
from flowpilot.protocols.deep_common import tshark_path
from flowpilot.protocols.rtp import deep_rtp_flow


@pytest.fixture(autouse=True)
def clean_decode():
    set_esp_udp_ports([])
    set_rtp_udp_ports([])
    yield
    set_esp_udp_ports([])
    set_rtp_udp_ports([])


def test_rtp_rollover_late_arrival_duplicates_directions_and_saved_metrics():
    observations = []
    for i, seq in enumerate([65534, 0, 65535, 1, 1, 3]):
        observations.append(PacketObservation(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=6000,
            protocol="UDP", length=100, rtp_ssrc="0x00000001", rtp_sequence=seq,
            rtp_timestamp=i * 160, rtp_payload_type=0, srtp=True,
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
        ))
    observations.append(observations[0].model_copy(update={
        "src_ip": "10.0.0.2", "dst_ip": "10.0.0.1", "src_port": 6000, "dst_port": 5000,
    }))
    summary = summarize_capture(observations)
    flow = summary.flows[0]
    assert len(flow.rtp_streams) == 2
    forward, reverse = flow.rtp_streams
    assert forward.compact()["observed_sequence_holes"] == 1
    assert forward.duplicate_count == 1
    assert forward.out_of_order_count == 1
    assert reverse.direction == "B_to_A"
    assert forward.srtp_packets == 6
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json())
    assert loaded.compact() == summary.compact()
    assert deep_tool_requests_for_flow(1, flow)["tool"] == "deep_rtp_flow"
    assert flow.throughput_mbps_by_direction[0] > flow.throughput_mbps_by_direction[1]


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("secure", [False, True])
def test_real_rtp_capture_deep_batches_and_saved_details(tmp_path, family, secure):
    if not tshark_path():
        pytest.skip("TShark required")
    a, b = ("10.0.0.1", "10.0.0.2") if family == 4 else ("2001:db8::1", "2001:db8::2")
    frames = []
    for seq in range(1005):
        payload = struct.pack("!BBHII", 0x80, 0, seq, seq * 160, 1234) + b"media-not-for-llm"
        frames.append(_frame(a, b, 5000, 6000, "udp", payload))
    frames.append(_frame(b, a, 6000, 5000, "udp", payload))
    frames.append(_frame(a, b, 6000, 5000, "udp", payload))  # Wrong pairing.
    path = tmp_path / "rtp.pcap"
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        data += struct.pack("<IIII", 1 + i // 50, (i % 50) * 20000, len(frame), len(frame)) + frame
    path.write_bytes(data)
    set_rtp_udp_ports([] if secure else [5000], [5000] if secure else [])
    observations = list(read_capture(path, packet_limit=2))
    assert observations[0].rtp_sequence == 0
    assert observations[0].rtp_timestamp == 0
    assert observations[0].srtp is secure
    assert FlowFilter(protocol="rtp").matches(observations[0])
    assert FlowFilter(protocol="srtp").matches(observations[0]) is secure
    flow = FlowSummary(key=FlowKey(endpoint_a=a, endpoint_b=b, port_a=5000, port_b=6000,
                                   protocol="UDP"))
    result = deep_rtp_flow(path, flow_id=1, flow=flow, reason="test", sample_offset=1000)
    assert result["status"] == "ok", result
    assert result["packet_count"] == 1006
    assert result["batch"]["returned"] == 6
    assert result["rtp_header_samples"][0]["rtp.seq"] == "1000"
    assert "frame.time_relative" in result["rtp_header_samples"][0]
    assert "media-not-for-llm" not in str(result)
    collect_flow_details(path, flow, 1)
    assert len(flow.deep_details["deep_rtp_flow"]["rtp_header_samples"]) == 1006
    loaded = FlowSummary.model_validate_json(flow.model_dump_json())
    cached = run_deep_tool("deep_rtp_flow", None, flow_id=7, flow=loaded, reason="saved",
                           sample_offset=1000)
    assert cached["source"] == "saved_summary"
    assert cached["flow_id"] == 7
    assert cached["rtp_header_samples"] == result["rtp_header_samples"]


def test_rtp_decode_rejects_esp_overlap():
    set_esp_udp_ports([5000])
    with pytest.raises(ValueError, match="overlap"):
        set_rtp_udp_ports([5000])


def test_srtp_negotiated_by_sdp_without_port_override(tmp_path):
    if not tshark_path():
        pytest.skip("TShark required")
    sdp = (
        "v=0\r\no=- 1 1 IN IP4 10.0.0.2\r\ns=Media\r\nc=IN IP4 10.0.0.2\r\nt=0 0\r\n"
        "m=audio 6000 RTP/SAVP 0\r\n"
        "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
    )
    sip = (
        "INVITE sip:test@10.0.0.2 SIP/2.0\r\nVia: SIP/2.0/UDP 10.0.0.1:5060\r\n"
        "From: <sip:a@10.0.0.1>;tag=1\r\nTo: <sip:b@10.0.0.2>\r\n"
        "Call-ID: test-media\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp)}\r\n\r\n{sdp}"
    ).encode()
    media = struct.pack("!BBHII", 0x80, 0, 7, 160, 1234) + bytes(170)
    frames = [_frame("10.0.0.1", "10.0.0.2", 5060, 5060, "udp", sip),
              _frame("10.0.0.1", "10.0.0.2", 5000, 6000, "udp", media)]
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        data += struct.pack("<IIII", i + 1, 0, len(frame), len(frame)) + frame
    path = tmp_path / "srtp.pcap"
    path.write_bytes(data)
    observation = list(read_capture(path))[-1]
    assert observation.rtp_sequence == 7
    assert observation.srtp is True
    flow = summarize_capture([observation]).flows[0]
    result = deep_rtp_flow(path, flow_id=1, flow=flow, reason="test")
    assert result["status"] == "ok", result
    assert result["rtp_metadata_counts"]["srtp_packets"] == 1


def test_saved_rtp_preview_honors_offset(monkeypatch):
    import flowpilot.reasoning as reasoning

    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2",
                                   port_a=5000, port_b=6000, protocol="UDP"))
    flow.deep_details["deep_rtp_flow"] = {
        "tool": "deep_rtp_flow", "flow_id": 99, "status": "ok", "packet_count": 2005,
        "rtp_header_samples": [{"rtp.seq": str(i)} for i in range(2005)],
    }
    summary = CaptureSummary(packet_count=0, total_bytes=0, flow_count=1, protocols={},
                             top_ports={}, issue_counts={}, names=[], flows=[flow])
    token = reasoning.EVIDENCE_START_OFFSET.set(1000)
    try:
        evidence = reasoning._with_saved_evidence(summary, summary.compact(), [])
    finally:
        reasoning.EVIDENCE_START_OFFSET.reset(token)
    assert evidence[0]["batch"]["returned"] == 1000
    assert evidence[0]["batch"]["next_offset"] == 2000
    assert evidence[0]["rtp_header_samples"][0]["rtp.seq"] == "1000"
    assert evidence[0]["target_flow"]["flow_id"] == 1
