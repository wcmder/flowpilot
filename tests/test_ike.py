import struct

import pytest
from test_deep_filters import _frame

from flowpilot.analysis import summarize_capture
from flowpilot.capture import read_capture
from flowpilot.decode_as import set_esp_udp_ports, set_rtp_udp_ports
from flowpilot.deep_tools import collect_flow_details, deep_tool_requests_for_flow, run_deep_tool
from flowpilot.models import CaptureSummary, FlowKey, FlowSummary
from flowpilot.protocols.deep_common import tshark_path
from flowpilot.protocols.ike import deep_ike_flow


@pytest.fixture(autouse=True)
def clean_decode():
    set_esp_udp_ports([])
    set_rtp_udp_ports([])
    yield
    set_esp_udp_ports([])
    set_rtp_udp_ports([])


def ike_packet(version, *, response=False, encrypted=False, message_id=0, notifications=()):
    major = version >> 4
    exchange = 2 if major == 1 else (35 if encrypted else 34)
    flags = (1 if encrypted else 0) if major == 1 else (0x20 if response else 0x08)
    notify_payload = 11 if major == 1 else 41
    payload = b""
    for index, code in enumerate(notifications):
        body = ((struct.pack("!I", 1) if major == 1 else b"") +
                struct.pack("!BBH", 1 if major == 1 else 0, 0, code))
        payload += struct.pack("!BBH", notify_payload if index < len(notifications) - 1 else 0,
                               0, len(body) + 4) + body
    next_payload = notify_payload if notifications else 0
    if encrypted:
        next_payload = 46 if major == 2 else 5
        payload = struct.pack("!BBH", 0, 0, 36) + bytes(32)
    return struct.pack("!QQBBBBII", 0x12345678, 0x87654321, next_payload, version,
                       exchange, flags, message_id, 28 + len(payload)) + payload


def write_capture(path, frames):
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i, frame in enumerate(frames):
        data += struct.pack("<IIII", i + 1, 0, len(frame), len(frame)) + frame
    path.write_bytes(data)


@pytest.mark.parametrize("version", [0x10, 0x20])
@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("natt", [False, True])
def test_real_ike_versions_natt_excludes_esp_and_keepalives(tmp_path, version, family, natt):
    if not tshark_path():
        pytest.skip("TShark required")
    a, b = ("10.0.0.1", "10.0.0.2") if family == 4 else ("2001:db8::1", "2001:db8::2")
    port = 4500 if natt else 500
    marker = bytes(4) if natt else b""
    frames = [
        _frame(a, b, 40000, port, "udp", marker + ike_packet(version, notifications=(14, 24))),
        _frame(b, a, port, 40000, "udp", marker + ike_packet(version, response=True)),
        _frame(a, b, 40000, port, "udp",
               marker + ike_packet(version, encrypted=True, message_id=1)),
        _frame(a, b, port, 40000, "udp", marker + ike_packet(version)),  # Wrong pairing.
        _frame(a, b, 40000, port, "udp", b"\xff"),
        _frame(a, b, 40000, port, "udp", struct.pack("!II", 1234, 1) + bytes(32)),
    ]
    path = tmp_path / "ike.pcap"
    write_capture(path, frames)
    observations = list(read_capture(path))
    packet = observations[0]
    assert packet.protocol == "UDP"
    assert packet.ike.version == version
    assert packet.ike.message_id == 0
    assert packet.ike.notify_types == [14, 24]
    summary = summarize_capture(observations[:3])
    flow = summary.flows[0]
    session = flow.ike_sessions[0]
    assert session.packets_by_direction == [2, 1]
    assert session.encrypted_packets == 1
    assert session.v2_requests == (2 if version == 0x20 else 0)
    assert session.v2_responses == (1 if version == 0x20 else 0)
    assert deep_tool_requests_for_flow(1, flow)["tool"] == "deep_ike_flow"
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json())
    assert loaded.compact() == summary.compact()
    result = deep_ike_flow(path, flow_id=1, flow=flow, reason="test", sample_offset=1,
                           sample_limit=1)
    assert result["status"] == "ok", result
    assert result["packet_count"] == 3
    assert result["batch"]["next_offset"] == 2
    assert result["ike_header_samples"][0]["frame.number"] == "2"
    assert "frame.time_relative" in result["ike_header_samples"][0]
    assert result["ike_sessions"] == [s.model_dump() for s in flow.ike_sessions]


def test_ike_detailed_rows_and_saved_pagination(tmp_path):
    if not tshark_path():
        pytest.skip("TShark required")
    path = tmp_path / "many.pcap"
    write_capture(path, [
        _frame("10.0.0.1", "10.0.0.2", 40000, 500, "udp", ike_packet(0x20, message_id=i))
        for i in range(1005)
    ])
    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2",
                                   port_a=40000, port_b=500, protocol="UDP"))
    collect_flow_details(path, flow, 1)
    saved = FlowSummary.model_validate_json(flow.model_dump_json())
    assert len(saved.deep_details["deep_ike_flow"]["ike_header_samples"]) == 1005
    result = run_deep_tool("deep_ike_flow", None, flow_id=9, flow=saved, reason="saved",
                           sample_offset=1000)
    assert result["flow_id"] == 9
    assert result["batch"]["returned"] == 5
    assert result["source"] == "saved_summary"
    assert result["ike_header_samples"][0]["frame.number"] == "1001"
    assert result["batch"]["has_more"] is False


def test_ikev2_proposals_and_fragment_headers(tmp_path):
    if not tshark_path():
        pytest.skip("TShark required")
    transforms = (struct.pack("!BBHBBH", 3, 0, 8, 1, 0, 12) +
                  struct.pack("!BBHBBH", 0, 0, 8, 2, 0, 5))
    proposal = struct.pack("!BBHBBBB", 0, 0, 24, 1, 1, 0, 2) + transforms
    sa_payload = struct.pack("!BBH", 0, 0, 28) + proposal
    header = struct.pack("!QQBBBBII", 1, 2, 33, 0x20, 34, 8, 0, 28 + len(sa_payload))
    fragment = struct.pack("!BBHHH", 41, 0, 40, 1, 2) + bytes(32)
    fragment_header = struct.pack("!QQBBBBII", 1, 2, 53, 0x20, 35, 8, 1, 68)
    path = tmp_path / "details.pcap"
    write_capture(path, [
        _frame("10.0.0.1", "10.0.0.2", 40000, 500, "udp", header + sa_payload),
        _frame("10.0.0.1", "10.0.0.2", 40000, 500, "udp", fragment_header + fragment),
    ])
    observations = list(read_capture(path))
    assert observations[0].ike.proposal_fields["tf.type"] == ["1", "2"]
    assert observations[0].ike.proposal_fields["tf.id.encr"] == ["12"]
    assert observations[1].ike.fragment_number == 1
    assert observations[1].ike.fragment_total == 2
    flow = summarize_capture(observations).flows[0]
    assert flow.ike_sessions[0].fragmented_packets == 1
    assert flow.ike_sessions[0].encrypted_packets == 1
    evidence = deep_ike_flow(path, flow_id=1, flow=flow, reason="test")
    assert evidence["status"] == "ok", evidence
    assert evidence["ike_sessions"] == [s.model_dump() for s in flow.ike_sessions]
    assert evidence["ike_header_samples"][0]["isakmp.tf.type"] == "1,2"
    assert all(not field.endswith((".data", ".nonce", ".encrypted"))
               for field in evidence["ike_header_fields"])
