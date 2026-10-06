import struct

import pytest
from test_ike import write_capture

from flowpilot.analysis import summarize_capture
from flowpilot.capture import read_capture
from flowpilot.deep_tools import collect_flow_details, deep_tool_requests_for_flow, run_deep_tool
from flowpilot.filters import FlowFilter
from flowpilot.models import CaptureSummary, FlowSummary
from flowpilot.protocols.deep_common import tshark_path
from flowpilot.protocols.link_security import deep_eapol_flow, deep_macsec_flow

A = "00:11:22:33:44:55"
B = "00:aa:bb:cc:dd:ee"


def ethernet(protocol, body, *, reverse=False, vlan=None, other=False):
    a, b = bytes.fromhex(A.replace(":", "")), bytes.fromhex(B.replace(":", ""))
    if reverse:
        a, b = b, a
    if other:
        b = bytes.fromhex("001122334466")
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return b + a + tag + struct.pack("!H", protocol) + body


def macsec(pn):
    return struct.pack("!BBI", 0x2c, 0, pn) + bytes.fromhex("0011223344550001") + bytes(64)


def eapol(code=3):
    return struct.pack("!BBHBBH", 2, 0, 4, code, 1, 4)


@pytest.mark.parametrize("protocol,ethertype,body,runner", [
    ("MACSEC", 0x88e5, macsec(1), deep_macsec_flow),
    ("EAPOL", 0x888e, eapol(), deep_eapol_flow),
])
def test_real_layer2_capture_flows_filters_and_saved_details(
    tmp_path, protocol, ethertype, body, runner,
):
    if not tshark_path():
        pytest.skip("TShark required")
    path = tmp_path / "link.pcap"
    frames = [ethernet(ethertype, body, vlan=10), ethernet(ethertype, body, reverse=True, vlan=10),
              ethernet(ethertype, body, vlan=20), ethernet(ethertype, body, vlan=10, other=True)]
    write_capture(path, frames)
    observations = list(read_capture(path))
    assert len(observations) == 4
    assert observations[0].src_ip is None
    assert observations[0].src_mac == A
    assert observations[0].vlan_ids == (10,)
    assert observations[0].protocol == protocol
    assert FlowFilter(protocol=protocol, host=A.upper()).matches(observations[0])
    summary = summarize_capture(observations)
    assert len(summary.flows) == 3
    flow = summary.flows[0]
    assert flow.key.address_type == "mac"
    assert flow.key.vlan_ids == (10,)
    assert flow.src_to_dst_packets == flow.dst_to_src_packets == 1
    assert flow.throughput_mbps_by_direction[0] == flow.throughput_mbps_by_direction[1]
    assert deep_tool_requests_for_flow(1, flow)["tool"] == f"deep_{protocol.lower()}_flow"
    restored = CaptureSummary.model_validate_json(summary.model_dump_json())
    assert restored.compact() == summary.compact()
    result = runner(path, flow_id=1, flow=flow, reason="test", sample_limit=1, sample_offset=1)
    assert result["status"] == "ok", result
    assert result["packet_count"] == 2
    assert result["link_header_samples"][0]["frame.number"] == "2"
    assert "frame.time_relative" in result["link_header_samples"][0]
    collect_flow_details(path, flow, 1)
    restored_flow = FlowSummary.model_validate_json(flow.model_dump_json())
    cached = run_deep_tool(f"deep_{protocol.lower()}_flow", None, flow_id=7,
                           flow=restored_flow, reason="saved", sample_offset=1)
    assert cached["source"] == "saved_summary"
    assert cached["flow_id"] == 7
    assert cached["batch"]["returned"] == 1
    if protocol == "MACSEC":
        assert flow.macsec.number_ranges["macsec.PN"] == [1, 1]
    else:
        assert flow.eapol.fields["eap.code"] == {"3": 2}


def test_mka_and_eap_identity_without_secret_payloads(tmp_path):
    if not tshark_path():
        pytest.skip("TShark required")
    basic = (struct.pack("!BBH", 1, 1, 0xd020) + bytes.fromhex("0011223344550001") +
             bytes(12) + struct.pack("!II", 1, 0x0080c201) + b"CKN1" + bytes(16))
    mka = struct.pack("!BBH", 3, 5, len(basic)) + basic
    identity = b"private-user-identity"
    eap = struct.pack("!BBHB", 2, 1, 5 + len(identity), 1) + identity
    path = tmp_path / "mka.pcap"
    write_capture(path, [ethernet(0x888e, mka),
                         ethernet(0x888e, struct.pack("!BBH", 2, 0, len(eap)) + eap)])
    observations = list(read_capture(path))
    assert FlowFilter(protocol="mka").matches(observations[0])
    assert "mka.version_id" in observations[0].eapol_fields
    assert "private-user-identity" not in observations[1].model_dump_json()
    flow = summarize_capture(observations).flows[0]
    result = deep_eapol_flow(path, flow_id=1, flow=flow, reason="test")
    assert result["status"] == "ok", result
    assert "private-user-identity" not in str(result)
    assert "mka.actor_mn" in result["header_summary"]["number_ranges"]


def test_wlan_eapol_endpoints_and_deep_filter(tmp_path):
    if not tshark_path():
        pytest.skip("TShark required")
    a, b = bytes.fromhex(A.replace(":", "")), bytes.fromhex(B.replace(":", ""))
    header = struct.pack("<HH", 0x0008, 0) + b + a + bytes.fromhex("102030405060") + bytes(2)
    frame = header + bytes.fromhex("aaaa03000000888e") + eapol(4)
    path = tmp_path / "wlan.pcap"
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
    path.write_bytes(data + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame)
    observations = list(read_capture(path))
    assert len(observations) == 1
    assert observations[0].src_mac == A
    flow = summarize_capture(observations).flows[0]
    assert flow.key.link_type == "wlan"
    result = deep_eapol_flow(path, flow_id=1, flow=flow, reason="test")
    assert result["status"] == "ok", result
    assert result["packet_count"] == 1
    assert result["link_header_samples"][0]["src"] == A
    assert result["header_summary"]["fields"]["eap.code"] == {"4": 1}


def test_macsec_large_saved_batch_and_cli_round_trip(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    import flowpilot.cli as cli

    if not tshark_path():
        pytest.skip("TShark required")
    path = tmp_path / "many.pcap"
    write_capture(path, [ethernet(0x88e5, macsec(i + 1)) for i in range(1005)])
    observations = list(read_capture(path, packet_limit=1))
    monkeypatch.setattr(cli, "FLOWPILOT_PRIVATE_DIR", tmp_path)
    monkeypatch.setattr(cli, "_capture_packet_count", lambda _: None)
    monkeypatch.setattr(cli, "read_capture", lambda *args, **kwargs: iter(observations))
    result = CliRunner().invoke(cli.app, [
        "analyze", str(path), "--protocol", "macsec", "--detailed-summary", "--no-llm",
    ])
    assert result.exit_code == 0, result.output
    summary = cli._load_summary(tmp_path / "many-detailed.json")
    flow = summary.flows[0]
    assert flow.packet_details[0].src_ip is None
    assert flow.packet_details[0].src_mac == A
    assert flow.deep_details["deep_macsec_flow"]["packet_count"] == 1005
    cached = run_deep_tool("deep_macsec_flow", None, flow_id=1, flow=flow,
                           reason="test", sample_offset=1000)
    assert cached["batch"]["returned"] == 5
    assert cached["link_header_samples"][0]["macsec.PN"] == "1001"
    assert cached["header_summary"]["number_ranges"]["macsec.PN"] == [1, 1005]
