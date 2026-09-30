import ipaddress
import struct
import subprocess

import pytest

from flowpilot.models import FlowKey, FlowSummary
from flowpilot.protocols.deep_common import tcp_flow_filter, tshark_path, udp_flow_filter
from flowpilot.protocols.esp import esp_flow_filter


def _frame(source, destination, source_port, destination_port, transport, payload=None):
    if payload is None:
        payload = struct.pack("!II", 0x12345678, 7) + bytes(range(32))
    if transport == "tcp":
        data = struct.pack("!HHIIBBHHH", source_port, destination_port, 1, 0, 0x50, 2, 1024, 0, 0)
        protocol = 6
    elif transport == "udp":
        data = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
        protocol = 17
    else:
        data, protocol = payload, 50
    src, dst = ipaddress.ip_address(source), ipaddress.ip_address(destination)
    if src.version == 4:
        header = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(data), 1, 0, 64, protocol, 0,
            src.packed, dst.packed,
        )
        ethertype = b"\x08\x00"
    else:
        header = struct.pack(
            "!IHBB16s16s", 6 << 28, len(data), protocol, 64, src.packed, dst.packed
        )
        ethertype = b"\x86\xdd"
    return bytes.fromhex("00112233445566778899aabb") + ethertype + header + data


def _matching_frames(tmp_path, frames, display_filter, decode_ports=()):
    tshark = tshark_path()
    if not tshark:
        pytest.skip("TShark is required for flow-filter integration tests")
    capture = tmp_path / "conversations.pcap"
    content = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for number, frame in enumerate(frames, 1):
        content += struct.pack("<IIII", number, 0, len(frame), len(frame)) + frame
    capture.write_bytes(content)
    command = [
        tshark, "-r", str(capture), "-Y", display_filter, "-T", "fields", "-e", "frame.number",
    ]
    for port in decode_ports:
        command.extend(["-d", f"udp.port=={port},udpencap"])
    result = subprocess.run(command, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    return [int(number) for number in result.stdout.split()]


@pytest.mark.parametrize("family", [4, 6])
@pytest.mark.parametrize("protocol", ["TCP", "UDP", "ESP"])
def test_deep_filter_binds_ports_to_addresses_in_both_directions(tmp_path, family, protocol):
    a, b, c = ("10.0.0.1", "10.0.0.2", "10.0.0.3") if family == 4 else (
        "2001:db8::1", "2001:db8::2", "2001:db8::3"
    )
    flow = FlowSummary(key=FlowKey(
        endpoint_a=a, endpoint_b=b, port_a=30001, port_b=30002, protocol=protocol,
    ))
    transport = "tcp" if protocol == "TCP" else "udp"
    frames = [
        _frame(a, b, 30001, 30002, transport),  # forward
        _frame(b, a, 30002, 30001, transport),  # reverse
        _frame(a, b, 30002, 30001, transport),  # same IPs and port set, different flow
        _frame(b, a, 30001, 30002, transport),
        _frame(a, c, 30001, 30002, transport),  # wrong peer
        _frame(a, b, 30001, 30003, transport),  # wrong port
    ]
    make_filter = {"TCP": tcp_flow_filter, "UDP": udp_flow_filter, "ESP": esp_flow_filter}[protocol]
    assert _matching_frames(
        tmp_path, frames, make_filter(flow), [30001, 30002] if protocol == "ESP" else [],
    ) == [1, 2]


@pytest.mark.parametrize("ports", [(4500, 4500), (0, 30002), (30001, None)])
def test_udp_filter_handles_equal_zero_and_missing_ports(tmp_path, ports):
    a, b = "10.0.0.1", "10.0.0.2"
    pa, pb = ports
    actual_b = 30002 if pb is None else pb
    flow = FlowSummary(key=FlowKey(endpoint_a=a, endpoint_b=b, port_a=pa, port_b=pb))
    frames = [
        _frame(a, b, pa, actual_b, "udp"),
        _frame(b, a, actual_b, pa, "udp"),
        _frame(a, b, pa + 1, actual_b, "udp"),
    ]
    assert _matching_frames(tmp_path, frames, udp_flow_filter(flow)) == [1, 2]


@pytest.mark.parametrize("family", [4, 6])
def test_native_esp_excludes_udp_esp_and_nat_t_excludes_keepalives(tmp_path, family):
    a, b = ("10.0.0.1", "10.0.0.2") if family == 4 else ("2001:db8::1", "2001:db8::2")
    native = FlowSummary(key=FlowKey(endpoint_a=a, endpoint_b=b, protocol="ESP"))
    encapsulated = FlowSummary(key=FlowKey(
        endpoint_a=a, endpoint_b=b, port_a=4500, port_b=4500, protocol="ESP",
    ))
    frames = [
        _frame(a, b, None, None, "esp"),
        _frame(b, a, None, None, "esp"),
        _frame(a, b, 4500, 4500, "udp"),
        _frame(b, a, 4500, 4500, "udp"),
        _frame(a, b, 4500, 4500, "udp", b"\xff"),  # NAT keepalive
        _frame(a, b, 4500, 4500, "udp", bytes(32)),  # non-ESP marker
    ]
    assert _matching_frames(tmp_path, frames, esp_flow_filter(native)) == [1, 2]
    assert _matching_frames(tmp_path, frames, esp_flow_filter(encapsulated)) == [3, 4]
