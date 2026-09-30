import struct
import subprocess

import pytest

from flowpilot.decode_as import ALL_ESP_UDP_PORTS, set_esp_udp_ports, tshark_decode_as_parameters
from flowpilot.protocols.deep_common import field_command, parse_field_rows, tshark_path


def test_multiple_esp_udp_ports_use_udpencap() -> None:
    try:
        set_esp_udp_ports([12366, 12346, 12366])
        assert tshark_decode_as_parameters() == [
            "-d", "udp.port==12346,udpencap", "-d", "udp.port==12366,udpencap",
        ]
    finally:
        set_esp_udp_ports(None)


@pytest.mark.parametrize("ports", [[12366], [ALL_ESP_UDP_PORTS], [12346, ALL_ESP_UDP_PORTS]])
def test_tshark_decodes_esp_on_custom_udp_port(tmp_path, ports) -> None:
    tshark = tshark_path()
    if not tshark:
        pytest.skip("TShark is required for the decode-as integration test")

    # Ethernet / IPv4 / UDP / ESP SPI and sequence, followed by opaque payload.
    esp = struct.pack("!II", 0x12345678, 7) + bytes(range(32))
    udp = struct.pack("!HHHH", 12366, 12366, 8 + len(esp), 0) + esp
    ip = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
        bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]),
    ) + udp
    frame = bytes.fromhex("00112233445566778899aabb0800") + ip
    capture = tmp_path / "udp-esp.pcap"
    capture.write_bytes(
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame
    )
    fields = ["ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "udp.srcport", "esp.spi", "esp.sequence"]
    try:
        set_esp_udp_ports(ports)
        result = subprocess.run(
            field_command(tshark, capture, "esp", fields),
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, result.stderr
        rows = parse_field_rows(result.stdout, fields)
        assert len(rows) == 1
        assert rows[0]["src"] == "10.0.0.1"
        assert rows[0]["dst"] == "10.0.0.2"
        assert rows[0]["udp.srcport"] == "12366"
        assert int(rows[0]["esp.spi"], 0) == 0x12345678
        assert int(rows[0]["esp.sequence"], 0) == 7
    finally:
        set_esp_udp_ports(None)
    assert tshark_decode_as_parameters() == []
