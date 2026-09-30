from __future__ import annotations

_ESP_UDP_PORTS: tuple[int, ...] = ()
ALL_ESP_UDP_PORTS = -1  # Internal value inserted for a bare CLI flag.
_ESP_ALL_UDP_PORTS = False


def set_esp_udp_ports(ports: list[int] | tuple[int, ...] | None) -> None:
    global _ESP_UDP_PORTS, _ESP_ALL_UDP_PORTS
    _ESP_ALL_UDP_PORTS = ALL_ESP_UDP_PORTS in (ports or ())
    _ESP_UDP_PORTS = tuple(sorted({port for port in ports or () if 0 <= port <= 65535}))


def esp_udp_ports() -> tuple[int, ...]:
    return _ESP_UDP_PORTS


def tshark_decode_as_parameters() -> list[str]:
    if _ESP_ALL_UDP_PORTS:
        return ["-d", "udp.port==0-65535,udpencap"]
    parameters = []
    for port in _ESP_UDP_PORTS:
        # ESP is an IP dissector; UDP decode-as requires its encapsulation dissector.
        parameters.extend(["-d", f"udp.port=={port},udpencap"])
    return parameters
