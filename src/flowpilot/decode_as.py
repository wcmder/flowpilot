from __future__ import annotations

_ESP_UDP_PORTS: tuple[int, ...] = ()


def set_esp_udp_ports(ports: list[int] | tuple[int, ...] | None) -> None:
    global _ESP_UDP_PORTS
    _ESP_UDP_PORTS = tuple(sorted({port for port in ports or () if port > 0}))


def esp_udp_ports() -> tuple[int, ...]:
    return _ESP_UDP_PORTS


def tshark_decode_as_parameters() -> list[str]:
    parameters = []
    for port in _ESP_UDP_PORTS:
        parameters.extend(["-d", f"udp.port=={port},esp"])
    return parameters
