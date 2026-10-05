from __future__ import annotations

_RTP_UDP_PORTS: tuple[int, ...] = ()
_SRTP_UDP_PORTS: tuple[int, ...] = ()
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
    for port in sorted(set((*_RTP_UDP_PORTS, *_SRTP_UDP_PORTS))):
        parameters.extend(["-d", f"udp.port=={port},rtp"])
    return parameters


def set_rtp_udp_ports(ports=None, secure_ports=None) -> None:
    global _RTP_UDP_PORTS, _SRTP_UDP_PORTS
    _RTP_UDP_PORTS = tuple(sorted(set(ports or ())))
    _SRTP_UDP_PORTS = tuple(sorted(set(secure_ports or ())))
    if (_RTP_UDP_PORTS or _SRTP_UDP_PORTS) and (
        _ESP_ALL_UDP_PORTS or set(_ESP_UDP_PORTS) & set((*_RTP_UDP_PORTS, *_SRTP_UDP_PORTS))
    ):
        raise ValueError("RTP/SRTP and ESP decode-as ports must not overlap.")


def srtp_udp_ports() -> tuple[int, ...]:
    return _SRTP_UDP_PORTS
