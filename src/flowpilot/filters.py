from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse

from .models import FlowSummary, PacketObservation
from .protocol_matching import canonical, flow_protocols, packet_protocols


@dataclass(frozen=True)
class FlowFilter:
    host: str | None = None
    peer: str | None = None
    protocol: str | None = None
    port: int | None = None
    src: str | None = None
    dst: str | None = None
    src_port: int | None = None
    dst_port: int | None = None

    @property
    def is_active(self) -> bool:
        return any(
            value is not None
            for value in (
                self.host,
                self.peer,
                self.protocol,
                self.port,
                self.src,
                self.dst,
                self.src_port,
                self.dst_port,
            )
        )

    def matches(self, packet: PacketObservation) -> bool:
        return (not self.protocol or canonical(self.protocol) in packet_protocols(packet)) and (
            self._matches_endpoints(packet.source_endpoint, packet.destination_endpoint,
                                    packet.src_port, packet.dst_port)
        )

    @property
    def is_directional(self) -> bool:
        return any(
            value is not None for value in (self.src, self.dst, self.src_port, self.dst_port)
        )

    def matches_flow(self, flow: FlowSummary) -> bool:
        """Select whole saved flows with an observed direction matching all criteria."""
        key = flow.key
        directions = (
            (key.endpoint_a, key.endpoint_b, key.port_a, key.port_b, flow.src_to_dst_packets),
            (key.endpoint_b, key.endpoint_a, key.port_b, key.port_a, flow.dst_to_src_packets),
        )
        return any(
            (not self.is_directional or packets > 0)
            and (not self.protocol or canonical(self.protocol) in
                 flow_protocols(flow, index if self.is_directional else None))
            and self._matches_endpoints(src, dst, src_port, dst_port)
            for index, (src, dst, src_port, dst_port, packets) in enumerate(directions)
        )

    def _matches_endpoints(
        self, src: str, dst: str, src_port: int | None, dst_port: int | None
    ) -> bool:
        is_mac = bool(re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", src))
        if is_mac:
            src, dst = src.lower(), dst.lower()

        def normalize(value):
            return value.lower() if is_mac and value else value
        if self.host and normalize(self.host) not in (src, dst):
            return False
        if self.peer and normalize(self.peer) not in (src, dst):
            return False
        if self.host and self.peer and {src, dst} != {normalize(self.host), normalize(self.peer)}:
            return False
        if self.src and src != normalize(self.src):
            return False
        if self.dst and dst != normalize(self.dst):
            return False
        if self.port is not None and self.port not in (src_port, dst_port):
            return False
        if self.src_port is not None and src_port != self.src_port:
            return False
        if self.dst_port is not None and dst_port != self.dst_port:
            return False
        return True


def filter_observations(
    observations: Iterable[PacketObservation],
    flow_filter: FlowFilter,
) -> Iterator[PacketObservation]:
    for observation in observations:
        if flow_filter.matches(observation):
            yield observation


def filter_sip_calls_by_phone(
    observations: Iterable[PacketObservation],
    phone_number: str,
) -> list[PacketObservation]:
    packets = list(observations)
    wanted = _digits(phone_number)
    if not wanted:
        return packets

    matching_call_ids = {
        packet.sip_call_id
        for packet in packets
        if packet.sip_call_id
        and (
            _phone_matches(wanted, packet.sip_from)
            or _phone_matches(wanted, packet.sip_to)
        )
    }
    return [
        packet
        for packet in packets
        if packet.sip_call_id in matching_call_ids
        or (
            not packet.sip_call_id
            and (
                _phone_matches(wanted, packet.sip_from)
                or _phone_matches(wanted, packet.sip_to)
            )
        )
    ]


def include_redirect_related_flows(
    observations: list[PacketObservation],
    seed_observations: list[PacketObservation],
) -> list[PacketObservation]:
    redirect_hosts = _redirect_hosts(seed_observations)
    if not redirect_hosts:
        return seed_observations

    related_ips = _ips_for_names(observations, redirect_hosts)
    included: list[PacketObservation] = []
    seen_ids: set[int] = set()

    for packet in [*seed_observations, *observations]:
        if id(packet) in seen_ids:
            continue
        if packet in seed_observations or _matches_related_target(
            packet,
            redirect_hosts,
            related_ips,
        ):
            included.append(packet)
            seen_ids.add(id(packet))

    return included


def _redirect_hosts(observations: Iterable[PacketObservation]) -> set[str]:
    hosts = set()
    for packet in observations:
        if not packet.http_location:
            continue
        parsed = urlparse(packet.http_location)
        host = parsed.hostname
        if host:
            hosts.add(host.lower())
    return hosts


def _ips_for_names(observations: Iterable[PacketObservation], names: set[str]) -> set[str]:
    ips = {name for name in names if _is_ip_address(name)}
    for packet in observations:
        if packet.dns_query and packet.dns_query.rstrip(".").lower() in names:
            ips.update(packet.dns_answers)
    return ips


def _matches_related_target(
    packet: PacketObservation,
    names: set[str],
    ips: set[str],
) -> bool:
    packet_names = {
        name.rstrip(".").lower()
        for name in (packet.dns_query, packet.http_host, packet.tls_sni)
        if name
    }
    if packet_names & names:
        return True
    return packet.src_ip in ips or packet.dst_ip in ips


def _is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True


def _digits(value: str) -> str:
    return "".join(re.findall(r"\d+", value))


def _phone_matches(wanted_digits: str, value: str | None) -> bool:
    return wanted_digits in _digits(value or "")
