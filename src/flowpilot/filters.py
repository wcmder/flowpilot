from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse

from .models import PacketObservation


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
        if self.protocol and packet.protocol.upper() != self.protocol.upper():
            return False
        if self.host and self.host not in (packet.src_ip, packet.dst_ip):
            return False
        if self.peer and self.peer not in (packet.src_ip, packet.dst_ip):
            return False
        if self.host and self.peer and {packet.src_ip, packet.dst_ip} != {self.host, self.peer}:
            return False
        if self.src and packet.src_ip != self.src:
            return False
        if self.dst and packet.dst_ip != self.dst:
            return False
        if self.port and self.port not in (packet.src_port, packet.dst_port):
            return False
        if self.src_port and packet.src_port != self.src_port:
            return False
        if self.dst_port and packet.dst_port != self.dst_port:
            return False
        return True


def filter_observations(
    observations: Iterable[PacketObservation],
    flow_filter: FlowFilter,
) -> Iterator[PacketObservation]:
    for observation in observations:
        if flow_filter.matches(observation):
            yield observation


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
