from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse

from .models import FlowSummary, PacketObservation
from .protocol_matching import canonical, flow_protocols, packet_protocols


def _values(value):
    if value is None:
        return ()
    return tuple(value) if isinstance(value, (list, tuple)) else (value,)


@dataclass(frozen=True)
class FlowFilter:
    host: str | list[str] | None = None
    peer: str | list[str] | None = None
    protocol: str | list[str] | None = None
    port: int | list[int] | None = None
    src: str | list[str] | None = None
    dst: str | list[str] | None = None
    src_port: int | list[int] | None = None
    dst_port: int | list[int] | None = None
    match_any: bool = False

    @property
    def is_active(self) -> bool:
        return any(_values(getattr(self, field)) for field in
                   ('host', 'peer', 'protocol', 'port', 'src', 'dst', 'src_port', 'dst_port'))

    @property
    def is_directional(self) -> bool:
        return any(_values(getattr(self, field)) for field in
                   ('src', 'dst', 'src_port', 'dst_port'))

    def matches(self, packet: PacketObservation) -> bool:
        return self._matches(packet.source_endpoint, packet.destination_endpoint,
                             packet.src_port, packet.dst_port, packet_protocols(packet))

    def matches_flow(self, flow: FlowSummary) -> bool:
        """Evaluate AND within one observed direction; OR may match any supplied field."""
        key = flow.key
        directions = (
            (key.endpoint_a, key.endpoint_b, key.port_a, key.port_b, flow.src_to_dst_packets),
            (key.endpoint_b, key.endpoint_a, key.port_b, key.port_a, flow.dst_to_src_packets),
        )
        for index, (src, dst, src_port, dst_port, packets) in enumerate(directions):
            if self.is_directional and not self.match_any and packets <= 0:
                continue
            protocols = flow_protocols(
                flow, index if self.is_directional and not self.match_any else None)
            if self._matches(src, dst, src_port, dst_port, protocols, observed=packets > 0):
                return True
        return False

    def _matches(self, src, dst, src_port, dst_port, protocols, *, observed=True):
        is_mac = bool(re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", src))

        def normalize(value):
            return value.lower() if is_mac and isinstance(value, str) else value

        src, dst = normalize(src), normalize(dst)
        hosts = tuple(normalize(v) for v in _values(self.host))
        peers = tuple(normalize(v) for v in _values(self.peer))
        checks = []
        if hosts:
            checks.append(src in hosts or dst in hosts)
        if peers:
            checks.append(src in peers or dst in peers)
        if hosts and peers and not self.match_any:
            checks.append((src in hosts and dst in peers) or (dst in hosts and src in peers))
        if _values(self.protocol):
            checks.append(any(canonical(v) in protocols for v in _values(self.protocol)))
        if _values(self.port):
            checks.append(src_port in _values(self.port) or dst_port in _values(self.port))
        for field, actual in (('src', src), ('dst', dst),
                              ('src_port', src_port), ('dst_port', dst_port)):
            wanted = tuple(normalize(v) for v in _values(getattr(self, field)))
            if wanted:
                checks.append(observed and actual in wanted)
        return (any(checks) if self.match_any else all(checks)) if checks else True


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
    seed_ids = {id(packet) for packet in seed_observations}

    for packet in observations:
        if id(packet) in seen_ids:
            continue
        if id(packet) in seed_ids or _matches_related_target(
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
