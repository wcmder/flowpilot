from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class TlsCertificateObservation(BaseModel):
    presenter_ip: str | None = None
    presenter_port: int | None = None
    presenter_role: str | None = None
    subject: str | None = None
    subject_cn: str | None = None
    issuer: str | None = None
    issuer_cn: str | None = None
    serial: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    san_dns: list[str] = Field(default_factory=list)
    fingerprint_sha256: str | None = None

    @property
    def summary_key(self) -> tuple[str | int | None, ...]:
        return (
            self.presenter_ip,
            self.presenter_port,
            self.subject,
            self.issuer,
            self.serial,
        )


class SipCallSummary(BaseModel):
    call_id: str
    caller: str | None = None
    callee: str | None = None
    methods: dict[str, int] = Field(default_factory=dict)
    statuses: dict[str, int] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)


class PacketObservation(BaseModel):
    timestamp: datetime | None = None
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "UNKNOWN"
    length: int = 0
    rtt_seconds: float | None = None
    issue_tags: list[str] = Field(default_factory=list)
    esp_spi: str | None = None
    dns_query: str | None = None
    dns_answers: list[str] = Field(default_factory=list)
    http_host: str | None = None
    http_location: str | None = None
    tls_sni: str | None = None
    tls_certificates: list[TlsCertificateObservation] = Field(default_factory=list)
    sip_call_id: str | None = None
    sip_method: str | None = None
    sip_status_code: int | None = None
    sip_reason: str | None = None
    sip_from: str | None = None
    sip_to: str | None = None
    smb_command: str | None = None
    smb_status: str | None = None
    smb_session_id: str | None = None
    smb_tree_id: str | None = None
    smb_filename: str | None = None


class FlowKey(BaseModel, frozen=True):
    endpoint_a: str
    endpoint_b: str
    port_a: int | None = None
    port_b: int | None = None
    protocol: str = "UNKNOWN"

    @classmethod
    def from_packet(cls, packet: PacketObservation) -> FlowKey:
        left = (packet.src_ip, packet.src_port)
        right = (packet.dst_ip, packet.dst_port)
        if _endpoint_sort_key(left) <= _endpoint_sort_key(right):
            endpoint_a, port_a = left
            endpoint_b, port_b = right
        else:
            endpoint_a, port_a = right
            endpoint_b, port_b = left
        return cls(
            endpoint_a=endpoint_a,
            endpoint_b=endpoint_b,
            port_a=port_a,
            port_b=port_b,
            protocol=packet.protocol,
        )


class FlowSummary(BaseModel):
    key: FlowKey
    packet_count: int = 0
    byte_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    src_to_dst_packets: int = 0
    dst_to_src_packets: int = 0
    rtt_sample_count: int = 0
    rtt_total_ms: float = 0.0
    rtt_max_ms: float | None = None
    max_interarrival_ms: float | None = None
    issue_counts: dict[str, int] = Field(default_factory=dict)
    esp_spis: list[str] = Field(default_factory=list)
    redirect_locations: list[str] = Field(default_factory=list)
    tls_certificates: list[TlsCertificateObservation] = Field(default_factory=list)
    sip_call_ids: list[str] = Field(default_factory=list)
    sip_calls: dict[str, SipCallSummary] = Field(default_factory=dict)
    sip_methods: dict[str, int] = Field(default_factory=dict)
    sip_statuses: dict[str, int] = Field(default_factory=dict)
    sip_participants: list[str] = Field(default_factory=list)
    smb_commands: dict[str, int] = Field(default_factory=dict)
    smb_statuses: dict[str, int] = Field(default_factory=dict)
    smb_session_ids: list[str] = Field(default_factory=list)
    smb_tree_ids: list[str] = Field(default_factory=list)
    smb_filenames: list[str] = Field(default_factory=list)
    names: list[str] = Field(default_factory=list)

    @property
    def duration_seconds(self) -> float:
        if not self.first_seen or not self.last_seen:
            return 0.0
        return max((self.last_seen - self.first_seen).total_seconds(), 0.0)

    @property
    def packet_rate_per_second(self) -> float:
        duration = self.duration_seconds
        if duration <= 0:
            return 0.0
        return self.packet_count / duration

    @property
    def byte_rate_per_second(self) -> float:
        duration = self.duration_seconds
        if duration <= 0:
            return 0.0
        return self.byte_count / duration

    @property
    def retransmission_rate(self) -> float:
        if self.packet_count == 0:
            return 0.0
        retransmissions = self.issue_counts.get("tcp_retransmission", 0)
        return retransmissions / self.packet_count

    @property
    def avg_rtt_ms(self) -> float | None:
        if self.rtt_sample_count == 0:
            return None
        return self.rtt_total_ms / self.rtt_sample_count

    @property
    def is_one_way(self) -> bool:
        return self.src_to_dst_packets == 0 or self.dst_to_src_packets == 0


class CaptureSummary(BaseModel):
    packet_count: int
    total_bytes: int
    flow_count: int
    protocols: dict[str, int]
    top_ports: dict[str, int]
    issue_counts: dict[str, int]
    names: list[str]
    flows: list[FlowSummary]

    def compact(self, max_flows: int = 25) -> dict[str, Any]:
        flows = sorted(self.flows, key=lambda flow: flow.byte_count, reverse=True)[:max_flows]
        return {
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "flow_count": self.flow_count,
            "protocols": self.protocols,
            "top_ports": self.top_ports,
            "observed_names": self.names[:50],
            "top_flows": [
                {
                    "protocol": flow.key.protocol,
                    "endpoint_a": flow.key.endpoint_a,
                    "port_a": flow.key.port_a,
                    "endpoint_b": flow.key.endpoint_b,
                    "port_b": flow.key.port_b,
                    "packets": flow.packet_count,
                    "bytes": flow.byte_count,
                    "src_to_dst_packets": flow.src_to_dst_packets,
                    "dst_to_src_packets": flow.dst_to_src_packets,
                    "duration_seconds": round(flow.duration_seconds, 3),
                    "packet_rate_per_second": round(flow.packet_rate_per_second, 3),
                    "byte_rate_per_second": round(flow.byte_rate_per_second, 3),
                    "retransmission_rate": round(flow.retransmission_rate, 4),
                    "avg_rtt_ms": _round_optional(flow.avg_rtt_ms, 3),
                    "max_rtt_ms": _round_optional(flow.rtt_max_ms, 3),
                    "max_interarrival_ms": _round_optional(flow.max_interarrival_ms, 3),
                    "one_way": flow.is_one_way,
                    "issue_counts": flow.issue_counts,
                    "esp_spis": flow.esp_spis[:10],
                    "redirect_locations": flow.redirect_locations[:10],
                    "tls_certificates": [
                        certificate.model_dump(mode="json")
                        for certificate in flow.tls_certificates[:5]
                    ],
                    "sip": {
                        "call_ids": flow.sip_call_ids[:10],
                        "calls": [
                            call.model_dump(mode="json")
                            for call in list(flow.sip_calls.values())[:10]
                        ],
                        "methods": flow.sip_methods,
                        "statuses": flow.sip_statuses,
                        "participants": flow.sip_participants[:10],
                    },
                    "smb": {
                        "commands": flow.smb_commands,
                        "statuses": flow.smb_statuses,
                        "session_ids": flow.smb_session_ids[:10],
                        "tree_ids": flow.smb_tree_ids[:10],
                        "filenames": flow.smb_filenames[:10],
                    },
                    "names": flow.names[:10],
                }
                for flow in flows
            ],
            "issue_counts": self.issue_counts,
        }


class AnalysisFinding(BaseModel):
    severity: str = Field(description="informational, low, medium, high, or critical")
    title: str
    evidence: list[str] = Field(default_factory=list)
    hypothesis: str
    recommended_action: str


class ReasoningReport(BaseModel):
    executive_summary: str
    risk_level: str
    findings: list[AnalysisFinding] = Field(default_factory=list)
    next_questions: list[str] = Field(default_factory=list)


def counter_to_sorted_dict(counter: Counter[str], limit: int) -> dict[str, int]:
    return dict(counter.most_common(limit))


def _endpoint_sort_key(endpoint: tuple[str, int | None]) -> tuple[str, int]:
    ip, port = endpoint
    return ip, port if port is not None else -1


def _round_optional(value: float | None, digits: int) -> float | None:
    return round(value, digits) if value is not None else None
