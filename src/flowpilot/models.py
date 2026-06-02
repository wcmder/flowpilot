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
    trace: list[dict[str, str | None]] = Field(default_factory=list)


class EspSequenceSummary(BaseModel):
    spi: str
    direction: str
    packet_count: int = 0
    first_sequence: int | None = None
    last_sequence: int | None = None
    highest_sequence: int | None = None
    largest_sequence_gap: int = 0
    gap_occurrences: list[dict[str, int]] = Field(default_factory=list)
    out_of_order_count: int = 0
    duplicate_count: int = 0
    seen_sequences: set[int] = Field(default_factory=set, exclude=True)

    @property
    def missing_count(self) -> int:
        if self.first_sequence is None or self.highest_sequence is None:
            return 0
        expected = self.highest_sequence - self.first_sequence + 1
        return max(expected - len(self.seen_sequences), 0)

    @property
    def has_anomalies(self) -> bool:
        return (
            self.missing_count > 0
            or self.out_of_order_count > 0
            or self.duplicate_count > 0
            or self.largest_sequence_gap > 0
        )

    def compact(self) -> dict[str, int | str | None]:
        return {
            "spi": self.spi,
            "direction": self.direction,
            "packets": self.packet_count,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "highest_sequence": self.highest_sequence,
            "missing_count": self.missing_count,
            "largest_sequence_gap": self.largest_sequence_gap,
            "gap_occurrences": self.gap_occurrences,
            "out_of_order_count": self.out_of_order_count,
            "duplicate_count": self.duplicate_count,
        }


class PacketObservation(BaseModel):
    timestamp: datetime | None = None
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "UNKNOWN"
    length: int = 0
    rtt_seconds: float | None = None
    initial_rtt_seconds: float | None = None
    issue_tags: list[str] = Field(default_factory=list)
    esp_spi: str | None = None
    esp_sequence: int | None = None
    dns_query: str | None = None
    dns_query_type: str | None = None
    dns_response_code: str | None = None
    dns_answers: list[str] = Field(default_factory=list)
    dhcp_message_type: str | None = None
    dhcp_transaction_id: str | None = None
    dhcp_client_mac: str | None = None
    dhcp_hostname: str | None = None
    dhcp_requested_ip: str | None = None
    dhcp_your_ip: str | None = None
    dhcp_server_id: str | None = None
    dhcp_lease_time: str | None = None
    http_host: str | None = None
    http_location: str | None = None
    tls_sni: str | None = None
    tls_alert_level: str | None = None
    tls_alert_description: str | None = None
    tls_certificates: list[TlsCertificateObservation] = Field(default_factory=list)
    sip_call_id: str | None = None
    sip_method: str | None = None
    sip_status_code: int | None = None
    sip_reason: str | None = None
    sip_from: str | None = None
    sip_to: str | None = None
    smb_command: str | None = None
    smb_commands_seen: list[str] = Field(default_factory=list)
    smb_status: str | None = None
    smb_message_id: str | None = None
    smb_is_response: bool | None = None
    smb_session_id: str | None = None
    smb_tree_id: str | None = None
    smb_file_id: str | None = None
    smb_filename: str | None = None
    smb_create_desired_access: int | None = None
    smb_create_file_attributes: int | None = None
    smb_read_length: int | None = None
    smb_write_length: int | None = None
    smb_file_offset: int | None = None
    smb_encrypted: bool = False
    smb_capabilities: list[str] = Field(default_factory=list)


class FlowKey(BaseModel, frozen=True):
    endpoint_a: str
    endpoint_b: str
    port_a: int | None = None
    port_b: int | None = None
    protocol: str = "UNKNOWN"

    @classmethod
    def from_packet(cls, packet: PacketObservation) -> FlowKey:
        if packet.dhcp_message_type or {packet.src_port, packet.dst_port} == {67, 68}:
            ports = sorted(port for port in (packet.src_port, packet.dst_port) if port is not None)
            return cls(
                endpoint_a=min(packet.src_ip, packet.dst_ip),
                endpoint_b=max(packet.src_ip, packet.dst_ip),
                port_a=ports[0] if ports else None,
                port_b=ports[-1] if ports else None,
                protocol=packet.protocol,
            )

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
    src_to_dst_bytes: int = 0
    dst_to_src_bytes: int = 0
    rtt_sample_count: int = 0
    rtt_total_ms: float = 0.0
    rtt_max_ms: float | None = None
    rtt_samples_ms: list[float] = Field(default_factory=list)
    initial_rtt_ms: float | None = None
    max_interarrival_ms: float | None = None
    issue_counts: dict[str, int] = Field(default_factory=dict)
    esp_spis: list[str] = Field(default_factory=list)
    esp_sequences: list[EspSequenceSummary] = Field(default_factory=list)
    redirect_locations: list[str] = Field(default_factory=list)
    tls_certificates: list[TlsCertificateObservation] = Field(default_factory=list)
    tls_snis: list[str] = Field(default_factory=list)
    tls_alerts: dict[str, int] = Field(default_factory=dict)
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
    smb_read_filenames: list[str] = Field(default_factory=list)
    smb_write_filenames: list[str] = Field(default_factory=list)
    smb_client_capabilities: list[str] = Field(default_factory=list)
    smb_server_capabilities: list[str] = Field(default_factory=list)
    smb_read_ops: int = 0
    smb_write_ops: int = 0
    smb_read_bytes: int = 0
    smb_write_bytes: int = 0
    smb_read_unknown_bytes_ops: int = 0
    smb_write_unknown_bytes_ops: int = 0
    smb_read_offset_inferred_ops: int = 0
    smb_write_offset_inferred_ops: int = 0
    smb_error_count: int = 0
    smb_encrypted_packets: int = 0
    smb_read_bytes_by_file: dict[str, int] = Field(default_factory=dict, exclude=True)
    smb_write_bytes_by_file: dict[str, int] = Field(default_factory=dict, exclude=True)
    smb_file_id_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    smb_pending_create_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    smb_file_id_read_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    smb_file_id_write_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    smb_pending_create_read_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    smb_pending_create_write_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    smb_counted_read_message_ids: set[str] = Field(default_factory=set, exclude=True)
    smb_counted_write_message_ids: set[str] = Field(default_factory=set, exclude=True)
    smb_last_read_offset_by_file: dict[str, int] = Field(default_factory=dict, exclude=True)
    smb_last_write_offset_by_file: dict[str, int] = Field(default_factory=dict, exclude=True)
    dns_queries: dict[str, int] = Field(default_factory=dict)
    dns_query_types: dict[str, int] = Field(default_factory=dict)
    dns_response_codes: dict[str, int] = Field(default_factory=dict)
    dns_answers: list[str] = Field(default_factory=list)
    dns_error_count: int = 0
    dhcp_message_types: dict[str, int] = Field(default_factory=dict)
    dhcp_transaction_ids: list[str] = Field(default_factory=list)
    dhcp_client_macs: list[str] = Field(default_factory=list)
    dhcp_hostnames: list[str] = Field(default_factory=list)
    dhcp_requested_ips: list[str] = Field(default_factory=list)
    dhcp_offered_ips: list[str] = Field(default_factory=list)
    dhcp_server_ids: list[str] = Field(default_factory=list)
    dhcp_lease_times: list[str] = Field(default_factory=list)
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
    def throughput_mbps(self) -> float:
        return (self.byte_rate_per_second * 8) / 1_000_000

    @property
    def retransmission_rate(self) -> float:
        if self.packet_count == 0:
            return 0.0
        retransmissions = self.issue_counts.get("tcp_retransmission", 0)
        return retransmissions / self.packet_count

    @property
    def packet_loss_rate(self) -> float:
        if self.packet_count == 0:
            return 0.0
        lost_segments = self.issue_counts.get("tcp_lost_segment", 0)
        return lost_segments / self.packet_count

    @property
    def avg_rtt_ms(self) -> float | None:
        if self.rtt_sample_count == 0:
            return None
        return self.rtt_total_ms / self.rtt_sample_count

    @property
    def median_rtt_ms(self) -> float | None:
        return _percentile(self.rtt_samples_ms, 0.5)

    @property
    def p95_rtt_ms(self) -> float | None:
        return _percentile(self.rtt_samples_ms, 0.95)

    @property
    def is_one_way(self) -> bool:
        return self.src_to_dst_packets == 0 or self.dst_to_src_packets == 0

    @property
    def diagnostic_hints(self) -> list[str]:
        hints = []
        if self.is_one_way and self.packet_count > 1:
            hints.append("one-way traffic observed")
        if self.duration_seconds >= 60 and self.throughput_mbps < 2:
            hints.append("low average throughput for long-lived flow")
        if self.retransmission_rate >= 0.01:
            hints.append("tcp retransmission rate above 1 percent")
        if self.issue_counts.get("tcp_zero_window", 0) > 0:
            hints.append("tcp receiver window pressure observed")
        if self.issue_counts.get("tcp_reset", 0) > 0:
            hints.append("tcp reset observed")
        if self.issue_counts.get("tls_fatal_alert", 0) > 0:
            hints.append("tls fatal alert observed")
        elif self.issue_counts.get("tls_alert", 0) > 0:
            hints.append("tls alert observed")
        if any(sequence.has_anomalies for sequence in self.esp_sequences):
            hints.append("esp sequence anomaly observed")
        if self.dns_error_count:
            hints.append("dns error responses observed")
        if self.dhcp_message_types and not _has_any_key(self.dhcp_message_types, {"ACK"}):
            hints.append("dhcp exchange lacks ack in observed packets")
        if self.key.protocol in {"ESP", "UDP"} and self.duration_seconds >= 60:
            hints.append("encrypted or datagram flow limits direct loss/latency proof")
        hints.extend(self.smb_diagnostic_hints)
        return hints

    @property
    def smb_transfer_bytes(self) -> int:
        return self.smb_read_bytes + self.smb_write_bytes

    @property
    def smb_transfer_mbps(self) -> float:
        duration = self.duration_seconds
        if duration <= 0:
            return 0.0
        return (self.smb_transfer_bytes * 8 / duration) / 1_000_000

    @property
    def smb_diagnostic_hints(self) -> list[str]:
        if not (
            self.smb_commands
            or self.smb_statuses
            or self.smb_filenames
            or self.smb_encrypted_packets
        ):
            return []

        hints = []
        if self.smb_encrypted_packets:
            hints.append(
                "smb encrypted transform traffic observed; "
                "filenames and read/write details are hidden"
            )
        total_ops = self.smb_read_ops + self.smb_write_ops
        if self.smb_error_count:
            hints.append("smb errors observed")
        if total_ops and self.smb_transfer_bytes:
            avg_size = self.smb_transfer_bytes / total_ops
            if avg_size < 64 * 1024:
                hints.append("small average smb read/write size")
        if self.duration_seconds >= 60 and self.smb_transfer_mbps < 10:
            hints.append("low smb transfer throughput for long-lived flow")
        if self.max_interarrival_ms is not None and self.max_interarrival_ms >= 1_000:
            hints.append("smb transfer stalls or idle gaps observed")
        return hints


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
            "analysis_focus": "network transport troubleshooting",
            "transport_metric_notes": {
                "loss": "tcp.analysis.lost_segment rate over observed flow packets",
                "rtt": (
                    "only tcp.analysis.initial_rtt is sent to LLM; tcp.analysis.ack_rtt "
                    "is capture-position dependent and excluded"
                ),
                "throughput": "observed bytes over first-to-last packet duration",
                "limitations": "absence of a metric does not prove absence of a problem",
            },
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
                    "src_to_dst_bytes": flow.src_to_dst_bytes,
                    "dst_to_src_bytes": flow.dst_to_src_bytes,
                    "duration_seconds": round(flow.duration_seconds, 3),
                    "packet_rate_per_second": round(flow.packet_rate_per_second, 3),
                    "byte_rate_per_second": round(flow.byte_rate_per_second, 3),
                    "throughput_mbps": round(flow.throughput_mbps, 3),
                    "retransmission_rate": round(flow.retransmission_rate, 4),
                    "packet_loss_rate": round(flow.packet_loss_rate, 4),
                    "initial_rtt_ms": _round_optional(flow.initial_rtt_ms, 3),
                    "one_way": flow.is_one_way,
                    "diagnostic_hints": flow.diagnostic_hints,
                    "issue_counts": flow.issue_counts,
                    "transport": {
                        "duration_seconds": round(flow.duration_seconds, 3),
                        "throughput_mbps": round(flow.throughput_mbps, 3),
                        "packet_rate_per_second": round(flow.packet_rate_per_second, 3),
                        "retransmission_rate": round(flow.retransmission_rate, 4),
                        "packet_loss_rate": round(flow.packet_loss_rate, 4),
                        "tcp_issue_counts": _tcp_issue_counts(flow.issue_counts),
                        "rtt": {
                            "initial_ms": _round_optional(flow.initial_rtt_ms, 3),
                            "ack_rtt_excluded": True,
                        },
                        "directionality": {
                            "src_to_dst_packets": flow.src_to_dst_packets,
                            "dst_to_src_packets": flow.dst_to_src_packets,
                            "src_to_dst_bytes": flow.src_to_dst_bytes,
                            "dst_to_src_bytes": flow.dst_to_src_bytes,
                            "one_way": flow.is_one_way,
                        },
                    },
                    "esp_spis": flow.esp_spis,
                    "esp_sequences": [
                        sequence.compact() for sequence in flow.esp_sequences
                    ],
                    "redirect_locations": flow.redirect_locations,
                    "tls_certificates": [
                        certificate.model_dump(mode="json")
                        for certificate in flow.tls_certificates
                    ],
                    "tls_snis": flow.tls_snis,
                    "tls_alerts": flow.tls_alerts,
                    "sip": {
                        "call_ids": flow.sip_call_ids,
                        "calls": [
                            call.model_dump(mode="json")
                            for call in flow.sip_calls.values()
                        ],
                        "methods": flow.sip_methods,
                        "statuses": flow.sip_statuses,
                        "participants": flow.sip_participants,
                    },
                    "smb": {
                        "commands": flow.smb_commands,
                        "statuses": flow.smb_statuses,
                        "session_ids": flow.smb_session_ids,
                        "tree_ids": flow.smb_tree_ids,
                        "filenames": flow.smb_filenames,
                        "read_filenames": flow.smb_read_filenames,
                        "write_filenames": flow.smb_write_filenames,
                        "read_bytes_by_file": flow.smb_read_bytes_by_file,
                        "write_bytes_by_file": flow.smb_write_bytes_by_file,
                        "client_capabilities": flow.smb_client_capabilities,
                        "server_capabilities": flow.smb_server_capabilities,
                        "read_ops": flow.smb_read_ops,
                        "write_ops": flow.smb_write_ops,
                        "read_bytes": flow.smb_read_bytes,
                        "write_bytes": flow.smb_write_bytes,
                        "read_unknown_bytes_ops": flow.smb_read_unknown_bytes_ops,
                        "write_unknown_bytes_ops": flow.smb_write_unknown_bytes_ops,
                        "read_offset_inferred_ops": flow.smb_read_offset_inferred_ops,
                        "write_offset_inferred_ops": flow.smb_write_offset_inferred_ops,
                        "transfer_bytes": flow.smb_transfer_bytes,
                        "transfer_mbps": round(flow.smb_transfer_mbps, 3),
                        "encrypted_packets": flow.smb_encrypted_packets,
                        "error_count": flow.smb_error_count,
                        "diagnostic_hints": flow.smb_diagnostic_hints,
                    },
                    "dns": {
                        "queries": flow.dns_queries,
                        "query_types": flow.dns_query_types,
                        "response_codes": flow.dns_response_codes,
                        "answers": flow.dns_answers,
                        "error_count": flow.dns_error_count,
                    },
                    "dhcp": {
                        "message_types": flow.dhcp_message_types,
                        "transaction_ids": flow.dhcp_transaction_ids,
                        "client_macs": flow.dhcp_client_macs,
                        "hostnames": flow.dhcp_hostnames,
                        "requested_ips": flow.dhcp_requested_ips,
                        "offered_ips": flow.dhcp_offered_ips,
                        "server_ids": flow.dhcp_server_ids,
                        "lease_times": flow.dhcp_lease_times,
                    },
                    "names": flow.names,
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


class EvidenceRequest(BaseModel):
    tool: str = Field(description="Allowed tool name such as deep_tcp_flow or deep_udp_flow.")
    flow_id: int | None = Field(default=None, description="Flow ID from the Top Flows table.")
    reason: str


class ReasoningReport(BaseModel):
    executive_summary: str
    risk_level: str
    findings: list[AnalysisFinding] = Field(default_factory=list)
    next_questions: list[str] = Field(default_factory=list)
    evidence_requests: list[EvidenceRequest] = Field(default_factory=list)


def counter_to_sorted_dict(counter: Counter[str], limit: int) -> dict[str, int]:
    return dict(counter.most_common(limit))


def _endpoint_sort_key(endpoint: tuple[str, int | None]) -> tuple[str, int]:
    ip, port = endpoint
    return ip, port if port is not None else -1


def _round_optional(value: float | None, digits: int) -> float | None:
    return round(value, digits) if value is not None else None


def _tcp_issue_counts(issue_counts: dict[str, int]) -> dict[str, int]:
    return {
        issue_name: count
        for issue_name, count in issue_counts.items()
        if issue_name.startswith("tcp_")
    }


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * percentile))
    return ordered[index]


def _has_any_key(values: dict[str, int], wanted: set[str]) -> bool:
    return any(any(item in key.upper() for item in wanted) for key in values)
