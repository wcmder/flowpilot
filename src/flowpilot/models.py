from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, model_validator

LONG_LIVED_FLOW_SECONDS = 180


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
    def observed_unique_sequence_count(self) -> int:
        if self.seen_sequences:
            return len(self.seen_sequences)
        return max(self.packet_count - self.duplicate_count, 0)

    @property
    def expected_sequence_count(self) -> int:
        if self.first_sequence is None or self.highest_sequence is None:
            return 0
        return max(self.highest_sequence - self.first_sequence + 1, 0)

    @property
    def missing_count(self) -> int:
        return max(self.expected_sequence_count - self.observed_unique_sequence_count, 0)

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


class EspFlowMetadata(BaseModel):
    spis: list[str] = Field(default_factory=list)
    sequences: list[EspSequenceSummary] = Field(default_factory=list)


class TlsFlowMetadata(BaseModel):
    certificates: list[TlsCertificateObservation] = Field(default_factory=list)
    snis: list[str] = Field(default_factory=list)
    sni_endpoints: dict[str, list[str]] = Field(default_factory=dict)
    alerts: dict[str, int] = Field(default_factory=dict)
    alert_endpoints: dict[str, dict[str, int]] = Field(default_factory=dict)


class SipFlowMetadata(BaseModel):
    call_ids: list[str] = Field(default_factory=list)
    calls: dict[str, SipCallSummary] = Field(default_factory=dict)
    methods: dict[str, int] = Field(default_factory=dict)
    statuses: dict[str, int] = Field(default_factory=dict)
    participants: list[str] = Field(default_factory=list)


class SmbFlowMetadata(BaseModel):
    commands: dict[str, int] = Field(default_factory=dict)
    statuses: dict[str, int] = Field(default_factory=dict)
    session_ids: list[str] = Field(default_factory=list)
    tree_ids: list[str] = Field(default_factory=list)
    filenames: list[str] = Field(default_factory=list)
    read_filenames: list[str] = Field(default_factory=list)
    write_filenames: list[str] = Field(default_factory=list)
    client_capabilities: list[str] = Field(default_factory=list)
    server_capabilities: list[str] = Field(default_factory=list)
    read_ops: int = 0
    write_ops: int = 0
    read_bytes: int = 0
    write_bytes: int = 0
    read_unknown_bytes_ops: int = 0
    write_unknown_bytes_ops: int = 0
    read_offset_inferred_ops: int = 0
    write_offset_inferred_ops: int = 0
    error_count: int = 0
    encrypted_packets: int = 0
    read_bytes_by_file: dict[str, int] = Field(default_factory=dict)
    write_bytes_by_file: dict[str, int] = Field(default_factory=dict)
    file_id_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    pending_create_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    file_id_read_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    file_id_write_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    pending_create_read_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    pending_create_write_names: dict[str, str] = Field(default_factory=dict, exclude=True)
    counted_read_message_ids: set[str] = Field(default_factory=set, exclude=True)
    counted_write_message_ids: set[str] = Field(default_factory=set, exclude=True)
    last_read_offset_by_file: dict[str, int] = Field(default_factory=dict, exclude=True)
    last_write_offset_by_file: dict[str, int] = Field(default_factory=dict, exclude=True)


class DnsFlowMetadata(BaseModel):
    queries: dict[str, int] = Field(default_factory=dict)
    query_types: dict[str, int] = Field(default_factory=dict)
    response_codes: dict[str, int] = Field(default_factory=dict)
    answers: list[str] = Field(default_factory=list)
    error_count: int = 0


class DhcpFlowMetadata(BaseModel):
    message_types: dict[str, int] = Field(default_factory=dict)
    transaction_ids: list[str] = Field(default_factory=list)
    client_macs: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    requested_ips: list[str] = Field(default_factory=list)
    offered_ips: list[str] = Field(default_factory=list)
    server_ids: list[str] = Field(default_factory=list)
    lease_times: list[str] = Field(default_factory=list)


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


_ESP_FLOW_ALIASES = {
    "esp_spis": "spis",
    "esp_sequences": "sequences",
}

_TLS_FLOW_ALIASES = {
    "tls_certificates": "certificates",
    "tls_snis": "snis",
    "tls_sni_endpoints": "sni_endpoints",
    "tls_alerts": "alerts",
    "tls_alert_endpoints": "alert_endpoints",
}

_SIP_FLOW_ALIASES = {
    "sip_call_ids": "call_ids",
    "sip_calls": "calls",
    "sip_methods": "methods",
    "sip_statuses": "statuses",
    "sip_participants": "participants",
}

_SMB_FLOW_ALIASES = {
    "smb_commands": "commands",
    "smb_statuses": "statuses",
    "smb_session_ids": "session_ids",
    "smb_tree_ids": "tree_ids",
    "smb_filenames": "filenames",
    "smb_read_filenames": "read_filenames",
    "smb_write_filenames": "write_filenames",
    "smb_client_capabilities": "client_capabilities",
    "smb_server_capabilities": "server_capabilities",
    "smb_read_ops": "read_ops",
    "smb_write_ops": "write_ops",
    "smb_read_bytes": "read_bytes",
    "smb_write_bytes": "write_bytes",
    "smb_read_unknown_bytes_ops": "read_unknown_bytes_ops",
    "smb_write_unknown_bytes_ops": "write_unknown_bytes_ops",
    "smb_read_offset_inferred_ops": "read_offset_inferred_ops",
    "smb_write_offset_inferred_ops": "write_offset_inferred_ops",
    "smb_error_count": "error_count",
    "smb_encrypted_packets": "encrypted_packets",
    "smb_read_bytes_by_file": "read_bytes_by_file",
    "smb_write_bytes_by_file": "write_bytes_by_file",
    "smb_file_id_names": "file_id_names",
    "smb_pending_create_names": "pending_create_names",
    "smb_file_id_read_names": "file_id_read_names",
    "smb_file_id_write_names": "file_id_write_names",
    "smb_pending_create_read_names": "pending_create_read_names",
    "smb_pending_create_write_names": "pending_create_write_names",
    "smb_counted_read_message_ids": "counted_read_message_ids",
    "smb_counted_write_message_ids": "counted_write_message_ids",
    "smb_last_read_offset_by_file": "last_read_offset_by_file",
    "smb_last_write_offset_by_file": "last_write_offset_by_file",
}

_DNS_FLOW_ALIASES = {
    "dns_queries": "queries",
    "dns_query_types": "query_types",
    "dns_response_codes": "response_codes",
    "dns_answers": "answers",
    "dns_error_count": "error_count",
}

_DHCP_FLOW_ALIASES = {
    "dhcp_message_types": "message_types",
    "dhcp_transaction_ids": "transaction_ids",
    "dhcp_client_macs": "client_macs",
    "dhcp_hostnames": "hostnames",
    "dhcp_requested_ips": "requested_ips",
    "dhcp_offered_ips": "offered_ips",
    "dhcp_server_ids": "server_ids",
    "dhcp_lease_times": "lease_times",
}

_FLOW_PROTOCOL_ALIASES = {
    **{legacy: ("esp", nested) for legacy, nested in _ESP_FLOW_ALIASES.items()},
    **{legacy: ("tls", nested) for legacy, nested in _TLS_FLOW_ALIASES.items()},
    **{legacy: ("sip", nested) for legacy, nested in _SIP_FLOW_ALIASES.items()},
    **{legacy: ("smb", nested) for legacy, nested in _SMB_FLOW_ALIASES.items()},
    **{legacy: ("dns", nested) for legacy, nested in _DNS_FLOW_ALIASES.items()},
    **{legacy: ("dhcp", nested) for legacy, nested in _DHCP_FLOW_ALIASES.items()},
}


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
    src_to_dst_issue_counts: dict[str, int] = Field(default_factory=dict)
    dst_to_src_issue_counts: dict[str, int] = Field(default_factory=dict)
    rtt_sample_count: int = 0
    rtt_total_ms: float = 0.0
    rtt_max_ms: float | None = None
    rtt_samples_ms: list[float] = Field(default_factory=list)
    initial_rtt_ms: float | None = None
    max_interarrival_ms: float | None = None
    issue_counts: dict[str, int] = Field(default_factory=dict)
    redirect_locations: list[str] = Field(default_factory=list)
    esp: EspFlowMetadata = Field(default_factory=EspFlowMetadata)
    tls: TlsFlowMetadata = Field(default_factory=TlsFlowMetadata)
    sip: SipFlowMetadata = Field(default_factory=SipFlowMetadata)
    smb: SmbFlowMetadata = Field(default_factory=SmbFlowMetadata)
    dns: DnsFlowMetadata = Field(default_factory=DnsFlowMetadata)
    dhcp: DhcpFlowMetadata = Field(default_factory=DhcpFlowMetadata)
    names: list[str] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _migrate_legacy_protocol_fields(cls, data):
        if not isinstance(data, dict):
            return data
        data = dict(data)
        _move_legacy_fields(data, "esp", _ESP_FLOW_ALIASES)
        _move_legacy_fields(data, "tls", _TLS_FLOW_ALIASES)
        _move_legacy_fields(data, "sip", _SIP_FLOW_ALIASES)
        _move_legacy_fields(data, "smb", _SMB_FLOW_ALIASES)
        _move_legacy_fields(data, "dns", _DNS_FLOW_ALIASES)
        _move_legacy_fields(data, "dhcp", _DHCP_FLOW_ALIASES)
        return data

    def __getattr__(self, name: str):
        if name in _FLOW_PROTOCOL_ALIASES:
            protocol_field, nested_field = _FLOW_PROTOCOL_ALIASES[name]
            return getattr(getattr(self, protocol_field), nested_field)
        return super().__getattr__(name)

    def __setattr__(self, name: str, value) -> None:
        if name in _FLOW_PROTOCOL_ALIASES:
            protocol_field, nested_field = _FLOW_PROTOCOL_ALIASES[name]
            setattr(getattr(self, protocol_field), nested_field, value)
            return
        super().__setattr__(name, value)

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
    def packet_rate_per_second_by_direction(self) -> tuple[float | None, float | None]:
        """Observed A→B and B→A packets/s over the full-flow interval."""
        duration = self.duration_seconds
        if duration <= 0:
            return (None, None)
        return (self.src_to_dst_packets / duration, self.dst_to_src_packets / duration)

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
    def throughput_mbps_by_direction(self) -> tuple[float | None, float | None]:
        """Observed A→B and B→A Mbps over the same full-flow interval."""
        duration = self.duration_seconds
        if duration <= 0:
            return (None, None)
        return (
            self.src_to_dst_bytes * 8 / duration / 1_000_000,
            self.dst_to_src_bytes * 8 / duration / 1_000_000,
        )

    @property
    def retransmission_rate(self) -> float:
        if self.packet_count == 0:
            return 0.0
        retransmissions = self.issue_counts.get("tcp_retransmission", 0)
        return retransmissions / self.packet_count

    @property
    def retransmission_rates_by_direction(self) -> tuple[float, float]:
        return (
            _rate(
                self.src_to_dst_issue_counts.get("tcp_retransmission", 0),
                self.src_to_dst_packets,
            ),
            _rate(
                self.dst_to_src_issue_counts.get("tcp_retransmission", 0),
                self.dst_to_src_packets,
            ),
        )

    @property
    def packet_loss_rate(self) -> float:
        if self.packet_count == 0:
            return 0.0
        if self.key.protocol == "ESP" and self.esp_sequences:
            missing_sequences = sum(sequence.missing_count for sequence in self.esp_sequences)
            expected_sequences = sum(
                sequence.observed_unique_sequence_count + sequence.missing_count
                for sequence in self.esp_sequences
            )
            if expected_sequences > 0:
                return missing_sequences / expected_sequences
        lost_segments = self.issue_counts.get("tcp_lost_segment", 0)
        return lost_segments / self.packet_count

    @property
    def packet_loss_rates_by_direction(self) -> tuple[float, float]:
        if self.key.protocol == "ESP" and self.esp_sequences:
            return (
                self._esp_loss_rate_for_direction(forward=True),
                self._esp_loss_rate_for_direction(forward=False),
            )
        return (
            _rate(
                self.src_to_dst_issue_counts.get("tcp_lost_segment", 0),
                self.src_to_dst_packets,
            ),
            _rate(
                self.dst_to_src_issue_counts.get("tcp_lost_segment", 0),
                self.dst_to_src_packets,
            ),
        )

    @property
    def out_of_order_count(self) -> int:
        if self.key.protocol == "ESP" and self.esp_sequences:
            return sum(sequence.out_of_order_count for sequence in self.esp_sequences)
        return self.issue_counts.get("tcp_out_of_order", 0)

    @property
    def out_of_order_rate(self) -> float:
        if self.packet_count == 0:
            return 0.0
        return self.out_of_order_count / self.packet_count

    @property
    def out_of_order_rates_by_direction(self) -> tuple[float, float]:
        if self.key.protocol == "ESP" and self.esp_sequences:
            return (
                self._esp_out_of_order_rate_for_direction(forward=True),
                self._esp_out_of_order_rate_for_direction(forward=False),
            )
        return (
            _rate(
                self.src_to_dst_issue_counts.get("tcp_out_of_order", 0),
                self.src_to_dst_packets,
            ),
            _rate(
                self.dst_to_src_issue_counts.get("tcp_out_of_order", 0),
                self.dst_to_src_packets,
            ),
        )

    def _esp_loss_rate_for_direction(self, *, forward: bool) -> float:
        sequences = self._esp_sequences_for_flow_direction(forward=forward)
        missing_sequences = sum(sequence.missing_count for sequence in sequences)
        expected_sequences = sum(
            sequence.observed_unique_sequence_count + sequence.missing_count
            for sequence in sequences
        )
        return _rate(missing_sequences, expected_sequences)

    def _esp_out_of_order_rate_for_direction(self, *, forward: bool) -> float:
        sequences = self._esp_sequences_for_flow_direction(forward=forward)
        packets = sum(sequence.packet_count for sequence in sequences)
        out_of_order = sum(sequence.out_of_order_count for sequence in sequences)
        return _rate(out_of_order, packets)

    def _esp_sequences_for_flow_direction(self, *, forward: bool) -> list[EspSequenceSummary]:
        expected = _direction_label(
            self.key.endpoint_a if forward else self.key.endpoint_b,
            self.key.port_a if forward else self.key.port_b,
            self.key.endpoint_b if forward else self.key.endpoint_a,
            self.key.port_b if forward else self.key.port_a,
        )
        return [sequence for sequence in self.esp_sequences if sequence.direction == expected]

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
        if self.duration_seconds >= LONG_LIVED_FLOW_SECONDS and self.throughput_mbps < 2:
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
        if (
            self.key.protocol in {"ESP", "UDP"}
            and self.duration_seconds >= LONG_LIVED_FLOW_SECONDS
        ):
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
        if self.duration_seconds >= LONG_LIVED_FLOW_SECONDS and self.smb_transfer_mbps < 10:
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
                "loss": (
                    "TCP uses tcp.analysis.lost_segment rate over observed flow packets; "
                    "ESP uses missing sequence numbers over expected ESP sequence span"
                ),
                "out_of_order": (
                    "TCP uses tcp.analysis.out_of_order rate over observed flow packets; "
                    "ESP uses captured-late ESP sequence numbers over observed flow packets"
                ),
                "directional_rates": (
                    "rate lists are [endpoint_a_to_endpoint_b, endpoint_b_to_endpoint_a]. "
                    "packet_rate_per_second_by_direction uses directional packet counts "
                    "divided by full-flow duration_seconds (packets/s). "
                    "Null means duration is unavailable or zero."
                ),
                "rtt": (
                    "only tcp.analysis.initial_rtt is sent to LLM; tcp.analysis.ack_rtt "
                    "is capture-position dependent and excluded"
                ),
                "throughput": "observed bytes over first-to-last packet duration",
                "directional_throughput": (
                    "throughput_mbps_by_direction is [A_to_B, B_to_A], where A is "
                    "endpoint_a and B is endpoint_b; each uses directional observed "
                    "bytes * 8 / full-flow duration_seconds / 1,000,000 (Mbps). "
                    "Null means duration is unavailable or zero. ESP rates measure "
                    "observed encrypted traffic, not inner application goodput."
                ),
                "limitations": "absence of a metric does not prove absence of a problem",
            },
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "flow_count": self.flow_count,
            "protocols": self.protocols,
            "top_ports": self.top_ports,
            "observed_names": self.names[:50],
            "flow_endpoint_inventory": _flow_endpoint_inventory(flows),
            "top_flows": [
                {
                    "flow_id": flow_id,
                    "flow_label": _flow_label(flow),
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
                    "src_to_dst_issue_counts": flow.src_to_dst_issue_counts,
                    "dst_to_src_issue_counts": flow.dst_to_src_issue_counts,
                    "duration_seconds": round(flow.duration_seconds, 3),
                    "packet_rate_per_second_by_direction": list(
                        flow.packet_rate_per_second_by_direction
                    ),
                    "throughput_mbps_by_direction": list(flow.throughput_mbps_by_direction),
                    "retransmission_rate": round(flow.retransmission_rate, 4),
                    "packet_loss_rate": round(flow.packet_loss_rate, 4),
                    "out_of_order_rate": round(flow.out_of_order_rate, 4),
                    "out_of_order_count": flow.out_of_order_count,
                    "initial_rtt_ms": _round_optional(flow.initial_rtt_ms, 3),
                    "one_way": flow.is_one_way,
                    "diagnostic_hints": flow.diagnostic_hints,
                    "issue_counts": flow.issue_counts,
                    "transport": {
                        "duration_seconds": round(flow.duration_seconds, 3),
                        "throughput_mbps_by_direction": list(flow.throughput_mbps_by_direction),
                        "packet_rate_per_second_by_direction": list(
                            flow.packet_rate_per_second_by_direction
                        ),
                        "retransmission_rate": round(flow.retransmission_rate, 4),
                        "retransmission_rates_by_direction": [
                            round(rate, 4) for rate in flow.retransmission_rates_by_direction
                        ],
                        "packet_loss_rate": round(flow.packet_loss_rate, 4),
                        "packet_loss_rates_by_direction": [
                            round(rate, 4) for rate in flow.packet_loss_rates_by_direction
                        ],
                        "out_of_order_rate": round(flow.out_of_order_rate, 4),
                        "out_of_order_rates_by_direction": [
                            round(rate, 4) for rate in flow.out_of_order_rates_by_direction
                        ],
                        "out_of_order_count": flow.out_of_order_count,
                        "tcp_issue_counts": _tcp_issue_counts(flow.issue_counts),
                        "rtt": {
                            "initial_ms": _round_optional(flow.initial_rtt_ms, 3),
                            "ack_rtt_excluded": True,
                            "assessment": (
                                "Initial TCP handshake RTT is available; compare with the "
                                "expected path baseline before calling it excessive. It does "
                                "not measure ongoing or application latency."
                                if flow.initial_rtt_ms is not None else
                                "No direct RTT measurement in this summary. Latency cannot "
                                "be established from throughput, duration, sequence gaps, "
                                "or packet spacing alone."
                            ),
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
                    "tls_sni_endpoints": flow.tls_sni_endpoints,
                    "tls_alerts": flow.tls_alerts,
                    "tls_alert_endpoints": flow.tls_alert_endpoints,
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
                for flow_id, flow in enumerate(flows, start=1)
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
    tool: str = Field(
        description=(
            "Allowed deep tool name from the FlowPilot protocol registry."
        )
    )
    flow_id: int | None = Field(
        default=None,
        description="Flow ID from the Top Flows table. Flow IDs start at 1.",
    )
    reason: str


class ReasoningReport(BaseModel):
    executive_summary: str
    risk_level: str
    findings: list[AnalysisFinding] = Field(default_factory=list)
    next_questions: list[str] = Field(default_factory=list)
    evidence_requests: list[EvidenceRequest] = Field(default_factory=list)


class AgentChatResponse(BaseModel):
    answer: str
    evidence_requests: list[EvidenceRequest] = Field(default_factory=list)


def counter_to_sorted_dict(counter: Counter[str], limit: int) -> dict[str, int]:
    return dict(counter.most_common(limit))


def _flow_label(flow: FlowSummary) -> str:
    return (
        f"{flow.key.protocol} "
        f"{_endpoint_label(flow.key.endpoint_a, flow.key.port_a)} <-> "
        f"{_endpoint_label(flow.key.endpoint_b, flow.key.port_b)}"
    )


def _endpoint_label(endpoint: str, port: int | None) -> str:
    return endpoint if port is None else f"{endpoint}:{port}"


def _direction_label(
    src_endpoint: str,
    src_port: int | None,
    dst_endpoint: str,
    dst_port: int | None,
) -> str:
    return f"{_endpoint_label(src_endpoint, src_port)} -> {_endpoint_label(dst_endpoint, dst_port)}"


def _flow_endpoint_inventory(flows: list[FlowSummary]) -> dict[str, list[str]]:
    endpoints: set[str] = set()
    endpoint_ports: set[str] = set()
    flow_labels: list[str] = []
    for flow in flows:
        endpoints.add(flow.key.endpoint_a)
        endpoints.add(flow.key.endpoint_b)
        endpoint_ports.add(_endpoint_label(flow.key.endpoint_a, flow.key.port_a))
        endpoint_ports.add(_endpoint_label(flow.key.endpoint_b, flow.key.port_b))
        flow_labels.append(_flow_label(flow))
    return {
        "endpoints": sorted(endpoints),
        "endpoint_ports": sorted(endpoint_ports),
        "flow_labels": flow_labels,
    }


def _endpoint_sort_key(endpoint: tuple[str, int | None]) -> tuple[str, int]:
    ip, port = endpoint
    return ip, port if port is not None else -1


def _round_optional(value: float | None, digits: int) -> float | None:
    return round(value, digits) if value is not None else None


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


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


def _move_legacy_fields(data: dict, protocol_field: str, aliases: dict[str, str]) -> None:
    protocol_data = dict(data.get(protocol_field) or {})
    for legacy_field, nested_field in aliases.items():
        if legacy_field in data:
            protocol_data[nested_field] = data.pop(legacy_field)
    if protocol_data:
        data[protocol_field] = protocol_data
