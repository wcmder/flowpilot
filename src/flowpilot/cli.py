from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .analysis import summarize_capture
from .capture import read_capture
from .dhcp import has_dhcp_ack
from .dns import dns_issue_summary
from .esp import format_esp_sequences
from .filters import (
    FlowFilter,
    filter_observations,
    filter_sip_calls_by_phone,
    include_redirect_related_flows,
)
from .reasoning import DEFAULT_MODEL, chat_about_capture, list_openai_models, reason_about_capture
from .sip import format_sip_trace
from .smb import SMB1_COMMAND_NAMES, SMB_STATUS_NAMES, smb_display_value

app = typer.Typer(help="Agentic packet data-flow analysis with PyShark and OpenAI.")
console = Console()
SMB_TRANSFER_FILE_MIN_BYTES = 1_048_576


@app.callback()
def main() -> None:
    """FlowPilot command line interface."""


@app.command()
def analyze(
    capture_path: Annotated[Path, typer.Argument(help="Path to a .pcap or .pcapng file.")],
    model: Annotated[str, typer.Option(help="OpenAI model for reasoning.")] = DEFAULT_MODEL,
    packet_limit: Annotated[
        int | None, typer.Option(help="Maximum packets to read from the capture.")
    ] = None,
    tls_keylog_file: Annotated[
        Path | None,
        typer.Option(help="TLS key log file for TShark decryption, usually SSLKEYLOGFILE output."),
    ] = None,
    host: Annotated[
        str | None, typer.Option(help="Only include packets where this IP is either endpoint.")
    ] = None,
    peer: Annotated[
        str | None,
        typer.Option(help="Use with --host to isolate traffic between two endpoints."),
    ] = None,
    protocol: Annotated[
        str | None, typer.Option(help="Only include this protocol, for example tcp, udp, esp.")
    ] = None,
    port: Annotated[
        int | None, typer.Option(help="Only include packets where this TCP/UDP port appears.")
    ] = None,
    src: Annotated[
        str | None, typer.Option(help="Only include packets from this source IP.")
    ] = None,
    dst: Annotated[
        str | None, typer.Option(help="Only include packets to this destination IP.")
    ] = None,
    src_port: Annotated[
        int | None, typer.Option(help="Only include packets from this TCP/UDP source port.")
    ] = None,
    dst_port: Annotated[
        int | None, typer.Option(help="Only include packets to this TCP/UDP destination port.")
    ] = None,
    include_redirects: Annotated[
        bool,
        typer.Option(
            help=(
                "When filters are used, include follow-on flows for decrypted HTTP redirect "
                "Location targets."
            )
        ),
    ] = False,
    sip_phone: Annotated[
        str | None,
        typer.Option(
            help=(
                "Only include SIP calls where caller or callee contains this full or partial "
                "phone number. Keeps the full matching Call-ID trace."
            )
        ),
    ] = None,
    max_flows: Annotated[int, typer.Option(help="Maximum top flows sent to the model.")] = 25,
    show_flows: Annotated[int, typer.Option(help="Maximum flows shown in the terminal.")] = 10,
    no_llm: Annotated[bool, typer.Option(help="Only print the local flow summary.")] = False,
    chat: Annotated[
        bool,
        typer.Option(help="After LLM reasoning, open an interactive follow-up chat."),
    ] = False,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Write a JSON report to this path.")
    ] = None,
) -> None:
    """Analyze a packet capture."""
    if chat and no_llm:
        raise typer.BadParameter(
            "--chat requires LLM reasoning, so it cannot be used with --no-llm."
        )

    total_packets = _capture_packet_count(capture_path)
    if packet_limit is not None and total_packets is not None:
        total_packets = min(total_packets, packet_limit)
    _info(_local_analysis_start_message(capture_path, total_packets))
    progress = _progress_reporter(total_packets)
    observations = read_capture(
        capture_path,
        packet_limit=packet_limit,
        tls_keylog_file=tls_keylog_file,
        progress_callback=progress,
    )
    observations = _materialize_observations(observations)
    _info(
        _packet_read_complete_message(
            pyshark_packets=progress.packet_count,
            analyzable_packets=len(observations),
            total_packets=total_packets,
        )
    )
    flow_filter = FlowFilter(
        host=host,
        peer=peer,
        protocol=protocol,
        port=port,
        src=src,
        dst=dst,
        src_port=src_port,
        dst_port=dst_port,
    )
    if flow_filter.is_active and include_redirects:
        _info("Applying flow filters and redirect expansion.")
        seed_observations = list(filter_observations(observations, flow_filter))
        observations = include_redirect_related_flows(observations, seed_observations)
    elif flow_filter.is_active:
        _info("Applying flow filters.")
        observations = list(filter_observations(observations, flow_filter))
    if sip_phone:
        _info("Applying SIP phone filter.")
        observations = filter_sip_calls_by_phone(observations, sip_phone)

    _info(f"Summarizing local metadata from {len(observations)} analyzable packets.")
    summary = summarize_capture(observations)
    _info(
        "Local analysis finished: "
        f"{summary.packet_count} analyzable packets, "
        f"{summary.flow_count} flows, {summary.total_bytes} bytes."
    )
    _info("Rendering local analysis tables.")
    _render_summary(summary, show_flows=show_flows)
    if no_llm:
        _info("LLM reasoning skipped because --no-llm was set.")
        report = None
    else:
        _info(
            "Sending derived metadata to LLM: "
            f"model={model}, top_flows={min(summary.flow_count, max_flows)}. "
            "Raw packet payloads are not sent."
        )
        llm_started_at = time.perf_counter()
        report = reason_about_capture(summary, model=model, max_flows=max_flows)
        llm_elapsed = time.perf_counter() - llm_started_at
        _info(f"LLM reasoning finished in {llm_elapsed:.2f}s.")

    if report:
        _render_reasoning(report)

    if json_path:
        payload = {"summary": summary.model_dump(mode="json")}
        if report:
            payload["reasoning"] = report.model_dump(mode="json")
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]Wrote JSON report:[/green] {json_path}")

    if chat and report:
        _run_chat(summary, report=report, model=model, max_flows=max_flows)


@app.command("models")
def models_command(
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Print raw model list as JSON."),
    ] = False,
) -> None:
    """List models from the configured OpenAI-compatible /v1/models endpoint."""
    models = list_openai_models()
    if json_output:
        console.print(json.dumps(models, indent=2))
        return

    table = Table(title="Configured LLM Models")
    table.add_column("Model ID")
    table.add_column("Owner")
    table.add_column("Created", justify="right")
    for model in models:
        table.add_row(
            str(model["id"]),
            str(model["owned_by"] or "-"),
            str(model["created"] or "-"),
        )
    console.print(table)


def _render_summary(summary, *, show_flows: int) -> None:
    console.print(
        Panel.fit(
            f"Packets: {summary.packet_count}\n"
            f"Bytes: {summary.total_bytes}\n"
            f"Flows: {summary.flow_count}",
            title="FlowPilot Summary",
        )
    )

    table = Table(title="Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Flow")
    table.add_column("Traffic", justify="right")
    table.add_column("Direction")
    table.add_column("Metrics")
    table.add_column("Protocol")
    table.add_column("Issues")

    flow_ids = _flow_ids(summary.flows)
    for flow in summary.flows[:show_flows]:
        table.add_row(
            str(flow_ids[flow.key]),
            (
                f"{flow.key.protocol} "
                f"{_endpoint(flow.key.endpoint_a, flow.key.port_a)} <-> "
                f"{_endpoint(flow.key.endpoint_b, flow.key.port_b)}"
            ),
            f"{flow.packet_count} pkts\n{flow.byte_count} bytes",
            _direction(flow),
            "\n".join(
                [
                    f"rtx {_percent(flow.retransmission_rate)}",
                    f"rtt {_rtt(flow)}",
                    f"rate {flow.packet_rate_per_second:.1f} pps",
                    f"thr {flow.throughput_mbps:.3f} Mbps",
                ]
            ),
            _protocol_marker(flow),
            _format_flow_issues(flow),
        )
    console.print(table)
    _render_dns_details(summary, show_flows=show_flows)
    _render_dhcp_details(summary, show_flows=show_flows)
    _render_sip_details(summary, show_flows=show_flows)
    _render_smb_details(summary, show_flows=show_flows)
    _render_tls_certificates(summary, show_flows=show_flows)


def _info(message: str) -> None:
    console.print(f"[cyan][info][/cyan] {message}")


def _materialize_observations(observations) -> list:
    return list(observations)


def _local_analysis_start_message(capture_path: Path, total_packets: int | None) -> str:
    message = f"Local analysis started: reading {capture_path}"
    if total_packets is not None:
        message += f" ({total_packets} packets)"
    return f"{message}."


def _packet_read_complete_message(
    *,
    pyshark_packets: int,
    analyzable_packets: int,
    total_packets: int | None,
) -> str:
    skipped = max(pyshark_packets - analyzable_packets, 0)
    if total_packets is not None:
        return (
            "Packet reading complete: "
            f"{total_packets} packets reported by capinfos, "
            f"{pyshark_packets} packets yielded by PyShark, "
            f"{analyzable_packets} analyzable packets extracted, "
            f"{skipped} yielded packets skipped."
        )
    return (
        "Packet reading complete: "
        "pcap packet total unavailable because capinfos was not found or could not read it, "
        f"{pyshark_packets} packets yielded by PyShark, "
        f"{analyzable_packets} analyzable packets extracted, "
        f"{skipped} yielded packets skipped."
    )


class _ProgressReporter:
    def __init__(self, total_packets: int | None) -> None:
        self.total_packets = total_packets
        self.packet_count = 0
        self._last_report_at = 0.0
        self._last_percent = -1

    def __call__(self, packet_count: int) -> None:
        self.packet_count = packet_count
        now = time.monotonic()
        if self.total_packets:
            percent = min(int((packet_count / self.total_packets) * 100), 100)
            if (
                percent == self._last_percent
                or (percent < 100 and now - self._last_report_at < 10)
            ):
                return
            self._last_percent = percent
            _info(
                "Local analysis progress: "
                f"{percent}% ({packet_count}/{self.total_packets} raw packets)."
            )
        else:
            if packet_count < 1_000 or now - self._last_report_at < 10:
                return
            _info(f"Local analysis progress: read {packet_count} raw packets.")
        self._last_report_at = now


def _progress_reporter(total_packets: int | None) -> _ProgressReporter:
    return _ProgressReporter(total_packets)


def _capture_packet_count(capture_path: Path) -> int | None:
    capinfos = _capinfos_path()
    if capinfos:
        try:
            result = subprocess.run(
                [capinfos, "-c", "-M", str(capture_path)],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        if result and result.returncode == 0:
            count = _parse_capinfos_packet_count(result.stdout)
            if count is not None:
                return count
    return _count_packets_in_capture(capture_path)


def _capinfos_path() -> str | None:
    path = shutil.which("capinfos")
    if path:
        return path
    macos_app_path = Path("/Applications/Wireshark.app/Contents/MacOS/capinfos")
    if macos_app_path.exists():
        return str(macos_app_path)
    return None


def _parse_capinfos_packet_count(output: str) -> int | None:
    for line in output.splitlines():
        match = re.match(
            r"\s*(?:Number of packets|Packet count)\s*[:=]\s*([0-9,]+)\s*$",
            line,
        )
        if match:
            return int(match.group(1).replace(",", ""))
    return None


def _count_packets_in_capture(capture_path: Path) -> int | None:
    try:
        with capture_path.open("rb") as capture_file:
            magic = capture_file.read(4)
            capture_file.seek(0)
            if magic in {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}:
                return _count_packets_in_pcap(capture_file, "<")
            if magic in {b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"}:
                return _count_packets_in_pcap(capture_file, ">")
            if magic == b"\x0a\x0d\x0d\x0a":
                return _count_packets_in_pcapng(capture_file)
    except OSError:
        return None
    return None


def _count_packets_in_pcap(capture_file, endian: str) -> int | None:
    capture_file.seek(24)
    count = 0
    while True:
        header = capture_file.read(16)
        if not header:
            return count
        if len(header) < 16:
            return None
        _ts_sec, _ts_frac, captured_length, _original_length = struct.unpack(
            f"{endian}IIII",
            header,
        )
        if captured_length < 0:
            return None
        capture_file.seek(captured_length, 1)
        count += 1


def _count_packets_in_pcapng(capture_file) -> int | None:
    endian = "<"
    count = 0
    while True:
        header = capture_file.read(8)
        if not header:
            return count
        if len(header) < 8:
            return None
        block_type, block_length = struct.unpack(f"{endian}II", header)
        if block_type == 0x0A0D0D0A:
            body = capture_file.read(4)
            if len(body) < 4:
                return None
            if body == b"\x4d\x3c\x2b\x1a":
                endian = "<"
                block_length = struct.unpack(f"{endian}I", header[4:8])[0]
            elif body == b"\x1a\x2b\x3c\x4d":
                endian = ">"
                block_length = struct.unpack(f"{endian}I", header[4:8])[0]
            else:
                return None
            remaining = block_length - 12
        else:
            remaining = block_length - 8
            if block_type in {0x00000003, 0x00000006}:
                count += 1
        if block_length < 12 or remaining < 4:
            return None
        capture_file.seek(remaining, 1)


def _render_sip_details(summary, *, show_flows: int) -> None:
    flow_ids = _flow_ids(summary.flows)
    rows = [
        (flow_ids[flow.key], flow)
        for flow in summary.flows[:show_flows]
        if flow.sip_call_ids or flow.sip_methods or flow.sip_statuses
    ]
    if not rows:
        return

    table = Table(title="SIP Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Call ID")
    table.add_column("Caller")
    table.add_column("Callee")
    table.add_column("Methods")
    table.add_column("Statuses")
    table.add_column("Issue")
    table.add_column("Trace")

    for flow_id, flow in rows:
        if flow.sip_calls:
            for call in list(flow.sip_calls.values())[:10]:
                table.add_row(
                    str(flow_id),
                    call.call_id,
                    call.caller or "-",
                    call.callee or "-",
                    _format_counter_lines(call.methods),
                    _format_counter_lines(call.statuses),
                    "\n".join(call.issues),
                    format_sip_trace(call.trace),
                )
        else:
            table.add_row(
                str(flow_id),
                "\n".join(flow.sip_call_ids[:10]),
                "-",
                "-",
                _format_counter_lines(flow.sip_methods),
                _format_counter_lines(flow.sip_statuses),
                "",
                "",
            )
    console.print(table)


def _render_smb_details(summary, *, show_flows: int) -> None:
    flow_ids = _flow_ids(summary.flows)
    rows = [
        (flow_ids[flow.key], flow)
        for flow in summary.flows[:show_flows]
        if (
            flow.smb_commands
            or flow.smb_statuses
            or flow.smb_filenames
            or flow.smb_encrypted_packets
        )
    ]
    if not rows:
        return

    table = Table(title="SMB Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Commands")
    table.add_column("Statuses")
    table.add_column("Capabilities")
    table.add_column("Transfer")
    table.add_column("Issue")

    for flow_id, flow in rows:
        table.add_row(
            str(flow_id),
            _format_smb_counter_lines(flow.smb_commands, SMB1_COMMAND_NAMES),
            _format_smb_counter_lines(flow.smb_statuses, SMB_STATUS_NAMES),
            _format_smb_capabilities(flow),
            _format_smb_transfer(flow),
            "\n".join(flow.smb_diagnostic_hints),
        )
    console.print(table)


def _render_dns_details(summary, *, show_flows: int) -> None:
    flow_ids = _flow_ids(summary.flows)
    rows = [
        (flow_ids[flow.key], flow)
        for flow in summary.flows[:show_flows]
        if flow.dns_queries or flow.dns_response_codes or flow.dns_answers
    ]
    if not rows:
        return

    table = Table(title="DNS Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Queries")
    table.add_column("Types")
    table.add_column("RCode")
    table.add_column("Answers")
    table.add_column("Issue")

    for flow_id, flow in rows:
        table.add_row(
            str(flow_id),
            _format_counter_lines(flow.dns_queries),
            _format_counter_lines(flow.dns_query_types),
            _format_counter_lines(flow.dns_response_codes),
            "\n".join(flow.dns_answers[:10]),
            dns_issue_summary(flow.dns_response_codes),
        )
    console.print(table)


def _render_dhcp_details(summary, *, show_flows: int) -> None:
    flow_ids = _flow_ids(summary.flows)
    rows = [
        (flow_ids[flow.key], flow)
        for flow in summary.flows[:show_flows]
        if flow.dhcp_message_types or flow.dhcp_client_macs or flow.dhcp_requested_ips
    ]
    if not rows:
        return

    table = Table(title="DHCP Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Messages")
    table.add_column("Client")
    table.add_column("Requested/Offered")
    table.add_column("Server")
    table.add_column("Lease")
    table.add_column("Issue")

    for flow_id, flow in rows:
        table.add_row(
            str(flow_id),
            _format_counter_lines(flow.dhcp_message_types),
            "\n".join([*flow.dhcp_client_macs[:5], *flow.dhcp_hostnames[:5]]),
            "\n".join(
                [
                    *[f"requested {ip}" for ip in flow.dhcp_requested_ips[:5]],
                    *[f"offered {ip}" for ip in flow.dhcp_offered_ips[:5]],
                ]
            ),
            "\n".join(flow.dhcp_server_ids[:10]),
            "\n".join(flow.dhcp_lease_times[:10]),
            "dhcp exchange lacks ack in observed packets"
            if flow.dhcp_message_types and not has_dhcp_ack(flow.dhcp_message_types)
            else "",
        )
    console.print(table)


def _render_tls_certificates(summary, *, show_flows: int) -> None:
    flow_ids = _flow_ids(summary.flows)
    rows = [
        (flow_ids[flow.key], flow, certificate)
        for flow in summary.flows[:show_flows]
        for certificate in flow.tls_certificates
    ]
    if not rows:
        return

    table = Table(title="TLS Certificates Observed In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Role")
    table.add_column("Endpoint")
    table.add_column("Subject CN", overflow="fold")
    table.add_column("Issuer CN", overflow="fold")
    table.add_column("Validity")
    table.add_column("SAN")

    for flow_id, flow, certificate in rows:
        table.add_row(
            str(flow_id),
            certificate.presenter_role or "-",
            _certificate_endpoint(flow, certificate),
            certificate.subject_cn or certificate.subject or "-",
            certificate.issuer_cn or certificate.issuer or "-",
            _validity(certificate),
            ", ".join(certificate.san_dns[:5]),
        )
    console.print(table)


def _render_reasoning(report) -> None:
    console.print(Panel(report.executive_summary, title=f"LLM Risk: {report.risk_level}"))
    for finding in report.findings:
        console.print(
            Panel(
                "\n".join(
                    [
                        f"Severity: {finding.severity}",
                        f"Hypothesis: {finding.hypothesis}",
                        f"Action: {finding.recommended_action}",
                        f"Evidence: {'; '.join(finding.evidence)}",
                    ]
                ),
                title=finding.title,
            )
        )


def _run_chat(summary, *, report, model: str, max_flows: int) -> None:
    _info("Interactive chat started. Ask follow-up questions, or type `exit` to quit.")
    history: list[dict[str, str]] = []
    while True:
        try:
            question = Prompt.ask("[bold cyan]flowpilot[/bold cyan]")
        except (EOFError, KeyboardInterrupt):
            console.print()
            _info("Interactive chat ended.")
            return

        question = question.strip()
        if not question:
            continue
        if question.lower() in {"exit", "quit", "q"}:
            _info("Interactive chat ended.")
            return

        _info("Sending follow-up question to LLM.")
        answer = chat_about_capture(
            summary,
            question,
            model=model,
            max_flows=max_flows,
            report=report,
            history=history,
        )
        console.print(Panel(answer, title="FlowPilot Chat"))
        history.extend(
            [
                {"role": "user", "content": question},
                {"role": "assistant", "content": answer},
            ]
        )


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip


def _flow_ids(flows) -> dict[object, int]:
    return {flow.key: index for index, flow in enumerate(flows, start=1)}


def _certificate_endpoint(flow, certificate) -> str:
    ip = certificate.presenter_ip
    port = certificate.presenter_port
    if ip:
        return _endpoint(ip, port)
    return (
        f"{_endpoint(flow.key.endpoint_a, flow.key.port_a)} or "
        f"{_endpoint(flow.key.endpoint_b, flow.key.port_b)}"
    )


def _direction(flow) -> str:
    if flow.is_one_way:
        return "one-way"
    return f"{flow.src_to_dst_packets}/{flow.dst_to_src_packets}"


def _percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _rtt(flow) -> str:
    if flow.avg_rtt_ms is None:
        return "-"
    return f"{flow.avg_rtt_ms:.1f}/{flow.rtt_max_ms:.1f} ms"


def _milliseconds(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.1f} ms"


def _format_issue_counts(issue_counts: dict[str, int]) -> str:
    return ", ".join(f"{name}={count}" for name, count in issue_counts.items())


def _format_flow_issues(flow) -> str:
    issue_lines = []
    issue_counts = _format_issue_counts(flow.issue_counts)
    if issue_counts:
        issue_lines.append(issue_counts)
    issue_lines.extend(flow.diagnostic_hints)
    return "\n".join(dict.fromkeys(issue_lines))


def _protocol_marker(flow) -> str:
    details = []
    if flow.sip_call_ids or flow.sip_methods or flow.sip_statuses:
        details.append(
            f"SIP calls={len(flow.sip_call_ids)} "
            f"methods={sum(flow.sip_methods.values())} "
            f"statuses={sum(flow.sip_statuses.values())}"
        )
    if flow.smb_commands or flow.smb_statuses or flow.smb_filenames or flow.smb_encrypted_packets:
        details.append(
            f"SMB commands={sum(flow.smb_commands.values())} "
            f"statuses={sum(flow.smb_statuses.values())} "
            f"files={len(flow.smb_filenames)} "
            f"encrypted={flow.smb_encrypted_packets}"
        )
    if flow.dns_queries or flow.dns_response_codes:
        details.append(
            f"DNS queries={sum(flow.dns_queries.values())} "
            f"rcodes={sum(flow.dns_response_codes.values())} "
            f"errors={flow.dns_error_count}"
        )
    if flow.dhcp_message_types:
        details.append(
            f"DHCP messages={sum(flow.dhcp_message_types.values())} "
            f"clients={len(flow.dhcp_client_macs)} "
            f"offers={len(flow.dhcp_offered_ips)}"
        )
    if flow.esp_sequences:
        details.append(format_esp_sequences(flow.esp_sequences))
    return "\n".join(details)


def _format_counter_lines(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return "\n".join(f"{key}: {value}" for key, value in list(counts.items())[:10])


def _format_smb_counter_lines(counts: dict[str, int], names: dict[str, str]) -> str:
    if not counts:
        return ""
    return "\n".join(
        f"{smb_display_value(value, names)}: {count}"
        for value, count in list(counts.items())[:10]
    )


def _format_smb_transfer(flow) -> str:
    return "\n".join(
        [
            _format_smb_transfer_line(
                "read",
                flow.smb_read_ops,
                flow.smb_read_bytes,
                flow.smb_read_unknown_bytes_ops,
                flow.smb_read_offset_inferred_ops,
                _format_smb_transfer_files("download", flow.smb_read_bytes_by_file),
            ),
            _format_smb_transfer_line(
                "write",
                flow.smb_write_ops,
                flow.smb_write_bytes,
                flow.smb_write_unknown_bytes_ops,
                flow.smb_write_offset_inferred_ops,
                _format_smb_transfer_files("upload", flow.smb_write_bytes_by_file),
            ),
            f"smb payload {flow.smb_transfer_mbps:.3f} Mbps",
            f"flow total {flow.throughput_mbps:.3f} Mbps",
        ]
    )


def _format_smb_transfer_files(label: str, bytes_by_file: dict[str, int]) -> list[str]:
    transferred_files = [
        (filename, byte_count)
        for filename, byte_count in bytes_by_file.items()
        if byte_count >= SMB_TRANSFER_FILE_MIN_BYTES
    ]
    transferred_files.sort(key=lambda item: item[1], reverse=True)
    return [
        f"{label} {filename} ({_format_bytes(byte_count)})"
        for filename, byte_count in transferred_files[:10]
    ]


def _format_smb_capabilities(flow) -> str:
    capability_sources: dict[str, set[str]] = {}
    for capability in flow.smb_client_capabilities:
        capability_sources.setdefault(capability, set()).add("c")
    for capability in flow.smb_server_capabilities:
        capability_sources.setdefault(capability, set()).add("s")
    lines = [
        f"{capability} ({','.join(source for source in ('c', 's') if source in sources)})"
        for capability, sources in list(capability_sources.items())[:20]
    ]
    return "\n".join(lines)


def _format_smb_transfer_line(
    label: str,
    ops: int,
    byte_count: int,
    unknown_ops: int,
    inferred_ops: int = 0,
    files: list[str] | None = None,
) -> str:
    line = f"{label} {ops} ops / {byte_count} bytes"
    notes = []
    if inferred_ops:
        notes.append(f"{inferred_ops} ops inferred from offsets")
    if unknown_ops:
        notes.append(f"{unknown_ops} ops length unavailable")
    if notes:
        line += f" ({', '.join(notes)})"
    if files:
        line += "\n" + "\n".join(files)
    return line


def _format_bytes(byte_count: int) -> str:
    if byte_count >= 1_048_576:
        return f"{byte_count / 1_048_576:.1f} MiB"
    if byte_count >= 1024:
        return f"{byte_count / 1024:.1f} KiB"
    return f"{byte_count} bytes"


def _validity(certificate) -> str:
    if not certificate.not_before and not certificate.not_after:
        return "-"
    return f"{certificate.not_before or '?'} to {certificate.not_after or '?'}"


if __name__ == "__main__":
    app()
