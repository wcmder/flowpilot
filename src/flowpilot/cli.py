from __future__ import annotations

import json
import re
import shutil
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
from .filters import (
    FlowFilter,
    filter_observations,
    filter_sip_calls_by_phone,
    include_redirect_related_flows,
)
from .reasoning import DEFAULT_MODEL, chat_about_capture, list_openai_models, reason_about_capture

app = typer.Typer(help="Agentic packet data-flow analysis with PyShark and OpenAI.")
console = Console()


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
        all_observations = list(observations)
        seed_observations = list(filter_observations(all_observations, flow_filter))
        observations = include_redirect_related_flows(all_observations, seed_observations)
    elif flow_filter.is_active:
        observations = filter_observations(observations, flow_filter)
    if sip_phone:
        observations = filter_sip_calls_by_phone(observations, sip_phone)

    summary = summarize_capture(observations)
    _info(
        "Local analysis finished: "
        f"{summary.packet_count} packets, {summary.flow_count} flows, {summary.total_bytes} bytes."
    )
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
            f"Flows: {summary.flow_count}\n"
            f"Issues: {_format_issue_counts(summary.issue_counts)}",
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
                    f"gap {_milliseconds(flow.max_interarrival_ms)}",
                    f"rate {flow.packet_rate_per_second:.1f} pps",
                    f"thr {flow.throughput_mbps:.3f} Mbps",
                ]
            ),
            _protocol_marker(flow),
            _format_issue_counts(flow.issue_counts) or ", ".join(flow.names[:3]),
        )
    console.print(table)
    _render_dns_details(summary, show_flows=show_flows)
    _render_dhcp_details(summary, show_flows=show_flows)
    _render_sip_details(summary, show_flows=show_flows)
    _render_smb_details(summary, show_flows=show_flows)
    _render_tls_certificates(summary, show_flows=show_flows)


def _info(message: str) -> None:
    console.print(f"[cyan][info][/cyan] {message}")


def _local_analysis_start_message(capture_path: Path, total_packets: int | None) -> str:
    message = f"Local analysis started: reading {capture_path}"
    if total_packets is not None:
        message += f" ({total_packets} packets)"
    return f"{message}."


def _progress_reporter(total_packets: int | None):
    last_report_at = 0.0
    last_percent = -1

    def report(packet_count: int) -> None:
        nonlocal last_report_at, last_percent
        now = time.monotonic()
        if total_packets:
            percent = min(int((packet_count / total_packets) * 100), 100)
            if percent == last_percent or (percent < 100 and now - last_report_at < 5):
                return
            last_percent = percent
            _info(f"Local analysis progress: {percent}% ({packet_count}/{total_packets} packets).")
        else:
            if packet_count < 1_000 or now - last_report_at < 5:
                return
            _info(f"Local analysis progress: read {packet_count} packets.")
        last_report_at = now

    return report


def _capture_packet_count(capture_path: Path) -> int | None:
    capinfos = shutil.which("capinfos")
    if not capinfos:
        return None
    try:
        result = subprocess.run(
            [capinfos, "-c", str(capture_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    match = re.search(r"Number of packets:\s*([0-9,]+)", result.stdout)
    if not match:
        match = re.search(r"\b([0-9][0-9,]*)\b", result.stdout)
    if not match:
        return None
    return int(match.group(1).replace(",", ""))


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
                    _format_sip_trace(call.trace),
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
        if flow.smb_commands or flow.smb_statuses or flow.smb_filenames
    ]
    if not rows:
        return

    table = Table(title="SMB Details In Top Flows", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Commands")
    table.add_column("Statuses")
    table.add_column("Files")
    table.add_column("Transfer")
    table.add_column("Issue")

    for flow_id, flow in rows:
        table.add_row(
            str(flow_id),
            _format_smb_counter_lines(flow.smb_commands, _SMB_COMMAND_NAMES),
            _format_smb_counter_lines(flow.smb_statuses, _SMB_STATUS_NAMES),
            "\n".join(flow.smb_filenames[:10]),
            (
                f"read {flow.smb_read_ops} ops / {flow.smb_read_bytes} bytes\n"
                f"write {flow.smb_write_ops} ops / {flow.smb_write_bytes} bytes\n"
                f"{flow.smb_transfer_mbps:.3f} Mbps"
            ),
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
            "dns error responses observed" if flow.dns_error_count else "",
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
            if flow.dhcp_message_types and not _has_counter_key(flow.dhcp_message_types, "ACK")
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
    table.add_column("SHA-256")

    for flow_id, flow, certificate in rows:
        table.add_row(
            str(flow_id),
            certificate.presenter_role or "-",
            _certificate_endpoint(flow, certificate),
            certificate.subject_cn or certificate.subject or "-",
            certificate.issuer_cn or certificate.issuer or "-",
            _validity(certificate),
            ", ".join(certificate.san_dns[:5]),
            certificate.fingerprint_sha256 or "-",
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


def _protocol_marker(flow) -> str:
    details = []
    if flow.sip_call_ids or flow.sip_methods or flow.sip_statuses:
        details.append(
            f"SIP calls={len(flow.sip_call_ids)} "
            f"methods={sum(flow.sip_methods.values())} "
            f"statuses={sum(flow.sip_statuses.values())}"
        )
    if flow.smb_commands or flow.smb_statuses or flow.smb_filenames:
        details.append(
            f"SMB commands={sum(flow.smb_commands.values())} "
            f"statuses={sum(flow.smb_statuses.values())} "
            f"files={len(flow.smb_filenames)}"
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
        details.append(_format_esp_sequences(flow.esp_sequences))
    return "\n".join(details)


def _format_esp_sequences(sequences) -> str:
    lines = []
    for sequence in sequences[:6]:
        lines.append(
            f"{sequence.direction} "
            f"pkts={sequence.packet_count} "
            f"missing={sequence.missing_count} "
            f"ooo={sequence.out_of_order_count} "
            f"dup={sequence.duplicate_count} "
            f"gaps={_format_esp_gap_distribution(sequence.gap_occurrences)}"
        )
    if len(sequences) > 6:
        lines.append(f"... {len(sequences) - 6} more ESP directions/SPIs")
    return "\n".join(lines)


def _format_esp_gap_distribution(gaps: list[dict[str, int]]) -> str:
    if not gaps:
        return "none"
    counts: dict[int, int] = {}
    for gap in gaps:
        missing = gap["missing"]
        counts[missing] = counts.get(missing, 0) + 1
    return " ".join(f"gap={missing}(x{count})" for missing, count in sorted(counts.items()))


def _format_counter_lines(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return "\n".join(f"{key}: {value}" for key, value in list(counts.items())[:10])


_SMB_COMMAND_NAMES = {
    "0": "SMBmkdir",
    "0x00": "SMBmkdir",
    "1": "SMBrmdir",
    "0x01": "SMBrmdir",
    "2": "SMBopen",
    "0x02": "SMBopen",
    "3": "SMBcreate",
    "0x03": "SMBcreate",
    "4": "SMBclose",
    "0x04": "SMBclose",
    "5": "SMBflush",
    "0x05": "SMBflush",
    "6": "SMBunlink",
    "0x06": "SMBunlink",
    "7": "SMBmv",
    "0x07": "SMBmv",
    "8": "SMBgetatr",
    "0x08": "SMBgetatr",
    "9": "SMBsetatr",
    "0x09": "SMBsetatr",
}

_SMB_STATUS_NAMES = {
    "0": "STATUS_SUCCESS",
    "0x00000000": "STATUS_SUCCESS",
}


def _format_smb_counter_lines(counts: dict[str, int], names: dict[str, str]) -> str:
    if not counts:
        return ""
    return "\n".join(
        f"{_format_smb_value(value, names)}: {count}"
        for value, count in list(counts.items())[:10]
    )


def _format_smb_value(value: str, names: dict[str, str]) -> str:
    normalized = value.lower()
    label = names.get(value) or names.get(normalized)
    if label:
        return f"{label}({value})"
    return value


def _has_counter_key(counts: dict[str, int], wanted: str) -> bool:
    return any(wanted.upper() in key.upper() for key in counts)


def _format_sip_trace(trace: list[dict[str, str | None]]) -> str:
    return "\n".join(
        f"{event.get('from_endpoint')} -> {event.get('to_endpoint')} {event.get('message')}"
        for event in trace[:8]
    )


def _validity(certificate) -> str:
    if not certificate.not_before and not certificate.not_after:
        return "-"
    return f"{certificate.not_before or '?'} to {certificate.not_after or '?'}"


if __name__ == "__main__":
    app()
