from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .analysis import summarize_capture
from .capture import read_capture
from .filters import FlowFilter, filter_observations, include_redirect_related_flows
from .reasoning import DEFAULT_MODEL, list_openai_models, reason_about_capture

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
    max_flows: Annotated[int, typer.Option(help="Maximum top flows sent to the model.")] = 25,
    show_flows: Annotated[int, typer.Option(help="Maximum flows shown in the terminal.")] = 10,
    no_llm: Annotated[bool, typer.Option(help="Only print the local flow summary.")] = False,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Write a JSON report to this path.")
    ] = None,
) -> None:
    """Analyze a packet capture."""
    observations = read_capture(
        capture_path,
        packet_limit=packet_limit,
        tls_keylog_file=tls_keylog_file,
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

    summary = summarize_capture(observations)
    report = None if no_llm else reason_about_capture(summary, model=model, max_flows=max_flows)

    _render_summary(summary, show_flows=show_flows)
    if report:
        _render_reasoning(report)

    if json_path:
        payload = {"summary": summary.model_dump(mode="json")}
        if report:
            payload["reasoning"] = report.model_dump(mode="json")
        json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]Wrote JSON report:[/green] {json_path}")


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
                ]
            ),
            _protocol_marker(flow),
            _format_issue_counts(flow.issue_counts) or ", ".join(flow.names[:3]),
        )
    console.print(table)
    _render_sip_details(summary, show_flows=show_flows)
    _render_smb_details(summary, show_flows=show_flows)
    _render_tls_certificates(summary, show_flows=show_flows)


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
    table.add_column("Session IDs")
    table.add_column("Tree IDs")
    table.add_column("Files")

    for flow_id, flow in rows:
        table.add_row(
            str(flow_id),
            _format_counter_lines(flow.smb_commands),
            _format_counter_lines(flow.smb_statuses),
            "\n".join(flow.smb_session_ids[:10]),
            "\n".join(flow.smb_tree_ids[:10]),
            "\n".join(flow.smb_filenames[:10]),
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
    return "\n".join(details)


def _format_counter_lines(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return "\n".join(f"{key}: {value}" for key, value in list(counts.items())[:10])


def _validity(certificate) -> str:
    if not certificate.not_before and not certificate.not_after:
        return "-"
    return f"{certificate.not_before or '?'} to {certificate.not_after or '?'}"


if __name__ == "__main__":
    app()
