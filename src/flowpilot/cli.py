from __future__ import annotations

import atexit
import json
import re
import shutil
import struct
import subprocess
import tempfile
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
from .protocols.dhcp import render_dhcp_details
from .protocols.dns import render_dns_details
from .protocols.esp import format_esp_sequences
from .protocols.sip import render_sip_details
from .protocols.smb import render_smb_details
from .protocols.tls import render_tls_details
from .reasoning import (
    DEFAULT_MODEL,
    LLM_API,
    LLM_TIMEOUT_SECONDS,
    chat_about_capture,
    list_openai_models,
    reason_about_capture,
)
from .workflow import run_agent_chat, run_agent_reasoning_state

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
    analysis_focus: Annotated[
        str,
        typer.Option(
            "--analysis-focus",
            help="LLM focus: transport or security. Local packet analysis is unchanged.",
        ),
    ] = "transport",
    no_llm: Annotated[bool, typer.Option(help="Only print the local flow summary.")] = False,
    chat: Annotated[
        bool,
        typer.Option(help="After LLM reasoning, open an interactive follow-up chat."),
    ] = False,
    agent: Annotated[
        bool,
        typer.Option(
            "--agent",
            help=(
                "Route LLM reasoning and chat through a LangGraph workflow. Local packet "
                "analysis remains deterministic."
            ),
        ),
    ] = False,
    agent_auto_tools: Annotated[
        bool,
        typer.Option(
            "--agent-auto-tools",
            help=(
                "With --agent, run deterministic deep TCP/UDP rereads before the first LLM "
                "request. Without this flag, tools run only when the LLM requests them."
            ),
        ),
    ] = False,
    json_path: Annotated[
        Path | None, typer.Option("--json", help="Write a JSON report to this path.")
    ] = None,
    cache_pcap: Annotated[
        bool,
        typer.Option(
            "--cache-pcap",
            help=(
                "Copy the capture into a temporary FlowPilot session workspace before "
                "analysis. Useful for future agentic rereads of large pcaps."
            ),
        ),
    ] = False,
    keep_cache: Annotated[
        bool,
        typer.Option(
            "--keep-cache",
            help="Keep the temporary session workspace after analysis for debugging.",
        ),
    ] = False,
) -> None:
    """Analyze a packet capture."""
    if chat and no_llm:
        raise typer.BadParameter(
            "--chat requires LLM reasoning, so it cannot be used with --no-llm."
        )
    if agent_auto_tools and not agent:
        raise typer.BadParameter("--agent-auto-tools requires --agent.")
    if analysis_focus not in {"transport", "security"}:
        raise typer.BadParameter("--analysis-focus must be either transport or security.")
    if keep_cache:
        cache_pcap = True

    session = _CachedCaptureSession.create(capture_path, keep=keep_cache) if cache_pcap else None
    if session:
        _info(
            "Session pcap cache ready: "
            f"{session.capture_path}. Full packet headers and captured bytes are preserved."
        )
        capture_path = session.capture_path
    try:
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
        try:
            observations = _materialize_observations(observations)
        finally:
            progress.finish()
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
            llm_started_at = time.perf_counter()
            agent_evidence = []
            if agent:
                agent_progress = _RefreshingInfo()
                _info(
                    "LangGraph agent workflow started. "
                    f"auto_tools={agent_auto_tools}, model={model}, api={LLM_API}, "
                    f"focus={analysis_focus}, "
                    f"timeout={LLM_TIMEOUT_SECONDS:g}s. Raw packet payloads are not sent."
                )
                try:
                    agent_state = run_agent_reasoning_state(
                        summary,
                        capture_path=capture_path,
                        model=model,
                        max_flows=max_flows,
                        analysis_focus=analysis_focus,
                        agent_auto_tools=agent_auto_tools,
                        progress_callback=agent_progress,
                    )
                finally:
                    agent_progress.finish()
                report = agent_state["report"]
                agent_evidence = agent_state.get("deep_evidence", [])
                if agent_evidence:
                    _info(f"LangGraph gathered {len(agent_evidence)} deep evidence result(s).")
            else:
                _info(
                    "Sending derived metadata to LLM: "
                    f"model={model}, api={LLM_API}, "
                    f"focus={analysis_focus}, "
                    f"timeout={LLM_TIMEOUT_SECONDS:g}s, "
                    f"top_flows={min(summary.flow_count, max_flows)}. "
                    "Raw packet payloads are not sent."
                )
                report = reason_about_capture(
                    summary,
                    model=model,
                    max_flows=max_flows,
                    analysis_focus=analysis_focus,
                )
            llm_elapsed = time.perf_counter() - llm_started_at
            _info(f"LLM reasoning finished in {llm_elapsed:.2f}s.")

        if report:
            if agent_evidence:
                _render_agent_evidence(agent_evidence)
            _render_reasoning(report)

        if json_path:
            payload = {"summary": summary.model_dump(mode="json")}
            if report:
                payload["reasoning"] = report.model_dump(mode="json")
            json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            console.print(f"[green]Wrote JSON report:[/green] {json_path}")

        if chat and report:
            _run_chat(
                summary,
                report=report,
                model=model,
                max_flows=max_flows,
                agent=agent,
                analysis_focus=analysis_focus,
                additional_evidence=agent_evidence if agent else None,
                capture_path=capture_path if agent else None,
            )
    finally:
        if session:
            session.close()


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
    table.add_column("Model ID", overflow="fold")
    table.add_column("Owner", overflow="fold")
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
    table.add_column("Flow", overflow="fold")
    table.add_column("Traffic", overflow="fold")
    table.add_column("Direction", overflow="fold")
    table.add_column("Metrics", overflow="fold")
    table.add_column("Protocol", overflow="fold")
    table.add_column("Issues", overflow="fold")

    flow_ids = _flow_ids(summary.flows)
    for flow in summary.flows[:show_flows]:
        table.add_row(
            str(flow_ids[id(flow)]),
            (
                f"{flow.key.protocol}\n"
                f"{_endpoint(flow.key.endpoint_a, flow.key.port_a)} <->\n"
                f"{_endpoint(flow.key.endpoint_b, flow.key.port_b)}"
            ),
            _traffic(flow),
            _direction(flow),
            "\n".join(
                [
                    f"rtx {_percent(flow.retransmission_rate)}",
                    f"loss {_percent(flow.packet_loss_rate)}",
                    f"rtt {_rtt(flow)}",
                    f"rate {flow.packet_rate_per_second:.1f} pps",
                    f"thr {flow.throughput_mbps:.3f} Mbps",
                ]
            ),
            _protocol_marker(flow),
            _format_flow_issues(flow),
        )
    console.print(table)
    render_dns_details(summary, show_flows=show_flows, console=console)
    render_dhcp_details(summary, show_flows=show_flows, console=console)
    render_sip_details(summary, show_flows=show_flows, console=console)
    render_smb_details(summary, show_flows=show_flows, console=console)
    render_tls_details(summary, show_flows=show_flows, console=console)


def _info(message: str) -> None:
    console.print(f"[cyan][info][/cyan] {message}")


class _RefreshingInfo:
    REFRESH_PREFIX = "__flowpilot_refresh__:"

    def __init__(self) -> None:
        self._last_message_length = 0

    def __call__(self, message: str) -> None:
        if message.startswith(self.REFRESH_PREFIX):
            self.refresh(message.removeprefix(self.REFRESH_PREFIX))
            return
        self.finish()
        _info(message)

    def refresh(self, message: str) -> None:
        line = f"[info] {message}"
        console.file.write("\r\033[2K" + line)
        console.file.flush()
        self._last_message_length = len(line)

    def finish(self) -> None:
        if not self._last_message_length:
            return
        console.file.write("\r\033[2K")
        console.file.flush()
        self._last_message_length = 0


def _materialize_observations(observations) -> list:
    return list(observations)


class _CachedCaptureSession:
    def __init__(self, workspace: Path, capture_path: Path, *, keep: bool) -> None:
        self.workspace = workspace
        self.capture_path = capture_path
        self.keep = keep
        self._closed = False

    @classmethod
    def create(cls, source_path: Path, *, keep: bool) -> _CachedCaptureSession:
        workspace = Path(tempfile.mkdtemp(prefix="flowpilot-"))
        capture_path = workspace / source_path.name
        try:
            shutil.copy2(source_path, capture_path)
        except OSError:
            shutil.rmtree(workspace, ignore_errors=True)
            raise
        session = cls(workspace, capture_path, keep=keep)
        atexit.register(session.close)
        return session

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self.keep:
            _info(f"Keeping session cache workspace: {self.workspace}")
            return
        shutil.rmtree(self.workspace, ignore_errors=True)
        _info(f"Removed session cache workspace: {self.workspace}")


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
        self._last_message_length = 0

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
            self._refresh(
                "Local analysis progress: "
                f"{percent}% ({packet_count}/{self.total_packets} raw packets)"
            )
        else:
            if packet_count < 1_000 or now - self._last_report_at < 10:
                return
            self._refresh(f"Local analysis progress: read {packet_count} raw packets")
        self._last_report_at = now

    def finish(self) -> None:
        if not self._last_message_length:
            return
        clear_line = "\r" + (" " * self._last_message_length) + "\r"
        console.file.write(clear_line)
        console.file.flush()
        self._last_message_length = 0

    def _refresh(self, message: str) -> None:
        line = f"[info] {message}"
        padding = max(self._last_message_length - len(line), 0)
        console.file.write("\r" + line + (" " * padding))
        console.file.flush()
        self._last_message_length = len(line)


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


def _render_agent_evidence(agent_evidence: list[dict]) -> None:
    table = Table(title="LangGraph Deep Evidence", show_lines=True)
    table.add_column("Flow ID", justify="right")
    table.add_column("Tool", overflow="fold")
    table.add_column("Status", overflow="fold")
    table.add_column("Packets", justify="right")
    table.add_column("Key Counts", overflow="fold")
    table.add_column("Display Filter", overflow="fold")
    table.add_column("Message", overflow="fold")

    for evidence in agent_evidence:
        table.add_row(
            str(evidence.get("flow_id") or "-"),
            str(evidence.get("tool") or "-"),
            str(evidence.get("status") or "-"),
            str(evidence.get("packet_count") or "-"),
            _format_agent_evidence_counts(evidence),
            str(evidence.get("display_filter") or "-"),
            str(evidence.get("message") or "-"),
        )
    console.print(table)


def _format_agent_evidence_counts(evidence: dict) -> str:
    counts = (
        evidence.get("tcp_analysis_counts")
        or evidence.get("udp_metadata_counts")
        or evidence.get("tls_metadata_counts")
        or {}
    )
    if not counts:
        return "-"
    return "\n".join(f"{key}: {value}" for key, value in counts.items())


def _run_chat(
    summary,
    *,
    report,
    model: str,
    max_flows: int,
    agent: bool = False,
    analysis_focus: str = "transport",
    additional_evidence: list[dict] | None = None,
    capture_path: Path | None = None,
) -> None:
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
        if agent:
            agent_progress = _RefreshingInfo()
            try:
                answer = run_agent_chat(
                    summary,
                    question,
                    model=model,
                    max_flows=max_flows,
                    analysis_focus=analysis_focus,
                    report=report,
                    history=history,
                    additional_evidence=additional_evidence,
                    capture_path=capture_path,
                    progress_callback=agent_progress,
                )
            finally:
                agent_progress.finish()
        else:
            answer = chat_about_capture(
                summary,
                question,
                model=model,
                max_flows=max_flows,
                analysis_focus=analysis_focus,
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


def _flow_endpoint_text(flow) -> str:
    return (
        f"{_endpoint(flow.key.endpoint_a, flow.key.port_a)} <-> "
        f"{_endpoint(flow.key.endpoint_b, flow.key.port_b)}"
    )


def _flow_ids(flows) -> dict[object, int]:
    return {id(flow): index for index, flow in enumerate(flows, start=1)}


def _direction(flow) -> str:
    packet_split = f"pkts {flow.src_to_dst_packets}/{flow.dst_to_src_packets}"
    byte_split = f"bytes {flow.src_to_dst_bytes}/{flow.dst_to_src_bytes}"
    if flow.is_one_way:
        return f"one-way\n{packet_split}\n{byte_split}"
    return f"{packet_split}\n{byte_split}"


def _traffic(flow) -> str:
    return f"pkts {flow.packet_count}\nbytes {flow.byte_count}"


def _percent(value: float) -> str:
    percent = value * 100
    if percent == 0:
        return "0%"
    if percent < 0.1:
        return f"{percent:.3f}%"
    return f"{percent:.1f}%"


def _rtt(flow) -> str:
    initial = f"{flow.initial_rtt_ms:.1f} ms" if flow.initial_rtt_ms is not None else "n/a"
    if flow.median_rtt_ms is None:
        return f"init {initial}\nack n/a"
    return (
        f"init {initial}\n"
        f"ack med/p95/max {flow.median_rtt_ms:.1f}/"
        f"{flow.p95_rtt_ms:.1f}/{flow.rtt_max_ms:.1f} ms"
    )


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
    if flow.tls_snis or flow.tls_certificates or flow.tls_alerts:
        details.append(
            f"TLS sni={len(flow.tls_snis)} "
            f"certs={len(flow.tls_certificates)} alerts={sum(flow.tls_alerts.values())}"
        )
    if flow.esp_sequences:
        details.append(format_esp_sequences(flow.esp_sequences))
    return "\n".join(details)


def _format_counter_lines(counts: dict[str, int]) -> str:
    if not counts:
        return ""
    return "\n".join(f"{key}: {value}" for key, value in list(counts.items())[:10])


if __name__ == "__main__":
    app()
