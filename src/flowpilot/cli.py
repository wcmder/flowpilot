from __future__ import annotations

import atexit
import json
import re
import shutil
import struct
import subprocess
import sys
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
from .decode_as import set_esp_udp_ports
from .filters import (
    FlowFilter,
    filter_observations,
    filter_sip_calls_by_phone,
    include_redirect_related_flows,
)
from .models import CaptureSummary, FlowSummary
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
    openai_models_url,
    reason_about_capture,
)
from .workflow import run_agent_chat, run_agent_reasoning_state

app = typer.Typer(help="Agentic packet data-flow analysis with PyShark and OpenAI.")
console = Console()
LOCAL_PROGRESS_REFRESH_SECONDS = 5
FLOWPILOT_PRIVATE_DIR = Path("private")


def _normalize_optional_json_arg(argv: list[str]) -> list[str]:
    if not argv or argv[0] != "analyze":
        return argv
    default_json_filename = _default_summary_filename(argv)
    normalized = []
    index = 0
    while index < len(argv):
        arg = argv[index]
        normalized.append(arg)
        if arg in {"--json", "--load-summary"}:
            next_arg = argv[index + 1] if index + 1 < len(argv) else None
            if next_arg is None or next_arg.startswith("-"):
                normalized.append(default_json_filename)
        index += 1
    return normalized


def _default_summary_filename(argv: list[str]) -> str:
    capture_path = _capture_path_arg(argv)
    if capture_path is None:
        return "flow-summary.json"
    return _default_summary_path_for_capture(Path(capture_path)).name


def _default_summary_path_for_capture(capture_path: Path) -> Path:
    return Path(f"{capture_path.stem}.json")


def _capture_path_arg(argv: list[str]) -> str | None:
    options_with_values = {
        "--model",
        "--packet-limit",
        "--tls-keylog-file",
        "--esp-udp-port",
        "--host",
        "--peer",
        "--protocol",
        "--port",
        "--src",
        "--dst",
        "--src-port",
        "--dst-port",
        "--sip-phone",
        "--max-flows",
        "--show-flows",
        "--analysis-focus",
        "--json",
        "--load-summary",
    }
    index = 1
    while index < len(argv):
        arg = argv[index]
        if arg in {"--json", "--load-summary"}:
            next_arg = argv[index + 1] if index + 1 < len(argv) else None
            if next_arg is not None and not next_arg.startswith("-"):
                index += 2
                continue
            index += 1
            continue
        if arg in options_with_values:
            index += 2
            continue
        if arg.startswith("-"):
            index += 1
            continue
        return arg
    return None


sys.argv[:] = [sys.argv[0], *_normalize_optional_json_arg(sys.argv[1:])]


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
    esp_udp_port: Annotated[
        list[int] | None,
        typer.Option(
            "--esp-udp-port",
            help=(
                "Decode this UDP port as ESP before analysis. Repeat for multiple "
                "Cisco SD-WAN or other UDP-encapsulated ESP ports."
            ),
        ),
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
        Path | None,
        typer.Option(
            "--json",
            help=(
                "Override the automatic JSON report filename under private/. Without "
                "this option, FlowPilot writes the capture filename with .json."
            ),
        ),
    ] = None,
    load_summary: Annotated[
        Path | None,
        typer.Option(
            "--load-summary",
            help=(
                "Load a previously written --json summary and skip the initial pcap read. "
                "Flow filters are applied to summarized flows. If no filename follows "
                "--load-summary, defaults to the capture filename with .json."
            ),
        ),
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
    original_capture_path = capture_path
    source_capture_path_for_json = original_capture_path
    effective_json_path = json_path or _default_summary_path_for_capture(original_capture_path)
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
    set_esp_udp_ports(esp_udp_port)

    session = _CachedCaptureSession.create(capture_path, keep=keep_cache) if cache_pcap else None
    if session:
        _info(
            "Session pcap cache ready: "
            f"{session.capture_path}. Full packet headers and captured bytes are preserved."
        )
        capture_path = session.capture_path
    try:
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
        if load_summary:
            _info(f"Loading local summary from {load_summary}. Skipping initial pcap read.")
            summary, summary_source_capture_path = _load_summary_with_metadata(load_summary)
            if summary_source_capture_path:
                source_capture_path_for_json = summary_source_capture_path
            if summary_source_capture_path and not capture_path.exists():
                _info(
                    "Using source capture path from loaded summary for agent deep tools: "
                    f"{summary_source_capture_path}"
                )
                capture_path = summary_source_capture_path
            summary = _apply_summary_filters(
                summary,
                flow_filter=flow_filter,
                sip_phone=sip_phone,
                include_redirects=include_redirects,
            )
            _info(
                "Local summary loaded: "
                f"{summary.packet_count} analyzable packets, "
                f"{summary.flow_count} flows, {summary.total_bytes} bytes."
            )
        else:
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

        json_output_path = _summary_json_output_path(effective_json_path)
        payload = {
            "source_capture_path": str(
                source_capture_path_for_json.expanduser().resolve(strict=False)
            ),
            "summary": summary.model_dump(mode="json"),
        }
        if report:
            payload["reasoning"] = report.model_dump(mode="json")
        json_output_path.parent.mkdir(parents=True, exist_ok=True)
        json_output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]Wrote JSON report:[/green] {json_output_path}")

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
    url = openai_models_url()
    models = list_openai_models()
    if json_output:
        console.print(json.dumps({"url": url, "models": models}, indent=2))
        return

    console.print(f"[bold]Models endpoint:[/bold] {url}")
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
            _flow_metrics(flow),
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


def _load_summary(summary_path: Path) -> CaptureSummary:
    summary, _source_capture_path = _load_summary_with_metadata(summary_path)
    return summary


def _load_summary_with_metadata(summary_path: Path) -> tuple[CaptureSummary, Path | None]:
    summary_path = _summary_json_input_path(summary_path)
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    summary_data = data.get("summary", data) if isinstance(data, dict) else data
    source_capture_path = None
    if isinstance(data, dict) and data.get("source_capture_path"):
        source_capture_path = Path(str(data["source_capture_path"])).expanduser()
    return CaptureSummary.model_validate(summary_data), source_capture_path


def _summary_json_output_path(json_path: Path) -> Path:
    return FLOWPILOT_PRIVATE_DIR / json_path.name


def _summary_json_input_path(summary_path: Path) -> Path:
    if summary_path.exists():
        return summary_path
    private_path = FLOWPILOT_PRIVATE_DIR / summary_path.name
    return private_path if private_path.exists() else summary_path


def _apply_summary_filters(
    summary: CaptureSummary,
    *,
    flow_filter: FlowFilter,
    sip_phone: str | None,
    include_redirects: bool,
) -> CaptureSummary:
    flows = summary.flows
    if flow_filter.is_active:
        _info("Applying flow filters to loaded summary.")
        flows = [flow for flow in flows if _flow_matches_filter(flow, flow_filter)]
        if include_redirects:
            _info(
                "Redirect expansion is skipped for --load-summary because it requires "
                "packet-level observations."
            )
    if sip_phone:
        _info("Applying SIP phone filter to loaded summary.")
        flows = [flow for flow in flows if _flow_matches_sip_phone(flow, sip_phone)]
    if flows == summary.flows:
        return summary
    return _summary_from_flows(flows)


def _flow_matches_filter(flow: FlowSummary, flow_filter: FlowFilter) -> bool:
    endpoints = {flow.key.endpoint_a, flow.key.endpoint_b}
    ports = {port for port in (flow.key.port_a, flow.key.port_b) if port is not None}
    if flow_filter.protocol and flow.key.protocol.upper() != flow_filter.protocol.upper():
        return False
    if flow_filter.host and flow_filter.host not in endpoints:
        return False
    if flow_filter.peer and flow_filter.peer not in endpoints:
        return False
    if flow_filter.host and flow_filter.peer and endpoints != {flow_filter.host, flow_filter.peer}:
        return False
    if flow_filter.src and flow_filter.src not in endpoints:
        return False
    if flow_filter.dst and flow_filter.dst not in endpoints:
        return False
    if flow_filter.port and flow_filter.port not in ports:
        return False
    if flow_filter.src_port and flow_filter.src_port not in ports:
        return False
    if flow_filter.dst_port and flow_filter.dst_port not in ports:
        return False
    return True


def _flow_matches_sip_phone(flow: FlowSummary, phone_number: str) -> bool:
    wanted = _digits(phone_number)
    if not wanted:
        return True
    for call in flow.sip_calls.values():
        if wanted in _digits(call.caller or "") or wanted in _digits(call.callee or ""):
            return True
    for participant in flow.sip_participants:
        if wanted in _digits(participant):
            return True
    return False


def _summary_from_flows(flows: list[FlowSummary]) -> CaptureSummary:
    protocols: dict[str, int] = {}
    top_ports: dict[str, int] = {}
    issue_counts: dict[str, int] = {}
    names: list[str] = []
    for flow in flows:
        protocols[flow.key.protocol] = protocols.get(flow.key.protocol, 0) + flow.packet_count
        for port in (flow.key.port_a, flow.key.port_b):
            if port is not None:
                port_text = str(port)
                top_ports[port_text] = top_ports.get(port_text, 0) + flow.packet_count
        for issue, count in flow.issue_counts.items():
            issue_counts[issue] = issue_counts.get(issue, 0) + count
        for name in flow.names:
            if name not in names:
                names.append(name)
    sorted_flows = sorted(flows, key=lambda flow: flow.byte_count, reverse=True)
    return CaptureSummary(
        packet_count=sum(flow.packet_count for flow in sorted_flows),
        total_bytes=sum(flow.byte_count for flow in sorted_flows),
        flow_count=len(sorted_flows),
        protocols=dict(sorted(protocols.items(), key=lambda item: item[1], reverse=True)[:20]),
        top_ports=dict(sorted(top_ports.items(), key=lambda item: item[1], reverse=True)[:20]),
        issue_counts=dict(
            sorted(issue_counts.items(), key=lambda item: item[1], reverse=True)[:30]
        ),
        names=names[:50],
        flows=sorted_flows,
    )


def _digits(value: str) -> str:
    return "".join(re.findall(r"\d+", value))


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
                or (
                    percent < 100
                    and now - self._last_report_at < LOCAL_PROGRESS_REFRESH_SECONDS
                )
            ):
                return
            self._last_percent = percent
            self._refresh(
                "Local analysis progress: "
                f"{percent}% ({packet_count}/{self.total_packets} raw packets)"
            )
        else:
            if (
                packet_count < 1_000
                or now - self._last_report_at < LOCAL_PROGRESS_REFRESH_SECONDS
            ):
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
    if evidence.get("esp_metadata_counts"):
        return _format_esp_agent_evidence_counts(evidence.get("esp_metadata_counts") or {})

    counts = (
        evidence.get("tcp_analysis_counts")
        or evidence.get("udp_metadata_counts")
        or evidence.get("tls_metadata_counts")
        or evidence.get("smb2_credit_counts")
        or {}
    )
    if not counts:
        return "-"
    if evidence.get("smb2_credit_counts"):
        keys = [
            "smb2_packets",
            "smb2_requests",
            "smb2_responses",
            "credit_charge_total",
            "credit_charge_max",
            "credit_request_total",
            "credit_request_max",
            "credit_grant_total",
            "credit_grant_max",
            "credit_grant_zero_packets",
            "read_packets",
            "write_packets",
            "status_error_packets",
            "tcp_loss_or_retransmission_packets",
            "tcp_zero_window_packets",
        ]
        return "\n".join(f"{key}: {counts[key]}" for key in keys if key in counts)
    lines = [f"{key}: {value}" for key, value in counts.items()]
    if tcp_window_stats := evidence.get("tcp_window_stats"):
        lines.extend(f"{key}: {value}" for key, value in tcp_window_stats.items())
    return "\n".join(lines)


def _format_esp_agent_evidence_counts(counts: dict) -> str:
    lines = []
    for key in (
        "esp_packets",
        "nat_t_udp_4500_packets",
        "fragmented_packets",
        "dscp_values",
        "ip_length_min",
        "ip_length_max",
        "df_bit",
    ):
        if key in counts:
            lines.append(f"{key}: {counts[key]}")
    return "\n".join(lines) or "-"


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


def _flow_metrics(flow) -> str:
    return "\n".join(
        [
            f"rtx {_directional_percent(flow.retransmission_rates_by_direction)}",
            f"loss {_directional_percent(flow.packet_loss_rates_by_direction)}",
            f"ooo {_directional_percent(flow.out_of_order_rates_by_direction)}",
            f"rtt {_rtt(flow)}",
            f"rate {flow.packet_rate_per_second:.1f} pps",
            f"thr {flow.throughput_mbps:.3f} Mbps",
        ]
    )


def _percent(value: float) -> str:
    percent = value * 100
    if percent == 0:
        return "0%"
    if percent < 0.1:
        return f"{percent:.3f}%"
    return f"{percent:.1f}%"


def _directional_percent(values: tuple[float, float]) -> str:
    return f"{_percent(values[0])}/{_percent(values[1])}"


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
