from __future__ import annotations

import ipaddress
import json
import os
import queue
import re
import threading
import time
from collections.abc import Callable
from contextvars import ContextVar
from typing import Any, Literal, TypeVar

from dotenv import load_dotenv
from openai import APIStatusError, APITimeoutError, OpenAI
from pydantic import ValidationError

from .deep_tools import run_deep_tool
from .models import AgentChatResponse, CaptureSummary, ReasoningReport
from .paths import runtime_private_dir
from .protocols.registry import (
    PROTOCOL_REGISTRY,
    deep_tool_guidance_prompt,
    protocol_name_for_deep_tool,
)

AnalysisFocus = Literal["transport", "security"]
T = TypeVar("T")

load_dotenv(runtime_private_dir() / ".env")
load_dotenv()

DEFAULT_MODEL = os.getenv("FLOWPILOT_MODEL", "gpt-5-mini")
OPENAI_BASE_URL = os.getenv("FLOWPILOT_OPENAI_BASE_URL")
LLM_API = os.getenv("FLOWPILOT_LLM_API", "responses").lower()
LLM_REQUESTS_PER_MINUTE = int(os.getenv("FLOWPILOT_LLM_REQUESTS_PER_MINUTE", "120"))
LLM_TIMEOUT_SECONDS = float(os.getenv("FLOWPILOT_LLM_TIMEOUT_SECONDS", "120"))
_last_llm_request_at = 0.0
EVIDENCE_START_OFFSET: ContextVar[int] = ContextVar("evidence_start_offset", default=0)

SYSTEM_PROMPT = f"""You are FlowPilot, a network transport troubleshooting agent for data-transfer
issues. Do not merely summarize the flows. Diagnose likely transport issues from derived metadata.
This is not a cybersecurity audit, vulnerability assessment, compliance review, or threat
investigation unless the user explicitly asks for one.

Prioritize network transport evidence: throughput over duration, one-way traffic, TCP loss,
TCP retransmissions, duplicate ACKs, out-of-order delivery, resets, zero windows, RTT
median/p95/max/initial RTT, UDP/datagram visibility limits, protocol or port blocking,
MTU/path issues, congestion, shaping/policing, asymmetric routing, and tunnel health.
Treat protocol names, filenames, and application names as supporting context unless they
directly explain a transport symptom.

When asked for throughput in each direction (A to B and B to A), return the numeric
throughput_mbps_by_direction values with Mbps units and the actual endpoint labels.
These rates are already calculated locally, including when a saved summary is loaded.
Packet rates are supplied as packet_rate_per_second_by_direction in packets/s.
Both lists are ordered [endpoint_a_to_endpoint_b, endpoint_b_to_endpoint_a].
Report packet rate and throughput separately for each direction; do not add the two
directions into an aggregate rate or reuse aggregate rates from prior chat history.
Use the same full-flow duration for both directions and state that averaging interval.
Do not substitute calculation instructions or ask the user to calculate available metrics.
ESP encryption does not prevent measuring observed directional throughput; it does prevent
equating it with inner application goodput. A null rate means the duration is unavailable
or zero, so explain that limitation instead of reporting zero or inventing a rate.
If the intended flow is ambiguous, ask which Flow ID; do not choose unrelated endpoints.

For follow-up diagnostic questions, analyze the supplied flow data first. Start with a
conclusion (supported issue, no supporting evidence, or insufficient measurement), then
cite the actual values and their meaning for that exact Flow ID. Recommendations come
after the assessment; never replace analysis with instructions to collect data already
provided. Do not claim the capture or flow table was not shared when requested_flow is found.
For latency questions, use transport.rtt.initial_ms and transport.rtt.assessment plus any
matching deep-tool timing evidence. An initial RTT is a handshake measurement, not proof
of sustained or excessive latency without a baseline. Missing RTT is unknown, not zero
latency or proof of a healthy path. For ESP, encrypted outer packets alone do not expose
inner request/response latency. Cite directional loss/reordering/retransmission evidence
as possible transport symptoms, not latency measurements. Low throughput, a long flow,
and inter-packet gaps do not by themselves prove latency. If another measurement is needed
and an allowed tool can obtain it, request the tool rather than telling the user to run it.

Only discuss protocols that are present in the provided metadata, present in additional tool
evidence, or explicitly asked about by the user. Do not add checklist-style negative statements
for absent protocols, such as "No TCP, SMB, SIP, DHCP, or ESP issue is evidenced", unless that
absence directly answers the user's question.
Do not invent IP addresses, endpoints, ports, hostnames, URLs, or flow identities. Any IP
address or endpoint you mention must appear in the current summary.flow_endpoint_inventory,
top_flows, requested_flow, or additional_tool_evidence target_flow/deep samples. If an
endpoint appears only in prior chat history but not in the current FlowPilot metadata, treat
it as unverified and do not use it as a finding.

For ESP/IPsec and other encrypted/datagram flows, explicitly state what cannot be proven from
the metadata, but still reason from duration, bytes, throughput_mbps_by_direction, packet
sequence gaps, missing sequence numbers, duplicate sequence numbers, out-of-order sequence
numbers, and peer behavior. Treat sequence anomalies as stronger evidence for packet loss,
replay/duplicate delivery, capture loss, or path reordering than byte counts alone. If a flow
has high bytes but low throughput, treat that as a potential performance finding and recommend
concrete next checks such as tunnel counters, anti-replay drops, MTU/MSS, fragmentation,
QoS/policing, path loss, CPU/crypto load, or comparing both endpoints.

Every finding must include evidence from the provided fields and a recommended action. Avoid generic
restatements of packet counts unless they support a hypothesis. Return concise JSON matching the
requested schema. Protocol-specific guidance is supplied separately based only on protocols present
in the metadata or additional deep evidence.

Tool access is delegated through the JSON evidence_requests field; you do not call
tools directly. Deep packet samples are paged: inspect batch.offset, returned,
total_matching_packets, has_more, and next_offset. This is only one batch, not the
entire flow. When more details are needed, request the same tool and flow_id with
sample_offset set to batch.next_offset. Aggregate counters cover the full matching
flow and repeat across batches; never sum those counters across pages. Do not claim
all packets were inspected unless every batch was supplied. If the tool budget stops
pagination, state which details remain unexamined and that more batches are available.
Tool access is delegated through the JSON evidence_requests field; you do not call
tools directly. If more packet evidence is needed, do not say you lack access to
an allowed tool. Instead, add an evidence_requests item with one allow-listed tool,
the Flow ID, and a concise reason. FlowPilot/LangGraph will run the requested tool
and call you again with additional_tool_evidence. {deep_tool_guidance_prompt()}
Flow IDs start at 1 and must reference entries from the provided top_flows list.
Each top_flows item includes flow_id and flow_label. If the user asks about a
specific Flow ID, use only the top_flows item and additional_tool_evidence whose
flow_id exactly matches that number. Do not answer a Flow ID question with
endpoints from another flow. If the requested Flow ID is not present in top_flows
or additional_tool_evidence, say that exact flow is not in the provided metadata.
Do not invent tools."""

TRANSPORT_FOCUS_PROMPT = """Transport focus is enabled. The user wants data-transfer and
session troubleshooting, not a security analysis. If deep TLS/DTLS evidence includes
certificates, cipher suites, hash/signature algorithms, supported groups, or alerts, use those
fields only to explain handshake compatibility, authentication/session failure, protocol
reachability, or why a transfer stopped. Do not label the answer as security analysis, do not
rank security posture, and do not discuss weak ciphers, certificate hygiene, CVEs, threat
activity, or compliance unless the user explicitly asks or --analysis-focus security is selected."""

SECURITY_FOCUS_PROMPT = """Security focus is enabled. Prioritize security-relevant evidence
visible in the capture metadata: TLS/DTLS certificate validity, issuer/subject/SAN consistency,
TLS alerts, cipher/hash/signature/group negotiation, SMB encryption/signing/capabilities,
unexpected cleartext protocols, suspicious DNS responses, and authentication/session failures.
Still distinguish security findings from transport findings, and do not claim vulnerabilities
that are not evidenced by the supplied metadata."""


def openai_client() -> OpenAI:
    if OPENAI_BASE_URL:
        return OpenAI(base_url=OPENAI_BASE_URL, timeout=LLM_TIMEOUT_SECONDS)
    return OpenAI(timeout=LLM_TIMEOUT_SECONDS)


def openai_models_url() -> str:
    base_url = OPENAI_BASE_URL or "https://api.openai.com/v1"
    return f"{base_url.rstrip('/')}/models"


def list_openai_models() -> list[dict[str, object]]:
    _respect_llm_rate_limit()
    models = openai_client().models.list()
    return sorted(
        [
            {
                "id": model.id,
                "owned_by": getattr(model, "owned_by", None),
                "created": getattr(model, "created", None),
            }
            for model in models.data
        ],
        key=lambda model: str(model["id"]),
    )


def reason_about_capture(
    summary: CaptureSummary,
    *,
    model: str = DEFAULT_MODEL,
    max_flows: int = 25,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> ReasoningReport:
    analysis_focus = _normalized_analysis_focus(analysis_focus)
    try:
        return _run_with_wall_timeout(
            lambda: _reason_about_capture_sync(
                summary,
                model=model,
                max_flows=max_flows,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            ),
            timeout_seconds=LLM_TIMEOUT_SECONDS,
            timeout_result=_empty_llm_report(
                _wall_clock_timeout_message("LLM reasoning")
            ),
        )
    except APITimeoutError:
        return _empty_llm_report(
            f"LLM request timed out after {LLM_TIMEOUT_SECONDS:g} seconds."
        )


def chat_about_capture(
    summary: CaptureSummary,
    question: str,
    *,
    model: str = DEFAULT_MODEL,
    max_flows: int = 25,
    report: ReasoningReport | None = None,
    history: list[dict[str, str]] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> str:
    if answer := _local_throughput_answer(summary, question):
        return answer
    analysis_focus = _normalized_analysis_focus(analysis_focus)
    try:
        return _run_with_wall_timeout(
            lambda: _chat_about_capture_sync(
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            ),
            timeout_seconds=LLM_TIMEOUT_SECONDS,
            timeout_result=_wall_clock_timeout_message("LLM chat"),
        )
    except APITimeoutError:
        return f"The LLM request timed out after {LLM_TIMEOUT_SECONDS:g} seconds."


def agent_chat_about_capture(
    summary: CaptureSummary,
    question: str,
    *,
    model: str = DEFAULT_MODEL,
    max_flows: int = 25,
    report: ReasoningReport | None = None,
    history: list[dict[str, str]] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> AgentChatResponse:
    if answer := _local_throughput_answer(summary, question):
        return AgentChatResponse(answer=answer)
    analysis_focus = _normalized_analysis_focus(analysis_focus)
    try:
        return _run_with_wall_timeout(
            lambda: _agent_chat_about_capture_sync(
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            ),
            timeout_seconds=LLM_TIMEOUT_SECONDS,
            timeout_result=AgentChatResponse(
                answer=_wall_clock_timeout_message("LLM agent chat")
            ),
        )
    except APITimeoutError:
        return AgentChatResponse(
            answer=f"The LLM request timed out after {LLM_TIMEOUT_SECONDS:g} seconds."
        )


def _reason_about_capture_sync(
    summary: CaptureSummary,
    *,
    model: str,
    max_flows: int,
    additional_evidence: list[dict[str, Any]] | None,
    analysis_focus: AnalysisFocus,
) -> ReasoningReport:
    client = openai_client()
    if LLM_API in {"chat", "chat_completions", "chat-completions"}:
        return _reason_with_chat_completions(
            client,
            summary,
            model=model,
            max_flows=max_flows,
            additional_evidence=additional_evidence,
            analysis_focus=analysis_focus,
        )
    if LLM_API == "auto":
        try:
            return _reason_with_responses(
                client,
                summary,
                model=model,
                max_flows=max_flows,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            )
        except APIStatusError as exc:
            if exc.status_code != 404:
                raise
            return _reason_with_chat_completions(
                client,
                summary,
                model=model,
                max_flows=max_flows,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            )
    return _reason_with_responses(
        client,
        summary,
        model=model,
        max_flows=max_flows,
        additional_evidence=additional_evidence,
        analysis_focus=analysis_focus,
    )


def _chat_about_capture_sync(
    summary: CaptureSummary,
    question: str,
    *,
    model: str,
    max_flows: int,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None,
    analysis_focus: AnalysisFocus,
) -> str:
    client = openai_client()
    if LLM_API in {"chat", "chat_completions", "chat-completions"}:
        answer = _chat_with_chat_completions(
            client,
            summary,
            question,
            model=model,
            max_flows=max_flows,
            report=report,
            history=history,
            additional_evidence=additional_evidence,
            analysis_focus=analysis_focus,
        )
        return _guard_answer_ips(
            answer,
            summary,
            question=question,
            max_flows=max_flows,
            additional_evidence=additional_evidence,
        )
    if LLM_API == "auto":
        try:
            answer = _chat_with_responses(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            )
        except APIStatusError as exc:
            if exc.status_code != 404:
                raise
            answer = _chat_with_chat_completions(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            )
        return _guard_answer_ips(
            answer,
            summary,
            question=question,
            max_flows=max_flows,
            additional_evidence=additional_evidence,
        )
    answer = _chat_with_responses(
        client,
        summary,
        question,
        model=model,
        max_flows=max_flows,
        report=report,
        history=history,
        additional_evidence=additional_evidence,
        analysis_focus=analysis_focus,
    )
    return _guard_answer_ips(
        answer,
        summary,
        question=question,
        max_flows=max_flows,
        additional_evidence=additional_evidence,
    )


def _agent_chat_about_capture_sync(
    summary: CaptureSummary,
    question: str,
    *,
    model: str,
    max_flows: int,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None,
    analysis_focus: AnalysisFocus,
) -> AgentChatResponse:
    client = openai_client()
    if LLM_API in {"chat", "chat_completions", "chat-completions"}:
        response = _agent_chat_with_chat_completions(
            client,
            summary,
            question,
            model=model,
            max_flows=max_flows,
            report=report,
            history=history,
            additional_evidence=additional_evidence,
            analysis_focus=analysis_focus,
        )
        return _guard_agent_chat_response_ips(
            response,
            summary,
            question=question,
            max_flows=max_flows,
            additional_evidence=additional_evidence,
        )
    if LLM_API == "auto":
        try:
            response = _agent_chat_with_responses(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            )
        except APIStatusError as exc:
            if exc.status_code != 404:
                raise
            response = _agent_chat_with_chat_completions(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            )
        return _guard_agent_chat_response_ips(
            response,
            summary,
            question=question,
            max_flows=max_flows,
            additional_evidence=additional_evidence,
        )
    response = _agent_chat_with_responses(
        client,
        summary,
        question,
        model=model,
        max_flows=max_flows,
        report=report,
        history=history,
        additional_evidence=additional_evidence,
        analysis_focus=analysis_focus,
    )
    return _guard_agent_chat_response_ips(
        response,
        summary,
        question=question,
        max_flows=max_flows,
        additional_evidence=additional_evidence,
    )


def _run_with_wall_timeout(
    function: Callable[[], T],
    *,
    timeout_seconds: float,
    timeout_result: T,
) -> T:
    if timeout_seconds <= 0:
        return function()
    results: queue.Queue[tuple[str, T | BaseException]] = queue.Queue(maxsize=1)

    def target() -> None:
        try:
            results.put(("result", function()))
        except BaseException as exc:  # pragma: no cover - passes through provider boundary
            results.put(("error", exc))

    thread = threading.Thread(target=target, daemon=True, name="flowpilot-llm-request")
    thread.start()
    try:
        kind, value = results.get(timeout=timeout_seconds)
    except queue.Empty:
        return timeout_result
    if kind == "error":
        raise value
    return value


def _wall_clock_timeout_message(operation: str) -> str:
    return (
        f"FlowPilot stopped waiting for {operation} after "
        f"{LLM_TIMEOUT_SECONDS:g} seconds. Local analysis and any completed deep evidence "
        "remain available, but the LLM provider did not return before the wall-clock timeout."
    )


def _with_saved_evidence(
    summary: CaptureSummary, compact_summary: dict[str, Any],
    evidence: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    """Attach bounded previews; complete saved rows stay local for batch retrieval."""
    result = list(evidence or [])
    start_offset = EVIDENCE_START_OFFSET.get()
    present = {
        (item.get("tool"), item.get("flow_id")) for item in result
        if item.get("batch", {}).get("offset", 0) == start_offset
    }
    for metadata in compact_summary.get("top_flows", []):
        flow_id = metadata["flow_id"]
        flow = summary.flows[flow_id - 1]
        for tool, details in flow.deep_details.items():
            if details.get("status") != "ok" or (tool, flow_id) in present:
                continue
            batch = run_deep_tool(tool, None, flow_id=flow_id, flow=flow,
                                  reason="Saved detailed summary preview",
                                  sample_offset=start_offset)
            batch["target_flow"] = {
                key: metadata[key] for key in (
                    "flow_id", "flow_label", "protocol", "endpoint_a", "endpoint_b",
                    "port_a", "port_b",
                )
            }
            result.append(batch)
    return result


def _reason_with_responses(
    client: OpenAI,
    summary: CaptureSummary,
    *,
    model: str,
    max_flows: int,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> ReasoningReport:
    _respect_llm_rate_limit()
    compact_summary = summary.compact(max_flows=max_flows)
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    response = client.responses.parse(
        model=model,
        instructions=_system_prompt(
            analysis_focus,
            compact_summary=compact_summary,
            additional_evidence=additional_evidence,
        ),
        input=[
            {
                "role": "user",
                "content": (
                    "Diagnose likely data-transfer issues in this packet-capture summary. "
                    "Return findings, hypotheses, and next checks. Do not just summarize flows. "
                    "If deeper packet evidence is needed, request it through the "
                    "evidence_requests JSON field; do not claim tool access is unavailable. "
                    "Pay special attention to long-lived low-throughput ESP/IPsec or UDP flows, "
                    "one-way flows, packet gaps, TCP issue counters, SIP call failures, "
                    "SMB transfer inefficiency or errors, "
                    "and certificate/redirect clues.\n\n"
                    f"{_reasoning_payload(compact_summary, additional_evidence, analysis_focus)}"
                ),
            }
        ],
        text_format=ReasoningReport,
    )
    if response.output_parsed:
        return response.output_parsed
    return _empty_llm_report("Responses API returned no parsed reasoning content.")


def _reason_with_chat_completions(
    client: OpenAI,
    summary: CaptureSummary,
    *,
    model: str,
    max_flows: int,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> ReasoningReport:
    _respect_llm_rate_limit()
    compact_summary = summary.compact(max_flows=max_flows)
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": _system_prompt(
                    analysis_focus,
                    compact_summary=compact_summary,
                    additional_evidence=additional_evidence,
                ),
            },
            {
                "role": "user",
                "content": (
                    "Return only JSON matching this JSON Schema:\n"
                    f"{json.dumps(ReasoningReport.model_json_schema(), indent=2)}\n\n"
                    "Diagnose likely data-transfer issues in this packet-capture summary. "
                    "Return findings, hypotheses, and next checks. Do not just summarize flows. "
                    "If deeper packet evidence is needed, request it through the "
                    "evidence_requests JSON field; do not claim tool access is unavailable. "
                    "Pay special attention to long-lived low-throughput ESP/IPsec or UDP flows, "
                    "one-way flows, packet gaps, TCP issue counters, SIP call failures, "
                    "SMB transfer inefficiency or errors, "
                    "and certificate/redirect clues.\n\n"
                    f"{_reasoning_payload(compact_summary, additional_evidence, analysis_focus)}"
                ),
            },
        ],
        response_format={"type": "json_object"},
    )
    content = response.choices[0].message.content
    if not content:
        return _empty_llm_report("Chat completions response did not include message content.")
    return ReasoningReport.model_validate(_json_object(content))


def _chat_with_responses(
    client: OpenAI,
    summary: CaptureSummary,
    question: str,
    *,
    model: str,
    max_flows: int,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> str:
    _respect_llm_rate_limit()
    compact_summary = summary.compact(
        max_flows=max_flows, include_flow_id=_requested_flow_id(question)
    )
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    response = client.responses.create(
        model=model,
        instructions=_chat_system_prompt(
            analysis_focus,
            compact_summary=compact_summary,
            additional_evidence=additional_evidence,
        ),
        input=_chat_input(
            compact_summary,
            question,
            report=report,
            history=history,
            additional_evidence=additional_evidence,
            analysis_focus=analysis_focus,
        ),
    )
    answer = getattr(response, "output_text", None)
    if answer:
        return str(answer)
    return str(response)


def _chat_with_chat_completions(
    client: OpenAI,
    summary: CaptureSummary,
    question: str,
    *,
    model: str,
    max_flows: int,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> str:
    _respect_llm_rate_limit()
    compact_summary = summary.compact(
        max_flows=max_flows, include_flow_id=_requested_flow_id(question)
    )
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": _chat_system_prompt(
                    analysis_focus,
                    compact_summary=compact_summary,
                    additional_evidence=additional_evidence,
                ),
            },
            *_chat_input(
                compact_summary,
                question,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            ),
        ],
    )
    content = _chat_choice_text(response.choices[0])
    if not content:
        return _empty_chat_message(
            "Plain chat-completions request returned an empty assistant message. "
            "For deep tools, run with --agent --chat and include a tool name plus Flow ID."
        )
    return content


def _agent_chat_with_responses(
    client: OpenAI,
    summary: CaptureSummary,
    question: str,
    *,
    model: str,
    max_flows: int,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> AgentChatResponse:
    _respect_llm_rate_limit()
    compact_summary = summary.compact(
        max_flows=max_flows, include_flow_id=_requested_flow_id(question)
    )
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    response = client.responses.parse(
        model=model,
        instructions=_agent_chat_system_prompt(
            analysis_focus,
            compact_summary=compact_summary,
            additional_evidence=additional_evidence,
        ),
        input=_chat_input(
            compact_summary,
            question,
            report=report,
            history=history,
            additional_evidence=additional_evidence,
            analysis_focus=analysis_focus,
        ),
        text_format=AgentChatResponse,
    )
    if response.output_parsed:
        return response.output_parsed
    return AgentChatResponse(answer="Responses API returned no parsed chat content.")


def _agent_chat_with_chat_completions(
    client: OpenAI,
    summary: CaptureSummary,
    question: str,
    *,
    model: str,
    max_flows: int,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> AgentChatResponse:
    _respect_llm_rate_limit()
    compact_summary = summary.compact(
        max_flows=max_flows, include_flow_id=_requested_flow_id(question)
    )
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": _agent_chat_system_prompt(
                    analysis_focus,
                    compact_summary=compact_summary,
                    additional_evidence=additional_evidence,
                ),
            },
            {
                "role": "user",
                "content": (
                    "Return only JSON matching this JSON Schema:\n"
                    f"{json.dumps(AgentChatResponse.model_json_schema(), indent=2)}\n\n"
                ),
            },
            *_chat_input(
                compact_summary,
                question,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            ),
        ],
        response_format={"type": "json_object"},
    )
    content = _chat_choice_text(response.choices[0])
    if not content:
        return AgentChatResponse(
            answer=_agent_chat_plain_fallback(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
                structured_finish_reason=_choice_finish_reason(response.choices[0]),
            )
        )
    if _is_role_label_answer(content):
        return AgentChatResponse(
            answer=_agent_chat_plain_fallback(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
                structured_finish_reason=_choice_finish_reason(response.choices[0]),
            )
        )
    try:
        parsed = _json_object(content)
    except (json.JSONDecodeError, ValueError):
        return AgentChatResponse(answer=content)
    if "answer" not in parsed:
        parsed["answer"] = ""
    try:
        chat_response = AgentChatResponse.model_validate(parsed)
    except ValidationError:
        return AgentChatResponse(answer=content)
    if not chat_response.answer.strip() and not chat_response.evidence_requests:
        return AgentChatResponse(
            answer=_agent_chat_plain_fallback(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
                structured_finish_reason=_choice_finish_reason(response.choices[0]),
            )
        )
    if _is_role_label_answer(chat_response.answer):
        return AgentChatResponse(
            answer=_agent_chat_plain_fallback(
                client,
                summary,
                question,
                model=model,
                max_flows=max_flows,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
                structured_finish_reason=_choice_finish_reason(response.choices[0]),
            ),
            evidence_requests=chat_response.evidence_requests,
        )
    return chat_response


def _agent_chat_plain_fallback(
    client: OpenAI,
    summary: CaptureSummary,
    question: str,
    *,
    model: str,
    max_flows: int,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
    structured_finish_reason: str | None = None,
) -> str:
    _respect_llm_rate_limit()
    compact_summary = summary.compact(
        max_flows=max_flows, include_flow_id=_requested_flow_id(question)
    )
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    system_prompt = _system_prompt(
        analysis_focus,
        compact_summary=compact_summary,
        additional_evidence=additional_evidence,
    )
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": (
                    f"{system_prompt}\n\n"
                    "You are in interactive follow-up mode. Answer in plain text only. "
                    "Do not return JSON. If additional_tool_evidence is present, use it "
                    "as the newest and most specific packet evidence. Provide the final "
                    "answer directly from the supplied FlowPilot metadata and the user's "
                    "question. If deep evidence was provided, cite what it shows and do "
                    "not say the tool is unavailable."
                ),
            },
            *_chat_input(
                compact_summary,
                question,
                report=report,
                history=history,
                additional_evidence=additional_evidence,
                analysis_focus=analysis_focus,
            ),
        ],
    )
    content = _chat_choice_text(response.choices[0])
    if content:
        return content
    plain_finish_reason = _choice_finish_reason(response.choices[0])
    finish_detail = _finish_reason_detail(
        structured_finish_reason=structured_finish_reason,
        plain_finish_reason=plain_finish_reason,
    )
    return (
        "Agent chat ran the requested deep evidence path, but the LLM provider returned "
        "empty message content for both the structured chat request and the plain-text "
        f"fallback request.{finish_detail}"
    )


def _empty_llm_report(reason: str) -> ReasoningReport:
    return ReasoningReport(
        executive_summary=(
            "LLM reasoning did not return usable content. Local FlowPilot analysis completed; "
            f"{reason}"
        ),
        risk_level="unknown",
        findings=[],
        next_questions=[
            "Retry LLM reasoning or run with --no-llm to review local transport metrics.",
        ],
    )


def _chat_input(
    compact_summary: dict[str, Any] | CaptureSummary,
    question: str,
    *,
    report: ReasoningReport | None,
    history: list[dict[str, str]] | None,
    additional_evidence: list[dict[str, Any]] | None = None,
    analysis_focus: AnalysisFocus = "transport",
) -> list[dict[str, str]]:
    evidence = additional_evidence or []
    if isinstance(compact_summary, CaptureSummary):
        compact_summary = compact_summary.compact(include_flow_id=_requested_flow_id(question))
    context = {
        "current_question": question,
        "requested_analysis_focus": analysis_focus,
        "analysis_focus_instruction": _analysis_focus_instruction(analysis_focus),
        "summary": compact_summary,
        "requested_flow": _requested_flow_context(compact_summary, question),
        "initial_reasoning": report.model_dump(mode="json") if report else None,
        "additional_tool_evidence_count": len(evidence),
        "additional_tool_evidence": evidence,
    }
    messages = [
        {
            "role": "user",
            "content": (
                "Use this derived FlowPilot metadata as the fixed analysis context. "
                "Answer current_question below using this attached evidence. "
                "Do not assume access to raw packet payloads beyond this metadata. "
                "Treat additional_tool_evidence as the newest deep evidence. Use "
                "target_flow as the authoritative identity. Use only evidence matching "
                "the requested Flow ID. Do not cite endpoints absent from "
                "summary.flow_endpoint_inventory unless present in additional_tool_evidence. "
                "Current FlowPilot metadata supersedes prior chat history for IPs, "
                "endpoints, ports, hostnames, URLs, and flow identities.\n\n"
                f"{json.dumps(context, default=str)}"
            ),
        }
    ]
    # Keep the current task and its evidence in one self-contained message,
    # like initial analysis. Prior assistant replies must not separate them.
    current_content = "\n\n".join(message["content"] for message in messages)
    return [
        *(history or [])[-12:],
        {"role": "user", "content": current_content},
    ]


def _reasoning_payload(
    compact_summary: dict[str, Any] | CaptureSummary,
    additional_evidence: list[dict[str, Any]] | None,
    analysis_focus: AnalysisFocus = "transport",
) -> str:
    evidence = additional_evidence or []
    if isinstance(compact_summary, CaptureSummary):
        compact_summary = compact_summary.compact()
    payload = {
        "requested_analysis_focus": analysis_focus,
        "analysis_focus_instruction": _analysis_focus_instruction(analysis_focus),
        "summary": compact_summary,
        "additional_tool_evidence_count": len(evidence),
        "additional_tool_evidence": evidence,
    }
    return json.dumps(payload, default=str)


def _requested_flow_context(
    compact_summary: dict[str, Any],
    question: str,
) -> dict[str, Any] | None:
    requested_flow_id = _requested_flow_id(question)
    if requested_flow_id is None:
        return None
    for flow in compact_summary.get("top_flows", []):
        if isinstance(flow, dict) and flow.get("flow_id") == requested_flow_id:
            return {
                "flow_id": requested_flow_id,
                "match_status": "found",
                "flow": flow,
            }
    return {
        "flow_id": requested_flow_id,
        "match_status": "not_found",
        "message": "Requested Flow ID is not present in the provided top_flows metadata.",
    }


def _local_throughput_answer(summary: CaptureSummary, question: str) -> str | None:
    """Answer simple flow throughput lookups without provider interpretation."""
    match = re.fullmatch(
        r"\s*(?:(?:what\s+is|give\s+me|show\s+me|show)\s+)?(?:the\s+)?"
        r"(?:average\s+)?(?:throughput|thoughput)"
        r"(?:\s+from\s+(?P<source>\S+)\s+to\s+(?P<destination>\S+))?"
        r"\s+(?:(?:in|for|of)\s+)?flow\s*(?:id\s*)?[:#-]?\s*(?P<id>\d+)\s*[?.]?\s*",
        question,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    flow_id = int(match["id"])
    if not 1 <= flow_id <= len(summary.flows):
        return f"Flow ID {flow_id} is not present in the current summary."
    flow = summary.flows[flow_id - 1]
    a, b = flow.key.endpoint_a, flow.key.endpoint_b
    source, destination = match["source"], match["destination"]
    indices = [0, 1]
    if source is not None:
        pair = (source.lower(), destination.lower())
        if pair in {("a", "b"), (a.lower(), b.lower())}:
            indices = [0]
        elif pair in {("b", "a"), (b.lower(), a.lower())}:
            indices = [1]
        else:
            return None
    labels = [(a, b), (b, a)]
    rates = flow.throughput_mbps_by_direction
    lines = [f"Flow ID {flow_id} ({flow.key.protocol}):"]
    for index in indices:
        origin, target = labels[index]
        rate = rates[index]
        value = (
            "unavailable (missing or zero flow duration)"
            if rate is None else f"{rate:.6g} Mbps"
        )
        lines.append(f"{origin} → {target}: {value}.")
    if flow.duration_seconds > 0:
        lines.append(f"Average over the full flow duration of {flow.duration_seconds:g} seconds.")
    if flow.key.protocol.upper() == "ESP":
        lines.append("Measures observed encrypted traffic, not inner application goodput.")
    return "\n".join(lines)


def _requested_flow_id(question: str) -> int | None:
    patterns = (
        r"\bflow\s*id\s*[:#-]?\s*(\d+)\b",
        r"\bflow\s*#\s*(\d+)\b",
        r"\bflow\s+(\d+)\b",
    )
    for pattern in patterns:
        match = re.search(pattern, question, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _chat_system_prompt(
    analysis_focus: AnalysisFocus = "transport",
    *,
    compact_summary: dict[str, Any] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
) -> str:
    system_prompt = _system_prompt(
        analysis_focus,
        compact_summary=compact_summary,
        additional_evidence=additional_evidence,
    )
    return (
        f"{system_prompt}\n\n"
        "You are now in interactive follow-up mode. Answer the user's question directly. "
        "Use the provided metadata and prior reasoning as the source of truth. If the answer "
        "cannot be proven from the metadata, say what is unknown and suggest the next check. "
        "Do not return JSON unless the user explicitly asks for JSON."
    )


def _agent_chat_system_prompt(
    analysis_focus: AnalysisFocus = "transport",
    *,
    compact_summary: dict[str, Any] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
) -> str:
    system_prompt = _system_prompt(
        analysis_focus,
        compact_summary=compact_summary,
        additional_evidence=additional_evidence,
    )
    return (
        f"{system_prompt}\n\n"
        "You are now in interactive follow-up mode. Return JSON matching the requested schema. "
        "Put the user-facing response in answer. If the user asks you to inspect a specific "
        "flow or to use an allowed deep tool, request that tool in evidence_requests instead "
        "of saying you cannot call it. If additional_tool_evidence already contains the needed "
        "tool result, answer from that evidence and leave evidence_requests empty."
    )


def _system_prompt(
    analysis_focus: AnalysisFocus = "transport",
    *,
    compact_summary: dict[str, Any] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
) -> str:
    focus_prompt = SECURITY_FOCUS_PROMPT if analysis_focus == "security" else TRANSPORT_FOCUS_PROMPT
    protocol_prompt = _protocol_focus_prompt(
        analysis_focus,
        compact_summary=compact_summary,
        additional_evidence=additional_evidence,
    )
    sections = [SYSTEM_PROMPT, focus_prompt]
    if protocol_prompt:
        sections.append(protocol_prompt)
    return "\n\n".join(sections)


def _protocol_focus_prompt(
    analysis_focus: AnalysisFocus,
    *,
    compact_summary: dict[str, Any] | None,
    additional_evidence: list[dict[str, Any]] | None,
) -> str:
    present = _present_protocol_registry_names(compact_summary or {}, additional_evidence or [])
    prompt_field = "security_prompt" if analysis_focus == "security" else "transport_prompt"
    lines = [
        getattr(PROTOCOL_REGISTRY[name], prompt_field)
        for name in sorted(present)
        if getattr(PROTOCOL_REGISTRY[name], prompt_field)
    ]
    if not lines:
        return ""
    return (
        "Protocol-specific guidance for protocols present in this metadata:\n"
        + "\n".join(f"- {line}" for line in lines)
    )


def _present_protocol_registry_names(
    compact_summary: dict[str, Any],
    additional_evidence: list[dict[str, Any]],
) -> set[str]:
    present: set[str] = set()
    for protocol_name in compact_summary.get("protocols", {}):
        transport = str(protocol_name).lower()
        if transport in PROTOCOL_REGISTRY:
            present.add(transport)
        if transport == "tcp":
            present.add("tcp")
        if transport == "udp":
            present.add("udp")

    for flow in compact_summary.get("top_flows", []):
        if not isinstance(flow, dict):
            continue
        transport = str(flow.get("protocol", "")).lower()
        if transport in PROTOCOL_REGISTRY:
            present.add(transport)
        _add_flow_protocol_metadata(present, flow)

    for evidence in additional_evidence:
        if not isinstance(evidence, dict):
            continue
        tool_name = evidence.get("tool")
        if protocol_name := protocol_name_for_deep_tool(str(tool_name)):
            present.add(protocol_name)
        if evidence.get("tls_metadata_counts"):
            present.add("tls")
        if evidence.get("udp_metadata_counts"):
            present.add("udp")
        if evidence.get("tcp_analysis_counts"):
            present.add("tcp")
        if evidence.get("smb2_credit_counts"):
            present.add("smb")
    return present


def _add_flow_protocol_metadata(present: set[str], flow: dict[str, Any]) -> None:
    if flow.get("tls_certificates") or flow.get("tls_snis") or flow.get("tls_alerts"):
        present.add("tls")
    if flow.get("esp_spis") or flow.get("esp_sequences"):
        present.add("esp")
    for name in ("sip", "smb", "dns", "dhcp", "rtp", "ike"):
        metadata = flow.get(name)
        if isinstance(metadata, dict) and any(
            _metadata_value_present(value) for value in metadata.values()
        ):
            present.add(name)


def _metadata_value_present(value: Any) -> bool:
    if value in (None, "", [], {}, 0, 0.0, False):
        return False
    return True


def _analysis_focus_instruction(analysis_focus: AnalysisFocus) -> str:
    if analysis_focus == "security":
        return "Prioritize security-relevant metadata and distinguish it from transport findings."
    return (
        "Prioritize transport/session troubleshooting. Deep TLS certificate/cipher/hash fields "
        "are compatibility/session evidence, not a request for security analysis."
    )


def _normalized_analysis_focus(value: str) -> AnalysisFocus:
    if value == "security":
        return "security"
    return "transport"


def _json_object(content: str) -> dict[str, Any]:
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start == -1 or end == -1 or end <= start:
            raise
        parsed = json.loads(content[start : end + 1])
    if not isinstance(parsed, dict):
        raise ValueError("Expected model response to be a JSON object.")
    return parsed


def _is_role_label_answer(answer: str) -> bool:
    return answer.strip().lower().strip(' "\'`') in {"assistant", "user", "system", "model"}


def _message_content_text(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text") or item.get("content") or ""))
            else:
                parts.append(str(item))
        return "\n".join(part for part in parts if part).strip()
    return str(content).strip()


def _chat_choice_text(choice: Any) -> str:
    message = getattr(choice, "message", None)
    if message is None:
        return ""
    content = _message_content_text(getattr(message, "content", None))
    if content:
        return content
    for field in ("text", "reasoning_content", "output_text"):
        content = _message_content_text(getattr(message, field, None))
        if content:
            return content
    dumped = _model_dump(message)
    if dumped:
        return _first_nested_text(dumped)
    return ""


def _first_nested_text(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        for key in ("content", "text", "reasoning_content", "output_text"):
            text = _first_nested_text(value.get(key))
            if text:
                return text
        for nested in value.values():
            text = _first_nested_text(nested)
            if text:
                return text
    if isinstance(value, list):
        parts = [_first_nested_text(item) for item in value]
        return "\n".join(part for part in parts if part).strip()
    return ""


def _choice_finish_reason(choice: Any) -> str | None:
    reason = getattr(choice, "finish_reason", None)
    return str(reason) if reason is not None else None


def _finish_reason_detail(
    *,
    structured_finish_reason: str | None,
    plain_finish_reason: str | None,
) -> str:
    reasons = []
    if structured_finish_reason:
        reasons.append(f"structured_finish_reason={structured_finish_reason}")
    if plain_finish_reason:
        reasons.append(f"plain_finish_reason={plain_finish_reason}")
    return " " + " ".join(reasons) if reasons else ""


def _guard_agent_chat_response_ips(
    response: AgentChatResponse,
    summary: CaptureSummary,
    *,
    max_flows: int,
    question: str = "",
    additional_evidence: list[dict[str, Any]] | None,
) -> AgentChatResponse:
    if additional_evidence and _claims_additional_evidence_missing(response.answer):
        return response.model_copy(
            update={
                "answer": _attached_evidence_guard_message(additional_evidence),
                "evidence_requests": [],
            }
        )
    guarded_answer = _guard_answer_ips(
        response.answer,
        summary,
        question=question,
        max_flows=max_flows,
        additional_evidence=additional_evidence,
    )
    if guarded_answer == response.answer:
        return response
    return response.model_copy(update={"answer": guarded_answer, "evidence_requests": []})


def _claims_additional_evidence_missing(answer: str) -> bool:
    normalized = re.sub(r"\s+", " ", answer.strip().lower())
    if (
        "additional_tool_evidence" not in normalized
        and "additional tool evidence" not in normalized
    ):
        return False
    missing_terms = (
        "missing",
        "empty",
        "not provided",
        "not passed",
        "not attached",
        "not available",
        "no evidence",
        "cannot verify",
        "verify that flowpilot",
    )
    return any(term in normalized for term in missing_terms)


def _attached_evidence_guard_message(additional_evidence: list[dict[str, Any]]) -> str:
    evidence_lines = []
    for index, evidence in enumerate(additional_evidence, start=1):
        tool = evidence.get("tool", "unknown_tool")
        flow_id = evidence.get("flow_id", "unknown")
        status = evidence.get("status", "unknown")
        packet_count = evidence.get("packet_count")
        detail = f"{index}. {tool} for Flow ID {flow_id}: status={status}"
        if packet_count is not None:
            detail += f", packets={packet_count}"
        if target_flow := evidence.get("target_flow"):
            detail += f", target_flow={target_flow}"
        evidence_lines.append(detail)
    return (
        "FlowPilot attached additional_tool_evidence to this chat turn, but the LLM "
        "provider returned an answer claiming that evidence was missing or empty. "
        "That provider answer was suppressed.\n\n"
        "Attached deep evidence:\n"
        + "\n".join(evidence_lines)
        + "\n\nAsk the follow-up again, or ask about one of the attached evidence fields; "
        "FlowPilot will keep passing this deep evidence as additional_tool_evidence."
    )


def _guard_answer_ips(
    answer: str,
    summary: CaptureSummary,
    *,
    max_flows: int,
    question: str = "",
    additional_evidence: list[dict[str, Any]] | None,
) -> str:
    compact_summary = summary.compact(
        max_flows=max_flows, include_flow_id=_requested_flow_id(question)
    )
    additional_evidence = _with_saved_evidence(summary, compact_summary, additional_evidence)
    invalid_ips = _unverified_answer_ips(
        answer,
        compact_summary,
        additional_evidence or [],
    )
    if not invalid_ips:
        return answer
    inventory = compact_summary.get("flow_endpoint_inventory", {})
    valid_endpoints = ", ".join(inventory.get("endpoint_ports", [])[:20]) or "none"
    return (
        "FlowPilot suppressed the LLM answer because it mentioned IP address(es) "
        "that are not present in the current pcap metadata or deep evidence: "
        f"{', '.join(invalid_ips)}.\n\n"
        f"Valid observed flow endpoints provided to the LLM: {valid_endpoints}.\n\n"
        "Ask again using the Flow ID or run the relevant deep tool; FlowPilot will only "
        "trust endpoints present in the current capture metadata."
    )


def _unverified_answer_ips(
    answer: str,
    compact_summary: dict[str, Any],
    additional_evidence: list[dict[str, Any]],
) -> list[str]:
    mentioned_ips = _ips_in_text(answer)
    if not mentioned_ips:
        return []
    allowed_ips = _ips_in_value(compact_summary) | _ips_in_value(additional_evidence)
    return sorted(mentioned_ips - allowed_ips)


def _ips_in_value(value: Any) -> set[str]:
    if isinstance(value, str):
        return _ips_in_text(value)
    if isinstance(value, dict):
        ips: set[str] = set()
        for nested in value.values():
            ips.update(_ips_in_value(nested))
        return ips
    if isinstance(value, (list, tuple, set)):
        ips: set[str] = set()
        for nested in value:
            ips.update(_ips_in_value(nested))
        return ips
    return set()


def _ips_in_text(text: str) -> set[str]:
    candidates = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    ips = set()
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4:
            ips.add(str(address))
    return ips


def _model_dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        dumped = value.model_dump()
        return dumped if isinstance(dumped, dict) else {}
    if hasattr(value, "dict"):
        dumped = value.dict()
        return dumped if isinstance(dumped, dict) else {}
    return {}


def _empty_chat_message(reason: str) -> str:
    return (
        "LLM chat returned no usable text. "
        f"{reason}"
    )


def _respect_llm_rate_limit() -> None:
    global _last_llm_request_at

    if LLM_REQUESTS_PER_MINUTE <= 0:
        return

    minimum_interval = 60 / LLM_REQUESTS_PER_MINUTE
    now = time.monotonic()
    wait_seconds = minimum_interval - (now - _last_llm_request_at)
    if wait_seconds > 0:
        time.sleep(wait_seconds)
    _last_llm_request_at = time.monotonic()
