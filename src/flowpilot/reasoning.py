from __future__ import annotations

import json
import os
import time
from typing import Any, Literal

from dotenv import load_dotenv
from openai import APIStatusError, APITimeoutError, OpenAI
from pydantic import ValidationError

from .models import AgentChatResponse, CaptureSummary, ReasoningReport
from .protocols.registry import PROTOCOL_REGISTRY

AnalysisFocus = Literal["transport", "security"]

load_dotenv()

DEFAULT_MODEL = os.getenv("FLOWPILOT_MODEL", "gpt-5-mini")
OPENAI_BASE_URL = os.getenv("FLOWPILOT_OPENAI_BASE_URL")
LLM_API = os.getenv("FLOWPILOT_LLM_API", "responses").lower()
LLM_REQUESTS_PER_MINUTE = int(os.getenv("FLOWPILOT_LLM_REQUESTS_PER_MINUTE", "120"))
LLM_TIMEOUT_SECONDS = float(os.getenv("FLOWPILOT_LLM_TIMEOUT_SECONDS", "120"))
_last_llm_request_at = 0.0

SYSTEM_PROMPT = """You are FlowPilot, a network transport troubleshooting agent for data-transfer
issues. Do not merely summarize the flows. Diagnose likely transport issues from derived metadata.
This is not a cybersecurity audit, vulnerability assessment, compliance review, or threat
investigation unless the user explicitly asks for one.

Prioritize network transport evidence: throughput over duration, one-way traffic, TCP loss,
TCP retransmissions, duplicate ACKs, out-of-order delivery, resets, zero windows, RTT
median/p95/max/initial RTT, UDP/datagram visibility limits, protocol or port blocking,
MTU/path issues, congestion, shaping/policing, asymmetric routing, and tunnel health.
Treat protocol names, filenames, and application names as supporting context unless they
directly explain a transport symptom.

Only discuss protocols that are present in the provided metadata, present in additional tool
evidence, or explicitly asked about by the user. Do not add checklist-style negative statements
for absent protocols, such as "No TCP, SMB, SIP, DHCP, or ESP issue is evidenced", unless that
absence directly answers the user's question.

For ESP/IPsec and other encrypted/datagram flows, explicitly state what cannot be proven from
the metadata, but still reason from duration, bytes, throughput_mbps, directionality, packet
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
tools directly. If more packet evidence is needed, do not say you lack access to
an allowed tool. Instead, add an evidence_requests item with one allow-listed tool,
the Flow ID, and a concise reason. FlowPilot/LangGraph will run the requested tool
and call you again with additional_tool_evidence. Allowed tools: deep_tcp_flow,
deep_udp_flow, deep_tls_flow. Use deep_tls_flow for TLS or DTLS handshake,
certificate, SNI, alert, cipher, hash/signature algorithm, and related TCP/UDP
header details as troubleshooting evidence, not as a standalone security review.
Use deep_udp_flow for UDP, DNS, or DHCP transaction/header details.
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
    analysis_focus = _normalized_analysis_focus(analysis_focus)
    try:
        client = openai_client()
        if LLM_API in {"chat", "chat_completions", "chat-completions"}:
            return _chat_with_chat_completions(
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
        if LLM_API == "auto":
            try:
                return _chat_with_responses(
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
                return _chat_with_chat_completions(
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
        return _chat_with_responses(
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
    analysis_focus = _normalized_analysis_focus(analysis_focus)
    try:
        client = openai_client()
        if LLM_API in {"chat", "chat_completions", "chat-completions"}:
            return _agent_chat_with_chat_completions(
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
        if LLM_API == "auto":
            try:
                return _agent_chat_with_responses(
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
                return _agent_chat_with_chat_completions(
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
        return _agent_chat_with_responses(
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
    except APITimeoutError:
        return AgentChatResponse(
            answer=f"The LLM request timed out after {LLM_TIMEOUT_SECONDS:g} seconds."
        )


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
    compact_summary = summary.compact(max_flows=max_flows)
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
    compact_summary = summary.compact(max_flows=max_flows)
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
    compact_summary = summary.compact(max_flows=max_flows)
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
    compact_summary = summary.compact(max_flows=max_flows)
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
    try:
        parsed = _json_object(content)
    except (json.JSONDecodeError, ValueError):
        return AgentChatResponse(answer=content)
    if "answer" not in parsed:
        parsed["answer"] = ""
    try:
        return AgentChatResponse.model_validate(parsed)
    except ValidationError:
        return AgentChatResponse(answer=content)


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
    compact_summary = summary.compact(max_flows=max_flows)
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
        compact_summary = compact_summary.compact()
    context = {
        "requested_analysis_focus": analysis_focus,
        "analysis_focus_instruction": _analysis_focus_instruction(analysis_focus),
        "summary": compact_summary,
        "initial_reasoning": report.model_dump(mode="json") if report else None,
        "additional_tool_evidence_count": len(evidence),
        "additional_tool_evidence": evidence,
    }
    messages = [
        {
            "role": "user",
            "content": (
                "Use this derived FlowPilot metadata as the fixed analysis context. "
                "Do not assume access to raw packet payloads beyond this metadata.\n\n"
                f"{json.dumps(context, indent=2, default=str)}"
            ),
        }
    ]
    if evidence:
        messages.append(
            {
                "role": "user",
                "content": (
                    "IMPORTANT: additional_tool_evidence is present below. Treat this "
                    "as the newest and most specific FlowPilot/LangGraph deep evidence. "
                    f"The requested_analysis_focus is {analysis_focus}. "
                    "If requested_analysis_focus is transport, use TLS certificate/cipher/hash "
                    "fields only for transport/session troubleshooting and do not present the "
                    "answer as security analysis. "
                    "Do not say the deep evidence payload was not passed into this "
                    "session context.\n\n"
                    f"additional_tool_evidence:\n{json.dumps(evidence, indent=2, default=str)}"
                ),
            }
        )
    messages.extend((history or [])[-12:])
    messages.append({"role": "user", "content": question})
    return messages


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
    return json.dumps(payload, indent=2, default=str)


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
        if tool_name == "deep_tls_flow":
            present.add("tls")
        elif tool_name == "deep_udp_flow":
            present.add("udp")
        elif tool_name == "deep_tcp_flow":
            present.add("tcp")
        if evidence.get("tls_metadata_counts"):
            present.add("tls")
        if evidence.get("udp_metadata_counts"):
            present.add("udp")
        if evidence.get("tcp_analysis_counts"):
            present.add("tcp")
    return present


def _add_flow_protocol_metadata(present: set[str], flow: dict[str, Any]) -> None:
    if flow.get("tls_certificates") or flow.get("tls_snis") or flow.get("tls_alerts"):
        present.add("tls")
    if flow.get("esp_spis") or flow.get("esp_sequences"):
        present.add("esp")
    for name in ("sip", "smb", "dns", "dhcp"):
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
