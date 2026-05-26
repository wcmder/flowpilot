from __future__ import annotations

import json
import os
import time
from typing import Any

from dotenv import load_dotenv
from openai import APIStatusError, OpenAI

from .models import CaptureSummary, ReasoningReport

load_dotenv()

DEFAULT_MODEL = os.getenv("FLOWPILOT_MODEL", "gpt-5-mini")
OPENAI_BASE_URL = os.getenv("FLOWPILOT_OPENAI_BASE_URL")
LLM_API = os.getenv("FLOWPILOT_LLM_API", "responses").lower()
LLM_REQUESTS_PER_MINUTE = int(os.getenv("FLOWPILOT_LLM_REQUESTS_PER_MINUTE", "120"))
_last_llm_request_at = 0.0

SYSTEM_PROMPT = """You are FlowPilot, a network data-transfer troubleshooting agent.
Do not merely summarize the flows. Diagnose likely flow issues from derived metadata.

Focus on symptoms such as low throughput over long duration, one-way traffic, large packet gaps,
TCP retransmissions, duplicate ACKs, out-of-order delivery, resets, zero windows,
UDP/ESP visibility limits, protocol or port blocking, MTU/path issues, congestion,
shaping/policing, asymmetric routing, SIP call failures, SMB transfer inefficiency,
and application handoff after redirects.

For ESP/IPsec and other encrypted/datagram flows, explicitly state what cannot be proven from
the metadata, but still reason from duration, bytes, throughput_mbps, directionality, packet
gaps, SPI, ESP sequence gaps, missing ESP sequence numbers, duplicate ESP sequence numbers,
out-of-order ESP sequence numbers, and peer behavior. Treat ESP sequence anomalies as stronger
evidence for packet loss, replay/duplicate delivery, capture loss, or path reordering than byte
counts alone. If a flow has high bytes but low throughput, treat that as a potential performance
finding and recommend concrete next checks such as tunnel counters, anti-replay drops, MTU/MSS,
fragmentation, QoS/policing, path loss, CPU/crypto load, or comparing both tunnel endpoints.

Every finding must include evidence from the provided fields and a recommended action. Avoid generic
restatements of packet counts unless they support a hypothesis. Return concise JSON matching the
requested schema. For SIP, use the per-call trace to identify failed calls, caller/callee,
failure response code, direction, likely cause category, and next checks. For SMB, assess whether
file transfer behavior looks optimal or suboptimal using transfer_mbps, read/write operation counts,
read/write bytes, SMB statuses/errors, file names, TCP issues, packet gaps, and duration."""


def openai_client() -> OpenAI:
    return OpenAI(base_url=OPENAI_BASE_URL) if OPENAI_BASE_URL else OpenAI()


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
) -> ReasoningReport:
    client = openai_client()
    if LLM_API in {"chat", "chat_completions", "chat-completions"}:
        return _reason_with_chat_completions(
            client,
            summary,
            model=model,
            max_flows=max_flows,
        )
    if LLM_API == "auto":
        try:
            return _reason_with_responses(client, summary, model=model, max_flows=max_flows)
        except APIStatusError as exc:
            if exc.status_code != 404:
                raise
            return _reason_with_chat_completions(
                client,
                summary,
                model=model,
                max_flows=max_flows,
            )
    return _reason_with_responses(client, summary, model=model, max_flows=max_flows)


def _reason_with_responses(
    client: OpenAI,
    summary: CaptureSummary,
    *,
    model: str,
    max_flows: int,
) -> ReasoningReport:
    _respect_llm_rate_limit()
    response = client.responses.parse(
        model=model,
        instructions=SYSTEM_PROMPT,
        input=[
            {
                "role": "user",
                "content": (
                    "Diagnose likely data-transfer issues in this packet-capture summary. "
                    "Return findings, hypotheses, and next checks. Do not just summarize flows. "
                    "Pay special attention to long-lived low-throughput ESP/IPsec or UDP flows, "
                    "one-way flows, packet gaps, TCP issue counters, SIP call failures, "
                    "SMB transfer inefficiency or errors, "
                    "and certificate/redirect clues.\n\n"
                    f"{json.dumps(summary.compact(max_flows=max_flows), indent=2, default=str)}"
                ),
            }
        ],
        text_format=ReasoningReport,
    )
    return response.output_parsed


def _reason_with_chat_completions(
    client: OpenAI,
    summary: CaptureSummary,
    *,
    model: str,
    max_flows: int,
) -> ReasoningReport:
    _respect_llm_rate_limit()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    "Return only JSON matching this JSON Schema:\n"
                    f"{json.dumps(ReasoningReport.model_json_schema(), indent=2)}\n\n"
                    "Diagnose likely data-transfer issues in this packet-capture summary. "
                    "Return findings, hypotheses, and next checks. Do not just summarize flows. "
                    "Pay special attention to long-lived low-throughput ESP/IPsec or UDP flows, "
                    "one-way flows, packet gaps, TCP issue counters, SIP call failures, "
                    "SMB transfer inefficiency or errors, "
                    "and certificate/redirect clues.\n\n"
                    f"{json.dumps(summary.compact(max_flows=max_flows), indent=2, default=str)}"
                ),
            },
        ],
        response_format={"type": "json_object"},
    )
    content = response.choices[0].message.content
    if not content:
        raise RuntimeError("Chat completions response did not include message content.")
    return ReasoningReport.model_validate(_json_object(content))


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
