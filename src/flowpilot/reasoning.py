from __future__ import annotations

import json
import os

from dotenv import load_dotenv
from openai import OpenAI

from .models import CaptureSummary, ReasoningReport

load_dotenv()

DEFAULT_MODEL = os.getenv("FLOWPILOT_MODEL", "gpt-5-mini")
OPENAI_BASE_URL = os.getenv("FLOWPILOT_OPENAI_BASE_URL")

SYSTEM_PROMPT = """You are FlowPilot, a careful network data-transfer troubleshooting agent.
Analyze derived flow metadata, not raw payloads. Focus on network-related transfer problems:
TCP retransmissions, duplicate ACKs, out-of-order delivery, resets, zero windows, one-way flows,
UDP loss symptoms, ESP/IPsec visibility limits, protocol or port blocking, MTU/path issues, and
asymmetric routing. Be precise about what the evidence supports, separate observation from
hypothesis, and recommend practical next checks for a network engineer.
Return concise JSON matching the requested schema."""


def openai_client() -> OpenAI:
    return OpenAI(base_url=OPENAI_BASE_URL) if OPENAI_BASE_URL else OpenAI()


def list_openai_models() -> list[dict[str, object]]:
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
    response = client.responses.parse(
        model=model,
        instructions=SYSTEM_PROMPT,
        input=[
            {
                "role": "user",
                "content": (
                    "Analyze this packet-capture flow summary. "
                    "Identify data-transfer issues across TCP, UDP, ESP/IPsec, and other "
                    "network protocols. Prioritize network causes over application causes "
                    "unless the flow evidence points otherwise.\n\n"
                    f"{json.dumps(summary.compact(max_flows=max_flows), indent=2, default=str)}"
                ),
            }
        ],
        text_format=ReasoningReport,
    )
    return response.output_parsed
