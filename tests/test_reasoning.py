import json
import time
from datetime import datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

import flowpilot.reasoning as reasoning
from flowpilot.models import (
    AgentChatResponse,
    CaptureSummary,
    FlowKey,
    FlowSummary,
    ReasoningReport,
)
from flowpilot.reasoning import _json_object


@pytest.mark.parametrize("api", ["responses", "chat_completions"])
@pytest.mark.parametrize("agent", [False, True])
def test_requested_flow_outside_limit_reaches_provider_and_passes_guard(monkeypatch, api, agent):
    calls = []
    answer = "Endpoints: 10.0.0.5 and 10.0.0.6."

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            output_parsed=AgentChatResponse(answer=answer), output_text=answer,
            choices=[SimpleNamespace(message=SimpleNamespace(content=(
                json.dumps({"answer": answer, "evidence_requests": []}) if agent else answer
            )))],
        )

    client = SimpleNamespace(
        responses=SimpleNamespace(create=create, parse=create),
        chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
    )
    monkeypatch.setattr(reasoning, "openai_client", lambda: client)
    monkeypatch.setattr(reasoning, "LLM_API", api)
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)
    flows = [FlowSummary(
        key=FlowKey(endpoint_a=f"10.0.0.{i}", endpoint_b=f"10.0.0.{i + 1}"),
        byte_count=i * 100,
    ) for i in (1, 3, 5)]
    summary = CaptureSummary(
        packet_count=0, total_bytes=900, flow_count=3, protocols={}, top_ports={},
        issue_counts={}, names=[], flows=flows,
    )
    summary = CaptureSummary.model_validate_json(summary.model_dump_json())
    from flowpilot.cli import _flow_ids
    from flowpilot.workflow import _flow_by_id

    cli_ids = _flow_ids(summary.flows)
    for metadata, flow in zip(summary.compact()["top_flows"], summary.flows, strict=True):
        assert metadata["flow_id"] == cli_ids[id(flow)]
        assert metadata["endpoint_a"] == flow.key.endpoint_a
        assert _flow_by_id(summary.flows, metadata["flow_id"]) is flow
    function = reasoning.agent_chat_about_capture if agent else reasoning.chat_about_capture
    result = function(summary, "what are the IPs in flow id 3?", max_flows=1)
    assert (result.answer if agent else result) == answer
    messages = calls[0].get("input", calls[0].get("messages"))
    context = json.loads(messages[-1]["content"].split("\n\n", 1)[1])
    assert [(f["flow_id"], f["endpoint_a"]) for f in context["summary"]["top_flows"]] == [
        (1, "10.0.0.1"), (3, "10.0.0.5"),
    ]
    assert context["requested_flow"]["flow"]["flow_id"] == 3
    assert context["requested_flow"]["match_status"] == "found"
    assert [f["flow_id"] for f in summary.compact(max_flows=1)["top_flows"]] == [1]
    assert [f["flow_id"] for f in summary.compact(1, include_flow_id=99)["top_flows"]] == [1]


@pytest.mark.parametrize("api", ["responses", "chat_completions"])
@pytest.mark.parametrize("agent", [False, True])
def test_chat_provider_receives_current_flow_with_question_after_history(monkeypatch, api, agent):
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(
            output_parsed=AgentChatResponse(answer="Flow endpoints are attached."),
            output_text="Flow endpoints are attached.",
            choices=[SimpleNamespace(message=SimpleNamespace(
                content='{"answer": "Flow endpoints are attached.", "evidence_requests": []}'
            ))],
        )

    client = SimpleNamespace(
        responses=SimpleNamespace(create=create, parse=create),
        chat=SimpleNamespace(completions=SimpleNamespace(create=create)),
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)
    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2"))
    summary = CaptureSummary(
        packet_count=0, total_bytes=0, flow_count=1, protocols={}, top_ports={},
        issue_counts={}, names=[], flows=[flow],
    )
    history = [{"role": "assistant", "content": "Context not found in this session."}]
    question = "what are the IPs in flow id 1?"
    function = getattr(reasoning, f"_{'agent_' if agent else ''}chat_with_{api}")
    function(
        client, summary, question, model="test-model", max_flows=25, report=None,
        history=history, additional_evidence=None,
    )
    messages = calls[0].get("input", calls[0].get("messages"))
    assert messages[-2] == history[0]
    current = messages[-1]
    assert current["role"] == "user"
    context = json.loads(current["content"].split("\n\n", 1)[1])
    assert context["current_question"] == question
    assert context["requested_flow"]["match_status"] == "found"
    assert context["requested_flow"]["flow"]["endpoint_a"] == "10.0.0.1"
    assert context["requested_flow"]["flow"]["endpoint_b"] == "10.0.0.2"


@pytest.mark.parametrize("protocol,rtt", [("ESP", None), ("UDP", None), ("TCP", 125.0)])
def test_latency_question_receives_exact_flow_measurement_and_limits(protocol, rtt) -> None:
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol=protocol),
        initial_rtt_ms=rtt,
    )
    summary = CaptureSummary(
        packet_count=0, total_bytes=0, flow_count=1, protocols={protocol: 0},
        top_ports={}, issue_counts={}, names=[], flows=[flow],
    )
    messages = reasoning._chat_input(
        summary, "any latency issue at flow id 1", report=None, history=None,
    )
    context = json.loads(messages[0]["content"].split("\n\n", 1)[1])
    requested = context["requested_flow"]
    assert requested["match_status"] == "found"
    assert requested["flow"]["endpoint_a"] == "10.0.0.1"
    evidence = requested["flow"]["transport"]["rtt"]
    assert evidence["initial_ms"] == rtt
    if rtt is None:
        assert "No direct RTT measurement" in evidence["assessment"]
    else:
        assert "expected path baseline" in evidence["assessment"]
    for prompt in (reasoning._chat_system_prompt(), reasoning._agent_chat_system_prompt()):
        assert "analyze the supplied flow data first" in prompt
        assert "Missing RTT is unknown, not zero" in prompt


@pytest.mark.parametrize("agent", [False, True])
def test_throughput_lookup_uses_exact_flow_without_provider(monkeypatch, agent) -> None:
    from flowpilot.workflow import run_agent_chat

    def unexpected_client():
        pytest.fail("A direct metric lookup must not call the LLM")

    monkeypatch.setattr(reasoning, "openai_client", unexpected_client)
    start = datetime(2026, 1, 1)
    flow = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="ESP"),
        first_seen=start, last_seen=start + timedelta(seconds=2),
        src_to_dst_bytes=1_000_000, dst_to_src_bytes=500_000,
        byte_count=1_500_000,
    )
    other = FlowSummary(
        key=FlowKey(endpoint_a="10.0.0.9", endpoint_b="10.0.0.8", protocol="TCP"),
        byte_count=9_000_000,
    )
    summary = CaptureSummary(
        packet_count=0, total_bytes=10_500_000, flow_count=2,
        protocols={}, top_ports={}, issue_counts={}, names=[], flows=[flow, other],
    )
    summary = CaptureSummary.model_validate_json(summary.model_dump_json())
    chat = run_agent_chat if agent else reasoning.chat_about_capture
    answer = chat(
        summary, "what is the throughput from a to b in flow id 1?",
        max_flows=1,
        history=[{"role": "assistant", "content": "No capture data was shared; use 10.0.0.9."}],
    )
    assert "10.0.0.1 → 10.0.0.2: 4 Mbps" in answer
    assert "2 seconds" in answer
    assert "10.0.0.9" not in answer
    reverse = chat(summary, "show throughput from b to a for flow id 1")
    assert "10.0.0.2 → 10.0.0.1: 2 Mbps" in reverse
    assert "not present" in chat(summary, "what is the throughput in flow id 0")
    flow = summary.flows[0]
    flow.last_seen = flow.first_seen
    assert "unavailable" in chat(summary, "what is the throughput in flow id 1")
    assert reasoning._local_throughput_answer(
        summary, "why is the throughput low in flow id 1?"
    ) is None


def test_json_object_extracts_wrapped_json() -> None:
    assert _json_object('Here is the report: {"risk_level": "low"}') == {"risk_level": "low"}


def test_rate_limit_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    reasoning._respect_llm_rate_limit()


def test_openai_models_url_defaults_to_openai_models_endpoint(monkeypatch) -> None:
    monkeypatch.setattr(reasoning, "OPENAI_BASE_URL", None)

    assert reasoning.openai_models_url() == "https://api.openai.com/v1/models"


def test_openai_models_url_uses_configured_base_url(monkeypatch) -> None:
    monkeypatch.setattr(reasoning, "OPENAI_BASE_URL", "https://llm.example/v1/")

    assert reasoning.openai_models_url() == "https://llm.example/v1/models"


def test_system_prompt_delegates_tool_access_through_evidence_requests() -> None:
    assert "deep_tls_flow" in reasoning.SYSTEM_PROMPT
    assert "deep_smb2_flow" in reasoning.SYSTEM_PROMPT
    assert "flow_id exactly matches" in reasoning.SYSTEM_PROMPT
    assert "Do not invent IP addresses" in reasoning.SYSTEM_PROMPT
    assert "summary.flow_endpoint_inventory" in reasoning.SYSTEM_PROMPT
    assert "evidence_requests" in reasoning.SYSTEM_PROMPT
    assert "do not say you lack access" in reasoning.SYSTEM_PROMPT


def test_system_prompt_avoids_absent_protocol_checklists() -> None:
    assert "Only discuss protocols that are present" in reasoning.SYSTEM_PROMPT
    assert "checklist-style negative statements" in reasoning.SYSTEM_PROMPT


def test_system_prompt_frames_tls_metadata_as_troubleshooting_not_security_audit() -> None:
    assert "not a cybersecurity audit" in reasoning.SYSTEM_PROMPT
    assert "not as a standalone security review" in reasoning.SYSTEM_PROMPT
    prompt = reasoning._system_prompt(
        "transport",
        compact_summary={
            "protocols": {"TCP": 1},
            "top_flows": [{"protocol": "TCP", "tls_alerts": {"fatal": 1}}],
        },
    )
    assert "handshake compatibility" in prompt


def test_transport_focus_adds_strong_no_security_analysis_prompt() -> None:
    prompt = reasoning._system_prompt("transport")

    assert "Transport focus is enabled" in prompt
    assert "not a security analysis" in prompt
    assert "Do not label the answer as security analysis" in prompt


def test_security_focus_adds_security_prompt_without_replacing_transport_context() -> None:
    prompt = reasoning._system_prompt("security")

    assert "network transport troubleshooting" in prompt
    assert "Security focus is enabled" in prompt
    assert "TLS/DTLS certificate validity" in prompt


def test_chat_input_includes_metadata_report_and_recent_history() -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    report = ReasoningReport(
        executive_summary="ESP flow looks slow.",
        risk_level="medium",
        findings=[],
        next_questions=[],
    )
    history = [
        {"role": "user", "content": f"question {index}"}
        for index in range(14)
    ]

    messages = reasoning._chat_input(
        summary,
        "what should I check?",
        report=report,
        history=history,
    )

    assert "initial_reasoning" in messages[-1]["content"]
    assert "ESP flow looks slow." in messages[-1]["content"]
    assert messages[0]["content"] == "question 2"
    assert '"current_question": "what should I check?"' in messages[-1]["content"]
    assert len(messages) == 13


def test_chat_input_includes_exact_requested_flow_context() -> None:
    summary = CaptureSummary(
        packet_count=4,
        total_bytes=4000,
        flow_count=2,
        protocols={"TCP": 4},
        top_ports={"443": 2, "445": 2},
        issue_counts={},
        names=[],
        flows=[
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.1",
                    endpoint_b="10.0.0.2",
                    port_a=50000,
                    port_b=443,
                    protocol="TCP",
                ),
                byte_count=3000,
            ),
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.3",
                    endpoint_b="10.0.0.4",
                    port_a=50001,
                    port_b=445,
                    protocol="TCP",
                ),
                byte_count=1000,
            ),
        ],
    )

    messages = reasoning._chat_input(
        summary,
        "please explain flow id 1",
        report=None,
        history=None,
    )

    assert '"requested_flow"' in messages[0]["content"]
    assert '"flow_endpoint_inventory"' in messages[0]["content"]
    assert "Current FlowPilot metadata supersedes prior chat history" in messages[0]["content"]
    assert '"flow_id": 1' in messages[0]["content"]
    assert '"match_status": "found"' in messages[0]["content"]
    assert "10.0.0.1:50000" in messages[0]["content"]
    assert "10.0.0.3:50001" in messages[0]["content"]
    requested_flow_section = messages[0]["content"].split('"requested_flow"', maxsplit=1)[1]
    assert "10.0.0.1:50000" in requested_flow_section
    assert "10.0.0.3:50001" not in requested_flow_section


def test_chat_input_attaches_deep_evidence_to_current_question() -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    evidence = [{"tool": "deep_tls_flow", "flow_id": 1, "status": "ok"}]

    messages = reasoning._chat_input(
        summary,
        "what did the deep evidence show?",
        report=None,
        history=None,
        additional_evidence=evidence,
    )

    assert '"additional_tool_evidence_count": 1' in messages[0]["content"]
    context = json.loads(messages[-1]["content"].split("\n\n", 1)[1])
    assert context["additional_tool_evidence"] == evidence
    assert context["current_question"] == "what did the deep evidence show?"
    assert messages[-1]["content"].count('"tool": "deep_tls_flow"') == 1
    assert len(messages) == 1


def test_answer_ip_guard_allows_ips_from_current_metadata() -> None:
    summary = CaptureSummary(
        packet_count=1,
        total_bytes=1000,
        flow_count=1,
        protocols={"TCP": 1},
        top_ports={"443": 1},
        issue_counts={},
        names=[],
        flows=[
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.1",
                    endpoint_b="10.0.0.2",
                    port_a=50000,
                    port_b=443,
                    protocol="TCP",
                )
            )
        ],
    )

    answer = reasoning._guard_answer_ips(
        "Flow 1 is between 10.0.0.1 and 10.0.0.2.",
        summary,
        max_flows=25,
        additional_evidence=None,
    )

    assert answer == "Flow 1 is between 10.0.0.1 and 10.0.0.2."


def test_answer_ip_guard_suppresses_ips_absent_from_metadata() -> None:
    summary = CaptureSummary(
        packet_count=1,
        total_bytes=1000,
        flow_count=1,
        protocols={"TCP": 1},
        top_ports={"443": 1},
        issue_counts={},
        names=[],
        flows=[
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.1",
                    endpoint_b="10.0.0.2",
                    port_a=50000,
                    port_b=443,
                    protocol="TCP",
                )
            )
        ],
    )

    answer = reasoning._guard_answer_ips(
        "The alert came from 192.0.2.99.",
        summary,
        max_flows=25,
        additional_evidence=None,
    )

    assert "suppressed the LLM answer" in answer
    assert "192.0.2.99" in answer
    assert "10.0.0.1:50000" in answer
    assert "The alert came from 192.0.2.99." not in answer


def test_agent_chat_ip_guard_clears_tool_requests_when_answer_is_suppressed() -> None:
    summary = CaptureSummary(
        packet_count=1,
        total_bytes=1000,
        flow_count=1,
        protocols={"TCP": 1},
        top_ports={"443": 1},
        issue_counts={},
        names=[],
        flows=[
            FlowSummary(
                key=FlowKey(
                    endpoint_a="10.0.0.1",
                    endpoint_b="10.0.0.2",
                    port_a=50000,
                    port_b=443,
                    protocol="TCP",
                )
            )
        ],
    )
    response = AgentChatResponse(
        answer="The alert came from 192.0.2.99.",
        evidence_requests=[{"tool": "deep_tls_flow", "flow_id": 1, "reason": "More."}],
    )

    guarded = reasoning._guard_agent_chat_response_ips(
        response,
        summary,
        max_flows=25,
        additional_evidence=None,
    )

    assert "suppressed the LLM answer" in guarded.answer
    assert guarded.evidence_requests == []


def test_agent_chat_guard_suppresses_false_missing_additional_evidence_claim() -> None:
    response = AgentChatResponse(
        answer=(
            "The additional_tool_evidence payload for this specific flow is missing or "
            "empty. Verify that FlowPilot's pipeline has successfully attached the "
            "additional_tool_evidence block to our conversation."
        ),
        evidence_requests=[{"tool": "deep_smb2_flow", "flow_id": 1, "reason": "More."}],
    )

    guarded = reasoning._guard_agent_chat_response_ips(
        response,
        CaptureSummary(
            packet_count=0,
            total_bytes=0,
            flow_count=0,
            protocols={},
            top_ports={},
            issue_counts={},
            names=[],
            flows=[],
        ),
        max_flows=25,
        additional_evidence=[
            {
                "tool": "deep_smb2_flow",
                "flow_id": 1,
                "status": "ok",
                "packet_count": 12,
            }
        ],
    )

    assert "FlowPilot attached additional_tool_evidence" in guarded.answer
    assert "deep_smb2_flow for Flow ID 1: status=ok, packets=12" in guarded.answer
    assert guarded.evidence_requests == []


def test_chat_input_includes_requested_analysis_focus() -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )

    messages = reasoning._chat_input(
        summary,
        "check security",
        report=None,
        history=None,
        analysis_focus="security",
    )

    assert '"requested_analysis_focus": "security"' in messages[0]["content"]


def test_reasoning_payload_includes_transport_focus_instruction() -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )

    payload = reasoning._reasoning_payload(
        summary,
        additional_evidence=[{"tool": "deep_tls_flow"}],
        analysis_focus="transport",
    )

    assert '"requested_analysis_focus": "transport"' in payload
    assert "not a request for security analysis" in payload


def test_security_prompt_uses_only_present_protocol_registry_guidance() -> None:
    compact_summary = {
        "protocols": {"TCP": 10},
        "top_flows": [
            {
                "protocol": "TCP",
                "tls_alerts": {"fatal handshake_failure": 1},
                "tls_certificates": [{"subject_cn": "api.example.com"}],
                "smb": {},
                "dns": {},
            }
        ],
    }

    prompt = reasoning._system_prompt(
        "security",
        compact_summary=compact_summary,
        additional_evidence=[{"tool": "deep_tls_flow", "tls_metadata_counts": {"tls_packets": 2}}],
    )

    assert "TLS/DTLS: assess certificate validity" in prompt
    assert "SMB:" not in prompt
    assert "DNS:" not in prompt


def test_chat_completions_reasoning_handles_empty_message_content(monkeypatch) -> None:
    class _Message:
        content = None

    class _Choice:
        message = _Message()

    class _Response:
        choices = [_Choice()]

    class _Completions:
        @staticmethod
        def create(**_kwargs):
            return _Response()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    report = reasoning._reason_with_chat_completions(
        _Client(),
        summary,
        model="test-model",
        max_flows=25,
    )

    assert report.risk_level == "unknown"
    assert "did not include message content" in report.executive_summary


def test_chat_followup_handles_empty_message_content(monkeypatch) -> None:
    class _Message:
        content = None

    class _Choice:
        message = _Message()

    class _Response:
        choices = [_Choice()]

    class _Completions:
        @staticmethod
        def create(**_kwargs):
            return _Response()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    answer = reasoning._chat_with_chat_completions(
        _Client(),
        summary,
        "what happened?",
        model="test-model",
        max_flows=25,
        report=None,
        history=None,
    )

    assert "LLM chat returned no usable text" in answer
    assert "--agent --chat" in answer


def test_agent_chat_completions_uses_plain_text_fallback(monkeypatch) -> None:
    class _Message:
        content = "I need more TLS detail, but the response is not JSON."

    class _Choice:
        message = _Message()

    class _Response:
        choices = [_Choice()]

    class _Completions:
        @staticmethod
        def create(**_kwargs):
            return _Response()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    response = reasoning._agent_chat_with_chat_completions(
        _Client(),
        summary,
        "what happened?",
        model="test-model",
        max_flows=25,
        report=None,
        history=None,
    )

    assert response.answer == "I need more TLS detail, but the response is not JSON."
    assert response.evidence_requests == []


def test_agent_chat_completions_accepts_evidence_requests_without_answer(monkeypatch) -> None:
    class _Message:
        content = (
            '{"evidence_requests":[{"tool":"deep_tls_flow","flow_id":2,'
            '"reason":"Need TLS alert details."}]}'
        )

    class _Choice:
        message = _Message()

    class _Response:
        choices = [_Choice()]

    class _Completions:
        @staticmethod
        def create(**_kwargs):
            return _Response()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    response = reasoning._agent_chat_with_chat_completions(
        _Client(),
        summary,
        "use deep_tls_flow for flow 2",
        model="test-model",
        max_flows=25,
        report=None,
        history=None,
    )

    assert response.answer == ""
    assert response.evidence_requests[0].tool == "deep_tls_flow"
    assert response.evidence_requests[0].flow_id == 2


def test_agent_chat_completions_falls_back_to_plain_chat_on_empty_content(
    monkeypatch,
) -> None:
    class _Message:
        def __init__(self, content):
            self.content = content

    class _Choice:
        def __init__(self, content):
            self.message = _Message(content)

    class _Response:
        def __init__(self, content):
            self.choices = [_Choice(content)]

    class _Completions:
        calls = []

        @classmethod
        def create(cls, **kwargs):
            cls.calls.append(kwargs)
            if len(cls.calls) == 1:
                return _Response(None)
            return _Response("Plain answer after deep evidence.")

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    response = reasoning._agent_chat_with_chat_completions(
        _Client(),
        summary,
        "use deep_tls_flow for flow 2",
        model="test-model",
        max_flows=25,
        report=None,
        history=None,
        additional_evidence=[{"tool": "deep_tls_flow", "flow_id": 2}],
    )

    assert response.answer == "Plain answer after deep evidence."
    assert len(_Completions.calls) == 2
    assert "response_format" in _Completions.calls[0]
    assert "response_format" not in _Completions.calls[1]
    fallback_messages = _Completions.calls[1]["messages"]
    assert '"current_question": "use deep_tls_flow for flow 2"' in fallback_messages[-1]["content"]
    assert "Provide the final answer now" not in fallback_messages[-1]["content"]


def test_agent_chat_completions_falls_back_when_provider_returns_role_label(
    monkeypatch,
) -> None:
    class _Message:
        def __init__(self, content):
            self.content = content

    class _Choice:
        def __init__(self, content):
            self.message = _Message(content)
            self.finish_reason = "stop"

    class _Response:
        def __init__(self, content):
            self.choices = [_Choice(content)]

    class _Completions:
        calls = []

        @classmethod
        def create(cls, **kwargs):
            cls.calls.append(kwargs)
            if len(cls.calls) == 1:
                return _Response("assistant")
            return _Response("The SMB deep evidence shows normal credit grants.")

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    response = reasoning._agent_chat_with_chat_completions(
        _Client(),
        summary,
        "run deep smb tool for flow 2",
        model="test-model",
        max_flows=25,
        report=None,
        history=None,
        additional_evidence=[{"tool": "deep_smb2_flow", "flow_id": 2}],
    )

    assert response.answer == "The SMB deep evidence shows normal credit grants."
    assert len(_Completions.calls) == 2


def test_agent_chat_completions_falls_back_when_json_answer_is_empty(
    monkeypatch,
) -> None:
    class _Message:
        def __init__(self, content):
            self.content = content

    class _Choice:
        def __init__(self, content):
            self.message = _Message(content)
            self.finish_reason = "stop"

    class _Response:
        def __init__(self, content):
            self.choices = [_Choice(content)]

    class _Completions:
        calls = []

        @classmethod
        def create(cls, **kwargs):
            cls.calls.append(kwargs)
            if len(cls.calls) == 1:
                return _Response('{"answer": "", "evidence_requests": []}')
            return _Response("The SMB deep evidence shows the credit window remained open.")

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    response = reasoning._agent_chat_with_chat_completions(
        _Client(),
        summary,
        "run deep smb tool for flow 2",
        model="test-model",
        max_flows=25,
        report=None,
        history=None,
        additional_evidence=[{"tool": "deep_smb2_flow", "flow_id": 2}],
    )

    assert response.answer == "The SMB deep evidence shows the credit window remained open."
    assert len(_Completions.calls) == 2


def test_agent_chat_completions_reports_when_structured_and_plain_are_empty(
    monkeypatch,
) -> None:
    class _Message:
        content = None

    class _Choice:
        message = _Message()
        finish_reason = "stop"

    class _Response:
        choices = [_Choice()]

    class _Completions:
        calls = []

        @classmethod
        def create(cls, **kwargs):
            cls.calls.append(kwargs)
            return _Response()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    response = reasoning._agent_chat_with_chat_completions(
        _Client(),
        summary,
        "use deep_tls_flow for flow 2",
        model="test-model",
        max_flows=25,
        report=None,
        history=None,
        additional_evidence=[{"tool": "deep_tls_flow", "flow_id": 2}],
    )

    assert "both the structured chat request and the plain-text fallback" in response.answer
    assert "structured_finish_reason=stop" in response.answer
    assert "plain_finish_reason=stop" in response.answer
    assert len(_Completions.calls) == 2


def test_chat_choice_text_reads_provider_specific_message_fields() -> None:
    class _Message:
        content = None
        reasoning_content = "provider field answer"

    class _Choice:
        message = _Message()

    assert reasoning._chat_choice_text(_Choice()) == "provider field answer"


def test_chat_choice_text_reads_nested_model_dump_text() -> None:
    class _Message:
        content = None

        @staticmethod
        def model_dump():
            return {"parts": [{"text": "nested answer"}]}

    class _Choice:
        message = _Message()

    assert reasoning._chat_choice_text(_Choice()) == "nested answer"


def test_message_content_text_handles_list_parts() -> None:
    assert (
        reasoning._message_content_text(
            [{"type": "text", "text": "part one"}, {"content": "part two"}]
        )
        == "part one\npart two"
    )


def test_reasoning_returns_fallback_on_llm_timeout(monkeypatch) -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )

    def timeout_reasoning(*_args, **_kwargs):
        raise reasoning.APITimeoutError(httpx.Request("POST", "https://example.test/v1"))

    monkeypatch.setattr(reasoning, "openai_client", lambda: object())
    monkeypatch.setattr(reasoning, "LLM_API", "responses")
    monkeypatch.setattr(reasoning, "LLM_TIMEOUT_SECONDS", 5)
    monkeypatch.setattr(reasoning, "_reason_with_responses", timeout_reasoning)

    report = reasoning.reason_about_capture(summary)

    assert report.risk_level == "unknown"
    assert "timed out after 5 seconds" in report.executive_summary


def test_reasoning_returns_fallback_on_flowpilot_wall_clock_timeout(monkeypatch) -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )

    def slow_reasoning(*_args, **_kwargs):
        time.sleep(0.2)
        return ReasoningReport(executive_summary="too late", risk_level="low")

    monkeypatch.setattr(reasoning, "openai_client", lambda: object())
    monkeypatch.setattr(reasoning, "LLM_API", "responses")
    monkeypatch.setattr(reasoning, "LLM_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(reasoning, "_reason_with_responses", slow_reasoning)

    started_at = time.monotonic()
    report = reasoning.reason_about_capture(summary)

    assert time.monotonic() - started_at < 0.15
    assert report.risk_level == "unknown"
    assert "FlowPilot stopped waiting for LLM reasoning after 0.01 seconds" in (
        report.executive_summary
    )


def test_chat_returns_message_on_llm_timeout(monkeypatch) -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )

    def timeout_chat(*_args, **_kwargs):
        raise reasoning.APITimeoutError(httpx.Request("POST", "https://example.test/v1"))

    monkeypatch.setattr(reasoning, "openai_client", lambda: object())
    monkeypatch.setattr(reasoning, "LLM_API", "responses")
    monkeypatch.setattr(reasoning, "LLM_TIMEOUT_SECONDS", 5)
    monkeypatch.setattr(reasoning, "_chat_with_responses", timeout_chat)

    answer = reasoning.chat_about_capture(summary, "what happened?")

    assert "timed out after 5 seconds" in answer


def test_agent_chat_returns_message_on_flowpilot_wall_clock_timeout(monkeypatch) -> None:
    summary = CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )

    def slow_agent_chat(*_args, **_kwargs):
        time.sleep(0.2)
        return AgentChatResponse(answer="too late")

    monkeypatch.setattr(reasoning, "openai_client", lambda: object())
    monkeypatch.setattr(reasoning, "LLM_API", "responses")
    monkeypatch.setattr(reasoning, "LLM_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(reasoning, "_agent_chat_with_responses", slow_agent_chat)

    response = reasoning.agent_chat_about_capture(summary, "what happened?")

    assert "FlowPilot stopped waiting for LLM agent chat after 0.01 seconds" in response.answer


def test_batched_reasoning_payload_preserves_rows_without_indentation():
    evidence = [{"tool": "deep_esp_flow", "flow_id": 1,
                 "batch": {"offset": offset, "returned": 1000},
                 "esp_deep_samples": [{"frame.number": str(i), "esp.sequence": str(i)}
                                      for i in range(offset, offset + 1000)]}
                for offset in (0, 1000, 2000)]
    payload = reasoning._reasoning_payload({}, evidence)
    decoded = json.loads(payload)
    assert decoded["additional_tool_evidence"] == evidence
    assert "\n" not in payload
    assert len(payload) < len(json.dumps(decoded, indent=2))
