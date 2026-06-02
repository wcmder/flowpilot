import httpx

import flowpilot.reasoning as reasoning
from flowpilot.models import CaptureSummary, ReasoningReport
from flowpilot.reasoning import _json_object


def test_json_object_extracts_wrapped_json() -> None:
    assert _json_object('Here is the report: {"risk_level": "low"}') == {"risk_level": "low"}


def test_rate_limit_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    reasoning._respect_llm_rate_limit()


def test_system_prompt_delegates_tool_access_through_evidence_requests() -> None:
    assert "deep_tls_flow" in reasoning.SYSTEM_PROMPT
    assert "evidence_requests" in reasoning.SYSTEM_PROMPT
    assert "do not say you lack access" in reasoning.SYSTEM_PROMPT


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
        max_flows=25,
        report=report,
        history=history,
    )

    assert "initial_reasoning" in messages[0]["content"]
    assert "ESP flow looks slow." in messages[0]["content"]
    assert messages[1]["content"] == "question 2"
    assert messages[-1] == {"role": "user", "content": "what should I check?"}


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

    assert "did not include message content" in answer


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


def test_agent_chat_completions_reports_when_structured_and_plain_are_empty(
    monkeypatch,
) -> None:
    class _Message:
        content = None

    class _Choice:
        message = _Message()

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
    assert len(_Completions.calls) == 2


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
