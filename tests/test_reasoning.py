import httpx

import flowpilot.reasoning as reasoning
from flowpilot.models import CaptureSummary, ReasoningReport
from flowpilot.reasoning import _json_object


def test_json_object_extracts_wrapped_json() -> None:
    assert _json_object('Here is the report: {"risk_level": "low"}') == {"risk_level": "low"}


def test_rate_limit_can_be_disabled(monkeypatch) -> None:
    monkeypatch.setattr(reasoning, "LLM_REQUESTS_PER_MINUTE", 0)

    reasoning._respect_llm_rate_limit()


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
