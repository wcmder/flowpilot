import pytest

import flowpilot.workflow as workflow
from flowpilot.models import (
    AgentChatResponse,
    CaptureSummary,
    FlowKey,
    FlowSummary,
    ReasoningReport,
)


def _summary() -> CaptureSummary:
    return CaptureSummary(
        packet_count=0,
        total_bytes=0,
        flow_count=0,
        protocols={},
        top_ports={},
        issue_counts={},
        names=[],
        flows=[],
    )


def test_deterministic_router_requests_deep_tcp_for_tcp_issues() -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=12345,
                port_b=443,
                protocol="TCP",
            ),
            issue_counts={"tcp_lost_segment": 48},
        )
    ]

    requests = workflow._deterministic_tool_requests(summary, max_requests=2)

    assert requests == [
        {
            "tool": "deep_tls_flow",
            "flow_id": 1,
            "reason": "Likely TLS flow by TCP port; inspect TLS handshake and TCP headers.",
        }
    ]


def test_deterministic_router_requests_deep_tls_for_tls_alerts() -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=12345,
                port_b=443,
                protocol="TCP",
            ),
            tls_alerts={"fatal (2) handshake_failure (40)": 1},
        )
    ]

    requests = workflow._deterministic_tool_requests(summary, max_requests=2)

    assert requests == [
        {
            "tool": "deep_tls_flow",
            "flow_id": 1,
            "reason": (
                "TLS/DTLS alert observed; inspect TLS/DTLS handshake, alert, "
                "and transport headers."
            ),
        }
    ]


def test_deterministic_router_requests_deep_tcp_for_non_tls_tcp_issues() -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=12345,
                port_b=8444,
                protocol="TCP",
            ),
            issue_counts={"tcp_lost_segment": 48},
        )
    ]

    requests = workflow._deterministic_tool_requests(summary, max_requests=2)

    assert requests == [
        {
            "tool": "deep_tcp_flow",
            "flow_id": 1,
            "reason": "TCP issue counters observed: {'tcp_lost_segment': 48}.",
        }
    ]


def test_deterministic_router_requests_deep_udp_for_dns_errors() -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.53",
                port_a=53000,
                port_b=53,
                protocol="UDP",
            ),
            dns_error_count=1,
        )
    ]

    requests = workflow._deterministic_tool_requests(summary, max_requests=2)

    assert requests == [
        {
            "tool": "deep_udp_flow",
            "flow_id": 1,
            "reason": "DNS error responses observed; inspect UDP/DNS transaction details.",
        }
    ]


def test_deterministic_router_requests_deep_udp_for_incomplete_dhcp() -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="0.0.0.0",
                endpoint_b="255.255.255.255",
                protocol="UDP",
            ),
            dhcp_message_types={"Discover": 1, "Offer": 1},
        )
    ]

    requests = workflow._deterministic_tool_requests(summary, max_requests=2)

    assert requests == [
        {
            "tool": "deep_udp_flow",
            "flow_id": 1,
            "reason": "DHCP exchange appears incomplete; inspect UDP/DHCP transaction details.",
        }
    ]


def test_llm_tool_requests_are_allow_listed_and_deduplicated() -> None:
    report = ReasoningReport(
        executive_summary="Need more evidence.",
        risk_level="medium",
        findings=[],
        next_questions=[],
        evidence_requests=[
            {"tool": "deep_tcp_flow", "flow_id": 1, "reason": "Need TCP headers."},
            {"tool": "deep_udp_flow", "flow_id": 3, "reason": "Need DNS transaction details."},
            {"tool": "deep_tls_flow", "flow_id": 4, "reason": "Need TLS handshake."},
            {"tool": "unknown_tool", "flow_id": 1, "reason": "Nope."},
            {"tool": "deep_tcp_flow", "flow_id": 2, "reason": "Already done."},
        ],
    )
    state = {
        "capture_path": "capture.pcap",
        "report": report,
        "completed_tool_requests": ["deep_tcp_flow:2"],
    }

    assert workflow._llm_tool_requests(state) == [
        {"tool": "deep_tcp_flow", "flow_id": 1, "reason": "Need TCP headers."},
        {"tool": "deep_udp_flow", "flow_id": 3, "reason": "Need DNS transaction details."},
        {"tool": "deep_tls_flow", "flow_id": 4, "reason": "Need TLS handshake."},
    ]


def test_explicit_chat_tool_requests_parse_named_tool_and_flow_id(tmp_path) -> None:
    state = {
        "capture_path": tmp_path / "capture.pcap",
        "question": "Please run deep_tls_flow for Flow ID 12 before answering.",
        "completed_tool_requests": [],
    }

    assert workflow._explicit_chat_tool_requests(state) == [
        {
            "tool": "deep_tls_flow",
            "flow_id": 12,
            "reason": "User explicitly requested deep_tls_flow for Flow ID 12.",
        }
    ]


def test_explicit_chat_tool_requests_parse_flow_id_before_tool(tmp_path) -> None:
    state = {
        "capture_path": tmp_path / "capture.pcap",
        "question": "For flow id 7, use deep_udp_flow and check DNS.",
        "completed_tool_requests": [],
    }

    assert workflow._explicit_chat_tool_requests(state) == [
        {
            "tool": "deep_udp_flow",
            "flow_id": 7,
            "reason": "User explicitly requested deep_udp_flow for Flow ID 7.",
        }
    ]


def test_explicit_chat_tool_requests_parse_spaced_tool_name(tmp_path) -> None:
    state = {
        "capture_path": tmp_path / "capture.pcap",
        "question": "run deep tls flow for flow 1",
        "completed_tool_requests": [],
    }

    assert workflow._explicit_chat_tool_requests(state) == [
        {
            "tool": "deep_tls_flow",
            "flow_id": 1,
            "reason": "User explicitly requested deep_tls_flow for Flow ID 1.",
        }
    ]


def test_explicit_chat_tool_requests_parse_hyphenated_tool_name(tmp_path) -> None:
    state = {
        "capture_path": tmp_path / "capture.pcap",
        "question": "For flow id 8 run deep-tcp-flow",
        "completed_tool_requests": [],
    }

    assert workflow._explicit_chat_tool_requests(state) == [
        {
            "tool": "deep_tcp_flow",
            "flow_id": 8,
            "reason": "User explicitly requested deep_tcp_flow for Flow ID 8.",
        }
    ]


def test_tool_result_error_detail_includes_message_and_filter() -> None:
    detail = workflow._tool_result_error_detail(
        {
            "status": "error",
            "message": "Invalid display filter",
            "display_filter": "ip.addr == 10.0.0.1",
        }
    )

    assert "message=Invalid display filter" in detail
    assert "filter=ip.addr == 10.0.0.1" in detail


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_reasoning_graph_returns_report(monkeypatch) -> None:
    expected = ReasoningReport(
        executive_summary="agent report",
        risk_level="low",
        findings=[],
        next_questions=[],
    )

    def fake_reason(summary, *, model, max_flows, additional_evidence):
        assert summary.packet_count == 0
        assert model == "test-model"
        assert max_flows == 3
        assert additional_evidence == []
        return expected

    monkeypatch.setattr(workflow, "reason_about_capture", fake_reason)

    report = workflow.run_agent_reasoning(_summary(), model="test-model", max_flows=3)

    assert report == expected


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_reasoning_graph_returns_fallback_report_on_llm_error(monkeypatch) -> None:
    def fake_reason(*_args, **_kwargs):
        raise ValueError("Gemini returned invalid structured content")

    monkeypatch.setattr(workflow, "reason_about_capture", fake_reason)

    report = workflow.run_agent_reasoning(_summary(), model="test-model", max_flows=3)

    assert report.risk_level == "unknown"
    assert "LangGraph reasoning node" in report.executive_summary
    assert "ValueError: Gemini returned invalid structured content" in report.executive_summary


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_reasoning_waits_for_llm_tool_requests_by_default(monkeypatch, tmp_path) -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=12345,
                port_b=443,
                protocol="TCP",
            ),
            issue_counts={"tcp_lost_segment": 48},
        )
    ]

    def fake_reason(summary, *, model, max_flows, additional_evidence):
        assert additional_evidence == []
        return ReasoningReport(
            executive_summary="agent report",
            risk_level="low",
            findings=[],
            next_questions=[],
        )

    monkeypatch.setattr(workflow, "reason_about_capture", fake_reason)

    state = workflow.run_agent_reasoning_state(
        summary,
        capture_path=tmp_path / "capture.pcap",
        model="test-model",
        max_flows=3,
    )

    assert state["deep_evidence"] == []


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_reasoning_auto_tools_runs_deterministic_router(monkeypatch, tmp_path) -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=12345,
                port_b=443,
                protocol="TCP",
            ),
            issue_counts={"tcp_lost_segment": 48},
        )
    ]
    evidence = {"tool": "deep_tls_flow", "flow_id": 1, "status": "ok", "packet_count": 2}

    def fake_deep_tls_flow(*_args, **_kwargs):
        return evidence

    def fake_reason(summary, *, model, max_flows, additional_evidence):
        assert additional_evidence == [evidence]
        return ReasoningReport(
            executive_summary="agent report",
            risk_level="low",
            findings=[],
            next_questions=[],
        )

    monkeypatch.setattr(workflow, "deep_tls_flow", fake_deep_tls_flow)
    monkeypatch.setattr(workflow, "reason_about_capture", fake_reason)

    state = workflow.run_agent_reasoning_state(
        summary,
        capture_path=tmp_path / "capture.pcap",
        model="test-model",
        max_flows=3,
        agent_auto_tools=True,
    )

    assert state["deep_evidence"] == [evidence]


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_reasoning_runs_llm_requested_deep_tls_tool(monkeypatch, tmp_path) -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=53150,
                port_b=443,
                protocol="TCP",
            ),
            tls_alerts={"fatal handshake_failure": 1},
        )
    ]
    evidence = {
        "tool": "deep_tls_flow",
        "flow_id": 1,
        "status": "ok",
        "packet_count": 5,
        "tls_alerts": [{"level": "fatal", "description": "handshake_failure"}],
    }
    additional_evidence_seen = []

    reports = [
        ReasoningReport(
            executive_summary="Need TLS detail.",
            risk_level="medium",
            findings=[],
            next_questions=[],
            evidence_requests=[
                {
                    "tool": "deep_tls_flow",
                    "flow_id": 1,
                    "reason": "Need TLS alert sender and handshake details.",
                }
            ],
        ),
        ReasoningReport(
            executive_summary="TLS alert ended the session.",
            risk_level="medium",
            findings=[],
            next_questions=[],
        ),
    ]

    def fake_deep_tls_flow(*_args, **_kwargs):
        return evidence

    def fake_reason(summary, *, model, max_flows, additional_evidence):
        additional_evidence_seen.append(additional_evidence)
        return reports.pop(0)

    monkeypatch.setattr(workflow, "deep_tls_flow", fake_deep_tls_flow)
    monkeypatch.setattr(workflow, "reason_about_capture", fake_reason)

    state = workflow.run_agent_reasoning_state(
        summary,
        capture_path=tmp_path / "capture.pcap",
        model="test-model",
        max_flows=3,
    )

    assert state["deep_evidence"] == [evidence]
    assert state["report"].executive_summary == "TLS alert ended the session."
    assert additional_evidence_seen == [[], [evidence]]


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_chat_graph_returns_answer(monkeypatch) -> None:
    report = ReasoningReport(
        executive_summary="agent report",
        risk_level="low",
        findings=[],
        next_questions=[],
    )

    def fake_chat(summary, question, *, model, max_flows, report, history, additional_evidence):
        assert summary.packet_count == 0
        assert question == "what next?"
        assert model == "test-model"
        assert max_flows == 3
        assert report.risk_level == "low"
        assert history == [{"role": "user", "content": "hello"}]
        assert additional_evidence == [{"tool": "deep_tcp_flow"}]
        return AgentChatResponse(answer="agent answer")

    monkeypatch.setattr(workflow, "agent_chat_about_capture", fake_chat)

    answer = workflow.run_agent_chat(
        _summary(),
        "what next?",
        model="test-model",
        max_flows=3,
        report=report,
        history=[{"role": "user", "content": "hello"}],
        additional_evidence=[{"tool": "deep_tcp_flow"}],
    )

    assert answer == "agent answer"


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_chat_runs_llm_requested_deep_tls_tool(monkeypatch, tmp_path) -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=53150,
                port_b=443,
                protocol="TCP",
            ),
            tls_alerts={"fatal handshake_failure": 1},
        )
    ]
    report = ReasoningReport(
        executive_summary="TLS flow needs review.",
        risk_level="medium",
        findings=[],
        next_questions=[],
    )
    evidence = {"tool": "deep_tls_flow", "flow_id": 1, "status": "ok", "packet_count": 5}
    additional_evidence_seen = []

    responses = [
        AgentChatResponse(
            answer="Requesting deep TLS evidence.",
            evidence_requests=[
                {
                    "tool": "deep_tls_flow",
                    "flow_id": 1,
                    "reason": "Need TLS alert sender and handshake details.",
                }
            ],
        ),
        AgentChatResponse(answer="The TLS alert came from the server side."),
    ]

    def fake_deep_tls_flow(*_args, **_kwargs):
        return evidence

    def fake_chat(summary, question, *, model, max_flows, report, history, additional_evidence):
        additional_evidence_seen.append(additional_evidence)
        return responses.pop(0)

    monkeypatch.setattr(workflow, "deep_tls_flow", fake_deep_tls_flow)
    monkeypatch.setattr(workflow, "agent_chat_about_capture", fake_chat)

    answer = workflow.run_agent_chat(
        summary,
        "can you inspect why the TLS alert happened?",
        model="test-model",
        max_flows=3,
        report=report,
        capture_path=tmp_path / "capture.pcap",
    )

    assert answer == "The TLS alert came from the server side."
    assert additional_evidence_seen == [[], [evidence]]


@pytest.mark.skipif(not workflow.langgraph_available(), reason="LangGraph is not installed")
def test_agent_chat_runs_explicit_deep_tls_request_before_llm(monkeypatch, tmp_path) -> None:
    summary = _summary()
    summary.flows = [
        FlowSummary(
            key=FlowKey(
                endpoint_a="10.0.0.10",
                endpoint_b="10.0.0.20",
                port_a=53150,
                port_b=443,
                protocol="TCP",
            )
        )
    ]
    evidence = {"tool": "deep_tls_flow", "flow_id": 1, "status": "ok", "packet_count": 5}

    def fake_deep_tls_flow(*_args, **_kwargs):
        return evidence

    def fake_chat(summary, question, *, model, max_flows, report, history, additional_evidence):
        assert additional_evidence == [evidence]
        return AgentChatResponse(answer="I used the deep TLS evidence.")

    monkeypatch.setattr(workflow, "deep_tls_flow", fake_deep_tls_flow)
    monkeypatch.setattr(workflow, "agent_chat_about_capture", fake_chat)

    answer = workflow.run_agent_chat(
        summary,
        "use deep_tls_flow for flow id 1",
        model="test-model",
        max_flows=3,
        capture_path=tmp_path / "capture.pcap",
    )

    assert answer == "I used the deep TLS evidence."
