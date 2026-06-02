import pytest

import flowpilot.workflow as workflow
from flowpilot.models import CaptureSummary, FlowKey, FlowSummary, ReasoningReport


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
    ]


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
        return "agent answer"

    monkeypatch.setattr(workflow, "chat_about_capture", fake_chat)

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
