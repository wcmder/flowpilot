from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, TypedDict

from .deep import deep_tcp_flow, deep_tls_flow, deep_udp_flow
from .models import CaptureSummary, FlowSummary, ReasoningReport
from .reasoning import (
    DEFAULT_MODEL,
    LLM_API,
    LLM_TIMEOUT_SECONDS,
    chat_about_capture,
    reason_about_capture,
)

ALLOWED_TOOLS = {"deep_tcp_flow", "deep_udp_flow", "deep_tls_flow"}


class FlowPilotAgentState(TypedDict, total=False):
    summary: CaptureSummary
    capture_path: Path
    model: str
    max_flows: int
    report: ReasoningReport
    question: str
    history: list[dict[str, str]]
    answer: str
    tool_requests: list[dict[str, Any]]
    completed_tool_requests: list[str]
    deep_evidence: list[dict[str, Any]]
    tool_loop_count: int
    max_tool_rereads: int
    agent_auto_tools: bool
    progress_callback: Callable[[str], None]


def run_agent_reasoning(
    summary: CaptureSummary,
    *,
    capture_path: Path | None = None,
    model: str = DEFAULT_MODEL,
    max_flows: int = 25,
    max_tool_rereads: int = 2,
    agent_auto_tools: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> ReasoningReport:
    return run_agent_reasoning_state(
        summary,
        capture_path=capture_path,
        model=model,
        max_flows=max_flows,
        max_tool_rereads=max_tool_rereads,
        agent_auto_tools=agent_auto_tools,
        progress_callback=progress_callback,
    )["report"]


def run_agent_reasoning_state(
    summary: CaptureSummary,
    *,
    capture_path: Path | None = None,
    model: str = DEFAULT_MODEL,
    max_flows: int = 25,
    max_tool_rereads: int = 2,
    agent_auto_tools: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> FlowPilotAgentState:
    graph = _build_reasoning_graph()
    state: FlowPilotAgentState = {
        "summary": summary,
        "model": model,
        "max_flows": max_flows,
        "max_tool_rereads": max_tool_rereads,
        "tool_loop_count": 0,
        "agent_auto_tools": agent_auto_tools,
        "completed_tool_requests": [],
        "deep_evidence": [],
        "tool_requests": [],
    }
    if capture_path:
        state["capture_path"] = capture_path
    if progress_callback:
        state["progress_callback"] = progress_callback
    return graph.invoke(state)


def run_agent_chat(
    summary: CaptureSummary,
    question: str,
    *,
    model: str = DEFAULT_MODEL,
    max_flows: int = 25,
    report: ReasoningReport | None = None,
    history: list[dict[str, str]] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
    progress_callback: Callable[[str], None] | None = None,
) -> str:
    graph = _build_chat_graph()
    state: FlowPilotAgentState = {
        "summary": summary,
        "model": model,
        "max_flows": max_flows,
        "question": question,
        "history": history or [],
        "deep_evidence": additional_evidence or [],
    }
    if report:
        state["report"] = report
    if progress_callback:
        state["progress_callback"] = progress_callback
    result = graph.invoke(state)
    return result["answer"]


def langgraph_available() -> bool:
    try:
        import langgraph.graph  # noqa: F401
    except ImportError:
        return False
    return True


def _build_reasoning_graph() -> Any:
    StateGraph, START, END = _langgraph_primitives()

    def deterministic_router_node(state: FlowPilotAgentState) -> dict[str, list[dict[str, Any]]]:
        if "capture_path" not in state:
            return {"tool_requests": []}
        if not state.get("agent_auto_tools", False):
            _progress(
                state,
                "LangGraph deterministic pre-router disabled; waiting for LLM tool requests.",
            )
            return {"tool_requests": []}
        requests = _deterministic_tool_requests(
            state["summary"],
            max_requests=state.get("max_tool_rereads", 2),
        )
        _progress(
            state,
            (
                f"LangGraph deterministic router selected {len(requests)} "
                "deep evidence request(s)."
            ),
        )
        return {"tool_requests": requests}

    def tool_node(state: FlowPilotAgentState) -> dict[str, Any]:
        requests = _pending_tool_requests(state)
        evidence = list(state.get("deep_evidence", []))
        completed = list(state.get("completed_tool_requests", []))
        for request in requests:
            request_key = _tool_request_key(request)
            _progress(
                state,
                (
                    f"LangGraph running {request.get('tool')} for Flow ID "
                    f"{request.get('flow_id')}: {request.get('reason', '')}"
                ),
            )
            tool_result = _run_tool_request(state, request)
            evidence.append(tool_result)
            _progress(
                state,
                (
                    f"LangGraph finished {request.get('tool')} for Flow ID "
                    f"{request.get('flow_id')} with status={tool_result.get('status')}."
                    f"{_tool_result_error_detail(tool_result)}"
                ),
            )
            completed.append(request_key)
        return {
            "tool_requests": [],
            "deep_evidence": evidence,
            "completed_tool_requests": completed,
        }

    def reason_node(state: FlowPilotAgentState) -> dict[str, ReasoningReport]:
        _progress(
            state,
            (
                "Sending derived metadata to LLM through LangGraph: "
                f"model={state.get('model', DEFAULT_MODEL)}, api={LLM_API}, "
                f"timeout={LLM_TIMEOUT_SECONDS:g}s, "
                f"top_flows={min(state['summary'].flow_count, state.get('max_flows', 25))}, "
                f"deep_evidence={len(state.get('deep_evidence', []))}."
            ),
        )
        return {
            "report": reason_about_capture(
                state["summary"],
                model=state.get("model", DEFAULT_MODEL),
                max_flows=state.get("max_flows", 25),
                additional_evidence=state.get("deep_evidence", []),
            )
        }

    def collect_llm_requests_node(state: FlowPilotAgentState) -> dict[str, Any]:
        loop_count = state.get("tool_loop_count", 0)
        if loop_count >= state.get("max_tool_rereads", 2):
            return {"tool_requests": [], "tool_loop_count": loop_count}
        requests = _llm_tool_requests(state)
        if requests:
            _progress(state, f"LLM requested {len(requests)} additional deep evidence reread(s).")
        return {
            "tool_requests": requests,
            "tool_loop_count": loop_count + 1 if requests else loop_count,
        }

    graph = StateGraph(FlowPilotAgentState)
    graph.add_node("deterministic_router", deterministic_router_node)
    graph.add_node("run_tools", tool_node)
    graph.add_node("llm_reasoning", reason_node)
    graph.add_node("collect_llm_requests", collect_llm_requests_node)
    graph.add_edge(START, "deterministic_router")
    graph.add_conditional_edges(
        "deterministic_router",
        _route_after_tool_request,
        {"tools": "run_tools", "reason": "llm_reasoning"},
    )
    graph.add_edge("run_tools", "llm_reasoning")
    graph.add_edge("llm_reasoning", "collect_llm_requests")
    graph.add_conditional_edges(
        "collect_llm_requests",
        _route_after_tool_request,
        {"tools": "run_tools", "reason": END},
    )
    return graph.compile()


def _build_chat_graph() -> Any:
    StateGraph, START, END = _langgraph_primitives()

    def chat_node(state: FlowPilotAgentState) -> dict[str, str]:
        _progress(
            state,
            (
                "Sending follow-up question to LLM through LangGraph: "
                f"model={state.get('model', DEFAULT_MODEL)}, api={LLM_API}, "
                f"timeout={LLM_TIMEOUT_SECONDS:g}s, "
                f"deep_evidence={len(state.get('deep_evidence', []))}."
            ),
        )
        return {
            "answer": chat_about_capture(
                state["summary"],
                state["question"],
                model=state.get("model", DEFAULT_MODEL),
                max_flows=state.get("max_flows", 25),
                report=state.get("report"),
                history=state.get("history"),
                additional_evidence=state.get("deep_evidence", []),
            )
        }

    graph = StateGraph(FlowPilotAgentState)
    graph.add_node("llm_chat", chat_node)
    graph.add_edge(START, "llm_chat")
    graph.add_edge("llm_chat", END)
    return graph.compile()


def _deterministic_tool_requests(
    summary: CaptureSummary,
    *,
    max_requests: int,
) -> list[dict[str, Any]]:
    requests = []
    for flow_id, flow in _flow_ids(summary.flows).items():
        if len(requests) >= max_requests:
            break
        reason = _tls_deep_reason(flow)
        if reason:
            requests.append({"tool": "deep_tls_flow", "flow_id": flow_id, "reason": reason})
            continue
        reason = _tcp_deep_reason(flow)
        if reason:
            requests.append({"tool": "deep_tcp_flow", "flow_id": flow_id, "reason": reason})
            continue
        reason = _udp_deep_reason(flow)
        if reason:
            requests.append({"tool": "deep_udp_flow", "flow_id": flow_id, "reason": reason})
    return requests


def _tls_deep_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol not in {"TCP", "UDP"}:
        return None
    if flow.tls_alerts:
        return "TLS/DTLS alert observed; inspect TLS/DTLS handshake, alert, and transport headers."
    if flow.tls_certificates:
        return (
            "TLS certificates observed; inspect complete TLS certificate chain "
            "and handshake fields."
        )
    if flow.tls_snis:
        return "TLS SNI observed; inspect TLS ClientHello and related transport headers."
    if flow.key.protocol == "TCP" and any(port in {443, 853, 8443} for port in _flow_ports(flow)):
        return "Likely TLS flow by TCP port; inspect TLS handshake and TCP headers."
    if flow.key.protocol == "UDP" and any(port in {443, 853, 4433} for port in _flow_ports(flow)):
        return "Likely DTLS or encrypted UDP flow by port; inspect DTLS and UDP headers."
    return None


def _tcp_deep_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol != "TCP":
        return None
    tcp_issues = {
        issue: count
        for issue, count in flow.issue_counts.items()
        if issue.startswith("tcp_") and count > 0
    }
    if tcp_issues:
        return f"TCP issue counters observed: {tcp_issues}."
    if flow.is_one_way:
        return "One-way TCP flow observed; inspect headers for handshake/reset/window clues."
    if flow.packet_count >= 100 and flow.throughput_mbps < 1:
        return "Longer TCP flow has low throughput; inspect headers for transport constraints."
    return None


def _udp_deep_reason(flow: FlowSummary) -> str | None:
    if flow.key.protocol != "UDP":
        return None
    if flow.dns_error_count:
        return "DNS error responses observed; inspect UDP/DNS transaction details."
    if flow.dns_queries or flow.dns_response_codes or flow.dns_answers:
        return "DNS metadata observed; inspect UDP/DNS transaction timing and answers."
    if flow.dhcp_message_types and not any("ACK" in key.upper() for key in flow.dhcp_message_types):
        return "DHCP exchange appears incomplete; inspect UDP/DHCP transaction details."
    if flow.dhcp_message_types:
        return "DHCP metadata observed; inspect UDP/DHCP transaction, lease, and server details."
    if flow.is_one_way:
        return "One-way UDP flow observed; inspect UDP headers and response visibility."
    return None


def _flow_ports(flow: FlowSummary) -> list[int]:
    return [port for port in (flow.key.port_a, flow.key.port_b) if port is not None]


def _llm_tool_requests(state: FlowPilotAgentState) -> list[dict[str, Any]]:
    if "capture_path" not in state:
        return []
    report = state.get("report")
    if not report:
        return []
    requests = []
    for request in report.evidence_requests:
        if request.tool not in ALLOWED_TOOLS or request.flow_id is None:
            continue
        request_dict = request.model_dump()
        if _tool_request_key(request_dict) not in state.get("completed_tool_requests", []):
            requests.append(request_dict)
    return requests


def _pending_tool_requests(state: FlowPilotAgentState) -> list[dict[str, Any]]:
    completed = set(state.get("completed_tool_requests", []))
    return [
        request
        for request in state.get("tool_requests", [])
        if request.get("tool") in ALLOWED_TOOLS and _tool_request_key(request) not in completed
    ]


def _run_tool_request(state: FlowPilotAgentState, request: dict[str, Any]) -> dict[str, Any]:
    tool = request.get("tool")
    if tool not in ALLOWED_TOOLS:
        return {
            "tool": tool,
            "status": "rejected",
            "message": "Tool is not allow-listed.",
        }
    flow_id = request.get("flow_id")
    flow = _flow_by_id(state["summary"].flows, flow_id)
    if not flow:
        return {
            "tool": tool,
            "flow_id": flow_id,
            "status": "not_found",
            "reason": request.get("reason", ""),
            "message": "Flow ID was not found in the current summary.",
        }
    if tool == "deep_tcp_flow":
        return deep_tcp_flow(
            state["capture_path"],
            flow_id=flow_id,
            flow=flow,
            reason=request.get("reason", ""),
        )
    if tool == "deep_tls_flow":
        return deep_tls_flow(
            state["capture_path"],
            flow_id=flow_id,
            flow=flow,
            reason=request.get("reason", ""),
        )
    return deep_udp_flow(
        state["capture_path"],
        flow_id=flow_id,
        flow=flow,
        reason=request.get("reason", ""),
    )


def _route_after_tool_request(state: FlowPilotAgentState) -> Literal["tools", "reason"]:
    return "tools" if _pending_tool_requests(state) else "reason"


def _tool_request_key(request: dict[str, Any]) -> str:
    return f"{request.get('tool')}:{request.get('flow_id')}"


def _tool_result_error_detail(tool_result: dict[str, Any]) -> str:
    if tool_result.get("status") != "error":
        return ""
    message = str(tool_result.get("message") or "").strip()
    display_filter = str(tool_result.get("display_filter") or "").strip()
    details = []
    if message:
        details.append(f"message={message}")
    if display_filter:
        details.append(f"filter={display_filter}")
    if not details:
        return ""
    return " " + " ".join(details)


def _progress(state: FlowPilotAgentState, message: str) -> None:
    callback = state.get("progress_callback")
    if callback:
        callback(message)


def _flow_ids(flows: list[FlowSummary]) -> dict[int, FlowSummary]:
    return {index: flow for index, flow in enumerate(flows, start=1)}


def _flow_by_id(flows: list[FlowSummary], flow_id: Any) -> FlowSummary | None:
    if not isinstance(flow_id, int):
        return None
    return _flow_ids(flows).get(flow_id)


def _langgraph_primitives() -> tuple[Any, Any, Any]:
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:
        raise RuntimeError(
            "LangGraph is not installed. Run `pip install -e \".[dev]\"` again "
            "inside env-flowpilot, then retry with --agent."
        ) from exc
    return StateGraph, START, END
