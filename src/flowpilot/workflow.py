from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Literal, TypedDict

from .deep_tools import (
    deep_tool_name_pattern,
    deep_tool_names,
    deep_tool_requests_for_flow,
    run_deep_tool,
)
from .models import CaptureSummary, FlowSummary, ReasoningReport
from .reasoning import (
    DEFAULT_MODEL,
    LLM_API,
    LLM_TIMEOUT_SECONDS,
    AnalysisFocus,
    agent_chat_about_capture,
    reason_about_capture,
)

ALLOWED_TOOLS = deep_tool_names()


class FlowPilotAgentState(TypedDict, total=False):
    summary: CaptureSummary
    capture_path: Path
    model: str
    analysis_focus: AnalysisFocus
    max_flows: int
    report: ReasoningReport
    question: str
    history: list[dict[str, str]]
    answer: str
    chat_response: Any
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
    analysis_focus: AnalysisFocus = "transport",
    max_tool_rereads: int = 2,
    agent_auto_tools: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> ReasoningReport:
    return run_agent_reasoning_state(
        summary,
        capture_path=capture_path,
        model=model,
        max_flows=max_flows,
        analysis_focus=analysis_focus,
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
    analysis_focus: AnalysisFocus = "transport",
    max_tool_rereads: int = 2,
    agent_auto_tools: bool = False,
    progress_callback: Callable[[str], None] | None = None,
) -> FlowPilotAgentState:
    graph = _build_reasoning_graph()
    state: FlowPilotAgentState = {
        "summary": summary,
        "model": model,
        "analysis_focus": analysis_focus,
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
    analysis_focus: AnalysisFocus = "transport",
    report: ReasoningReport | None = None,
    history: list[dict[str, str]] | None = None,
    additional_evidence: list[dict[str, Any]] | None = None,
    capture_path: Path | None = None,
    max_tool_rereads: int = 2,
    progress_callback: Callable[[str], None] | None = None,
) -> str:
    graph = _build_chat_graph()
    state: FlowPilotAgentState = {
        "summary": summary,
        "model": model,
        "analysis_focus": analysis_focus,
        "max_flows": max_flows,
        "question": question,
        "history": history or [],
        "deep_evidence": additional_evidence or [],
        "tool_requests": [],
        "completed_tool_requests": [],
        "tool_loop_count": 0,
        "max_tool_rereads": max_tool_rereads,
    }
    if capture_path:
        state["capture_path"] = capture_path
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
        return _tool_node_result(state)

    def reason_node(state: FlowPilotAgentState) -> dict[str, ReasoningReport]:
        wait_message = f"LLM reasoning waiting ({state.get('model', DEFAULT_MODEL)})"
        _progress(
            state,
            (
                "Sending derived metadata to LLM through LangGraph: "
                f"model={state.get('model', DEFAULT_MODEL)}, api={LLM_API}, "
                f"focus={state.get('analysis_focus', 'transport')}, "
                f"timeout={LLM_TIMEOUT_SECONDS:g}s, "
                f"top_flows={min(state['summary'].flow_count, state.get('max_flows', 25))}, "
                f"deep_evidence={len(state.get('deep_evidence', []))}."
            ),
        )
        try:
            with _llm_wait_timer(state, wait_message, interval_seconds=1.0):
                report = reason_about_capture(
                    state["summary"],
                    model=state.get("model", DEFAULT_MODEL),
                    max_flows=state.get("max_flows", 25),
                    additional_evidence=state.get("deep_evidence", []),
                    analysis_focus=state.get("analysis_focus", "transport"),
                )
        except Exception as exc:  # pragma: no cover - defensive provider boundary
            report = ReasoningReport(
                executive_summary=(
                    "LLM reasoning failed inside the LangGraph reasoning node. "
                    f"{type(exc).__name__}: {exc}"
                ),
                risk_level="unknown",
                findings=[],
                next_questions=[
                    "Retry with FLOWPILOT_LLM_API=chat_completions or use --no-llm "
                    "to review local FlowPilot metrics.",
                ],
            )
        return {"report": report}

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

    def explicit_request_node(state: FlowPilotAgentState) -> dict[str, Any]:
        requests = _explicit_chat_tool_requests(state)
        if requests:
            _progress(
                state,
                (
                    "LangGraph detected explicit chat tool request(s): "
                    f"{len(requests)} deep evidence reread(s)."
                ),
            )
            return {
                "tool_requests": requests,
                "question": _explicit_tool_followup_question(state["question"], requests),
            }
        return {"tool_requests": requests}

    def tool_node(state: FlowPilotAgentState) -> dict[str, Any]:
        return _tool_node_result(state)

    def chat_node(state: FlowPilotAgentState) -> dict[str, Any]:
        wait_message = f"LLM chat waiting ({state.get('model', DEFAULT_MODEL)})"
        _progress(
            state,
            (
                "Sending follow-up question to LLM through LangGraph agent chat: "
                f"model={state.get('model', DEFAULT_MODEL)}, api={LLM_API}, "
                f"focus={state.get('analysis_focus', 'transport')}, "
                f"timeout={LLM_TIMEOUT_SECONDS:g}s, "
                f"deep_evidence={len(state.get('deep_evidence', []))}."
            ),
        )
        try:
            with _llm_wait_timer(state, wait_message, interval_seconds=1.0):
                response = agent_chat_about_capture(
                    state["summary"],
                    state["question"],
                    model=state.get("model", DEFAULT_MODEL),
                    max_flows=state.get("max_flows", 25),
                    report=state.get("report"),
                    history=state.get("history"),
                    additional_evidence=state.get("deep_evidence", []),
                    analysis_focus=state.get("analysis_focus", "transport"),
                )
        except Exception as exc:  # pragma: no cover - defensive provider boundary
            return {
                "answer": (
                    "Agent chat failed before tool routing. "
                    f"{type(exc).__name__}: {exc}"
                ),
                "tool_requests": [],
            }
        loop_count = state.get("tool_loop_count", 0)
        if loop_count >= state.get("max_tool_rereads", 2):
            requests = []
        else:
            requests = _valid_tool_requests(state, response.evidence_requests)
        if requests:
            _progress(
                state,
                f"LLM chat requested {len(requests)} additional deep evidence reread(s).",
            )
        return {
            "answer": response.answer,
            "chat_response": response,
            "tool_requests": requests,
            "tool_loop_count": loop_count + 1 if requests else loop_count,
        }

    graph = StateGraph(FlowPilotAgentState)
    graph.add_node("explicit_request", explicit_request_node)
    graph.add_node("llm_chat", chat_node)
    graph.add_node("run_tools", tool_node)
    graph.add_edge(START, "explicit_request")
    graph.add_conditional_edges(
        "explicit_request",
        _route_after_tool_request,
        {"tools": "run_tools", "reason": "llm_chat"},
    )
    graph.add_conditional_edges(
        "llm_chat",
        _route_after_tool_request,
        {"tools": "run_tools", "reason": END},
    )
    graph.add_edge("run_tools", "llm_chat")
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
        request = deep_tool_requests_for_flow(flow_id, flow)
        if request:
            requests.append(request)
    return requests


def _llm_tool_requests(state: FlowPilotAgentState) -> list[dict[str, Any]]:
    if "capture_path" not in state:
        return []
    report = state.get("report")
    if not report:
        return []
    return _valid_tool_requests(state, report.evidence_requests)


def _explicit_chat_tool_requests(state: FlowPilotAgentState) -> list[dict[str, Any]]:
    if "capture_path" not in state:
        return []
    question = state.get("question", "")
    requests = []
    for tool in ALLOWED_TOOLS:
        tool_pattern = deep_tool_name_pattern(tool)
        if not re.search(tool_pattern, question, flags=re.IGNORECASE):
            continue
        flow_id = _explicit_flow_id(question, tool_pattern)
        if flow_id is None:
            continue
        request = {
            "tool": tool,
            "flow_id": flow_id,
            "reason": f"User explicitly requested {tool} for Flow ID {flow_id}.",
        }
        if _tool_request_key(request) not in state.get("completed_tool_requests", []):
            requests.append(request)
    return requests


def _explicit_flow_id(question: str, tool_pattern: str) -> int | None:
    patterns = [
        rf"{tool_pattern}\D{{0,80}}(?:flow(?:\s+id)?|id)\D{{0,20}}(\d+)",
        rf"(?:flow(?:\s+id)?|id)\D{{0,20}}(\d+)\D{{0,80}}{tool_pattern}",
    ]
    for pattern in patterns:
        match = re.search(pattern, question, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _explicit_tool_followup_question(
    original_question: str,
    requests: list[dict[str, Any]],
) -> str:
    request_summary = ", ".join(
        f"{request.get('tool')} for Flow ID {request.get('flow_id')}"
        for request in requests
    )
    return (
        "FlowPilot has already run the explicit deep evidence request before this "
        f"LLM call: {request_summary}. Use additional_tool_evidence as the source "
        "of truth for those tool results. For each requested Flow ID, use only "
        "the evidence item with that exact flow_id and its target_flow identity. "
        "Do not use endpoints or samples from a different Flow ID. "
        "Do not say the tool is unavailable or "
        "not integrated. Answer the user's original request using the supplied "
        f"deep evidence.\n\nOriginal user request: {original_question}"
    )


def _valid_tool_requests(
    state: FlowPilotAgentState,
    evidence_requests: Any,
) -> list[dict[str, Any]]:
    requests = []
    for request in evidence_requests:
        if request.tool not in ALLOWED_TOOLS or not _valid_flow_id(state, request.flow_id):
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
            "message": (
                "Flow ID was not found in the current summary. Flow IDs start at 1 "
                "and must reference the Top Flows table."
            ),
        }
    result = run_deep_tool(
        tool,
        state["capture_path"],
        flow_id=flow_id,
        flow=flow,
        reason=request.get("reason", ""),
    )
    result.setdefault("flow_id", flow_id)
    result["target_flow"] = _tool_target_flow(flow_id, flow)
    return result


def _tool_node_result(state: FlowPilotAgentState) -> dict[str, Any]:
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


@contextmanager
def _llm_wait_timer(
    state: FlowPilotAgentState,
    message: str,
    *,
    interval_seconds: float = 3.0,
) -> Iterator[None]:
    callback = state.get("progress_callback")
    if not callback:
        yield
        return

    stop_event = threading.Event()
    started_at = time.monotonic()

    def report_wait() -> None:
        while not stop_event.wait(interval_seconds):
            elapsed = time.monotonic() - started_at
            callback(f"__flowpilot_refresh__:{message}: {elapsed:.0f}s")

    timer = threading.Thread(target=report_wait, daemon=True)
    timer.start()
    try:
        yield
    finally:
        stop_event.set()
        timer.join(timeout=interval_seconds)


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


def _tool_target_flow(flow_id: int, flow: FlowSummary) -> dict[str, Any]:
    return {
        "flow_id": flow_id,
        "flow_label": _flow_label(flow),
        "protocol": flow.key.protocol,
        "endpoint_a": flow.key.endpoint_a,
        "port_a": flow.key.port_a,
        "endpoint_b": flow.key.endpoint_b,
        "port_b": flow.key.port_b,
    }


def _flow_label(flow: FlowSummary) -> str:
    return (
        f"{flow.key.protocol} "
        f"{_endpoint_label(flow.key.endpoint_a, flow.key.port_a)} <-> "
        f"{_endpoint_label(flow.key.endpoint_b, flow.key.port_b)}"
    )


def _endpoint_label(endpoint: str, port: int | None) -> str:
    return endpoint if port is None else f"{endpoint}:{port}"


def _valid_flow_id(state: FlowPilotAgentState, flow_id: Any) -> bool:
    if not isinstance(flow_id, int) or flow_id < 1:
        return False
    summary = state.get("summary")
    if not summary:
        return False
    return flow_id <= len(summary.flows)


def _langgraph_primitives() -> tuple[Any, Any, Any]:
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError as exc:
        raise RuntimeError(
            "LangGraph is not installed. Run `pip install -e \".[dev]\"` again "
            "inside env-flowpilot, then retry with --agent."
        ) from exc
    return StateGraph, START, END
