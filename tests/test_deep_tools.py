from flowpilot.deep_tools import (
    deep_tool_name_pattern,
    deep_tool_names,
    deep_tool_requests_for_flow,
)
from flowpilot.models import FlowKey, FlowSummary


def test_deep_tool_names_lists_registered_tools() -> None:
    assert deep_tool_names() == {
        "deep_tcp_flow",
        "deep_udp_flow",
        "deep_tls_flow",
        "deep_smb2_flow",
    }


def test_deep_tool_name_pattern_accepts_aliases() -> None:
    pattern = deep_tool_name_pattern("deep_tls_flow")

    import re

    assert re.search(pattern, "run deep_tls_flow for flow 1", flags=re.IGNORECASE)
    assert re.search(pattern, "run deep tls flow for flow 1", flags=re.IGNORECASE)
    assert re.search(pattern, "run deep-tls-flow for flow 1", flags=re.IGNORECASE)
    assert re.search(pattern, "run deep tls tool for flow 1", flags=re.IGNORECASE)
    assert re.search(pattern, "run deep-tls-tool for flow 1", flags=re.IGNORECASE)

    smb2_pattern = deep_tool_name_pattern("deep_smb2_flow")
    assert re.search(smb2_pattern, "run deep smb2 tool for flow 3", flags=re.IGNORECASE)
    assert re.search(smb2_pattern, "run deep smb tool for flow 3", flags=re.IGNORECASE)
    assert re.search(smb2_pattern, "run deep_smb_tool for flow 3", flags=re.IGNORECASE)
    assert re.search(smb2_pattern, "run deep-smb-flow for flow 3", flags=re.IGNORECASE)


def test_deep_tool_requests_prefers_tls_before_tcp_for_tls_port() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="10.0.0.20",
            port_a=12345,
            port_b=443,
            protocol="TCP",
        ),
        issue_counts={"tcp_lost_segment": 48},
    )

    assert deep_tool_requests_for_flow(1, flow) == {
        "tool": "deep_tls_flow",
        "flow_id": 1,
        "reason": "Likely TLS flow by TCP port; inspect TLS handshake and TCP headers.",
    }


def test_deep_tool_requests_prefers_smb2_before_tcp_for_smb_metadata() -> None:
    flow = FlowSummary(
        key=FlowKey(
            endpoint_a="10.0.0.10",
            endpoint_b="10.0.0.20",
            port_a=55000,
            port_b=445,
            protocol="TCP",
        ),
        issue_counts={"tcp_lost_segment": 2},
        smb_commands={"SMB2read": 10},
    )

    assert deep_tool_requests_for_flow(2, flow) == {
        "tool": "deep_smb2_flow",
        "flow_id": 2,
        "reason": (
            "SMB metadata observed; inspect SMB2 credit charge, request/grant, "
            "statuses, transfer headers, and related TCP symptoms."
        ),
    }
