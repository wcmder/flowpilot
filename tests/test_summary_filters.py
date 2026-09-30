import io
from datetime import datetime, timedelta

import pytest

from flowpilot.analysis import summarize_capture
from flowpilot.cli import _apply_summary_filters, console
from flowpilot.filters import FlowFilter
from flowpilot.models import CaptureSummary, PacketObservation


@pytest.mark.parametrize("addresses", [("10.0.0.1", "10.0.0.2"), ("2001:db8::1", "2001:db8::2")])
@pytest.mark.parametrize("ports", [(1111, 2222), (0, 2222), (4500, 4500), (None, None)])
@pytest.mark.parametrize("bidirectional", [False, True])
def test_saved_flow_selection_matches_observed_packet_directions(addresses, ports, bidirectional):
    a, b = addresses
    pa, pb = ports
    start = datetime(2026, 1, 1)
    packets = [PacketObservation(
        src_ip=a, dst_ip=b, src_port=pa, dst_port=pb, protocol="UDP", length=100,
        timestamp=start,
    )]
    if bidirectional:
        packets.append(PacketObservation(
            src_ip=b, dst_ip=a, src_port=pb, dst_port=pa, protocol="UDP", length=200,
            timestamp=start + timedelta(seconds=1),
        ))
    summary = summarize_capture(packets)
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json())
    filters = [
        FlowFilter(src=a, src_port=pa, dst=b, dst_port=pb),
        FlowFilter(src=b, src_port=pb, dst=a, dst_port=pa),
        FlowFilter(src=a, src_port=pb),
        FlowFilter(src=a, dst=a),
        FlowFilter(src=a, dst_port=pa),
        FlowFilter(src_port=pa, dst_port=pa),
        FlowFilter(host=a, peer=b, port=pb),
        FlowFilter(src_port=0),
        FlowFilter(dst_port=0),
        FlowFilter(port=0),
        FlowFilter(protocol="TCP", src=a),
    ]
    for flow_filter in filters:
        expected = any(flow_filter.matches(packet) for packet in packets)
        assert flow_filter.matches_flow(loaded.flows[0]) == expected, flow_filter


def test_directional_loaded_filter_preserves_whole_flow_metrics_and_explains_scope(monkeypatch):
    stream = io.StringIO()
    monkeypatch.setattr(console, "file", stream)
    start = datetime(2026, 1, 1)
    packets = [
        PacketObservation(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1111, dst_port=2222,
                          protocol="UDP", length=100, timestamp=start),
        PacketObservation(src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=2222, dst_port=1111,
                          protocol="UDP", length=200, timestamp=start + timedelta(seconds=1)),
    ]
    summary = summarize_capture(packets)
    before = summary.model_dump_json()
    result = _apply_summary_filters(
        summary, flow_filter=FlowFilter(src="10.0.0.1", src_port=1111),
        sip_phone=None, include_redirects=False,
    )
    assert result.total_bytes == 300
    assert result.flows[0].dst_to_src_bytes == 200
    assert result.flows[0].duration_seconds == 1
    assert summary.model_dump_json() == before
    output = stream.getvalue()
    assert "whole saved flows" in output
    assert "packet-level filtering" in output
