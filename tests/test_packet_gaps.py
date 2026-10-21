import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from flowpilot.analysis import summarize_capture
from flowpilot.deep_tools import run_deep_tool
from flowpilot.models import (
    CaptureSummary,
    FlowKey,
    FlowSummary,
    PacketGapSummary,
    PacketObservation,
)
from flowpilot.protocols import rtp, udp
from flowpilot.protocols.packet_gaps import annotate_packet_gaps


def test_direction_and_ssrc_gaps_survive_summary_round_trip():
    start = datetime(2026, 1, 1)
    def packet(seconds, reverse=False, ssrc='1', sequence=1):
        return PacketObservation(
            timestamp=start + timedelta(seconds=seconds), protocol='UDP',
            src_ip='10.0.0.2' if reverse else '10.0.0.1',
            dst_ip='10.0.0.1' if reverse else '10.0.0.2',
            src_port=2000 if reverse else 1000, dst_port=1000 if reverse else 2000,
            rtp_ssrc=ssrc, rtp_sequence=sequence,
        )
    summary = summarize_capture([
        packet(0), packet(.5, True), packet(1, ssrc='2'),
        packet(1.5, True, sequence=2), packet(2, sequence=2),
    ])
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json())
    metadata = loaded.compact()['top_flows'][0]
    gaps = metadata['packet_gaps_by_direction']
    assert [g['max_gap_ms'] for g in gaps] == [1000, 1000]
    assert [g['pause_count'] for g in gaps] == [2, 1]
    stream = next(s for s in metadata['rtp']['streams']
                  if s['ssrc'] == '1' and s['direction'] == 'A_to_B')
    assert stream['packet_gaps']['max_gap_ms'] == 2000
    assert stream['packet_gaps']['pause_count'] == 1
    legacy = summary.model_dump()
    del legacy['flows'][0]['packet_gaps_by_direction']
    old_flow = CaptureSummary.model_validate(legacy).flows[0]
    assert old_flow.packet_gaps_by_direction[0].max_gap_ms is None


def test_missing_backward_zero_and_threshold_timestamps():
    stats = PacketGapSummary(pause_threshold_ms=1000)
    assert [stats.record(s) for s in ('0', '0', '0.999', '1.999', None, '9', '8', '8.1')] == [
        None, 0, 999, 1000, None, None, None, 100,
    ]
    assert stats.pause_count == 1
    assert stats.interval_count == 4
    assert stats.backward_timestamp_count == 1
    assert stats.missing_timestamp_count == 1
    assert stats.compact()['mean_gap_ms'] == 524.75


@pytest.mark.parametrize('module,sample_key', [
    (udp, 'udp_header_samples'), (rtp, 'rtp_header_samples'),
])
def test_deep_gaps_full_scope_and_cached_boundary(monkeypatch, tmp_path, module, sample_key):
    flow = FlowSummary(key=FlowKey(endpoint_a='10.0.0.1', endpoint_b='10.0.0.2',
                                   port_a=1000, port_b=2000, protocol='UDP'))
    fields = module.UDP_HEADER_FIELDS if module is udp else module.RTP_HEADER_FIELDS
    rows = []
    for index in range(1002):
        # 20ms spacing, then a 2 second pause exactly at the second page boundary.
        seconds = index * .02 + (1.98 if index >= 1000 else 0)
        values = {'frame.number': str(index + 1), 'frame.time_relative': f'{seconds:.3f}',
                  'ip.src': '10.0.0.1', 'ip.dst': '10.0.0.2', 'udp.srcport': '1000',
                  'udp.dstport': '2000', 'rtp.ssrc': '0x00000001', 'rtp.seq': str(index),
                  'rtp.version': '2', 'rtp.timestamp': str(index * 160)}
        rows.append('\t'.join(values.get(field, '') for field in fields))
    monkeypatch.setattr(module, 'tshark_path', lambda: 'tshark')
    monkeypatch.setattr(module.subprocess, 'run', lambda *a, **kw: SimpleNamespace(
        returncode=0, stdout='\n'.join(rows), stderr='',
    ))
    runner = module.deep_udp_flow if module is udp else module.deep_rtp_flow
    tool = 'deep_udp_flow' if module is udp else 'deep_rtp_flow'
    first = runner(tmp_path / 'capture.pcap', flow_id=1, flow=flow, reason='first')
    assert first['packet_gaps']['by_direction'][0]['max_gap_ms'] == 2000
    assert first['packet_gaps']['by_direction'][0]['pause_count'] == 1
    assert len(first[sample_key]) == 1000
    full = runner(tmp_path / 'capture.pcap', flow_id=1, flow=flow, reason='save', sample_limit=None)
    flow.deep_details[tool] = full
    loaded = FlowSummary.model_validate_json(flow.model_dump_json())
    cached = run_deep_tool(tool, None, flow_id=1, flow=loaded, reason='next', sample_offset=1000)
    assert cached[sample_key][0]['direction_gap_ms'] == 2000
    assert cached['packet_gaps'] == first['packet_gaps']
    from flowpilot import reasoning

    summary = summarize_capture([])
    summary.flows = [loaded]
    summary.flow_count = 1
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(output_text='Measured gaps.', choices=[
            SimpleNamespace(message=SimpleNamespace(content='Measured gaps.')),
        ])

    client = SimpleNamespace(responses=SimpleNamespace(create=create),
                             chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(reasoning, 'LLM_REQUESTS_PER_MINUTE', 0)
    token = reasoning.EVIDENCE_START_OFFSET.set(1000)
    try:
        provider = (reasoning._chat_with_responses if module is udp
                    else reasoning._chat_with_chat_completions)
        provider(client, summary, 'Any pauses in flow 1?', model='test', max_flows=1,
                 report=None, history=None)
    finally:
        reasoning.EVIDENCE_START_OFFSET.reset(token)
    messages = calls[0]['input' if module is udp else 'messages']
    context = json.loads(messages[-1]['content'].split('\n\n', 1)[1])
    evidence = context['additional_tool_evidence'][0]
    assert evidence['packet_gaps']['by_direction'][0]['pause_count'] == 1
    assert evidence[sample_key][0]['direction_gap_ms'] == 2000

    if module is rtp:
        assert cached[sample_key][0]['stream_gap_ms'] == 2000
        assert cached['rtp_streams'][0]['packet_gaps']['pause_count'] == 1


def test_other_direction_and_ssrc_do_not_hide_pause():
    flow = FlowSummary(key=FlowKey(endpoint_a='a', endpoint_b='b', protocol='UDP'))
    rows = [
        {'src': src, 'frame.time_relative': time, 'rtp.ssrc': ssrc}
        for src, time, ssrc in [('a', '0', '1'), ('b', '.5', '1'), ('a', '1', '2'),
                                ('a', '2', '1')]
    ]
    stats = annotate_packet_gaps(rows, flow, rtp=True)
    assert rows[-1]['direction_gap_ms'] == 1000
    assert rows[-1]['stream_gap_ms'] == 2000
    assert stats['by_direction'][1]['max_gap_ms'] is None


def test_default_and_configured_thresholds_and_saved_counts():
    from flowpilot.models import PAUSE_THRESHOLD_MS

    assert PacketGapSummary().pause_threshold_ms == 100
    token = PAUSE_THRESHOLD_MS.set(50)
    try:
        stats = PacketGapSummary()
        for timestamp in ('0', '.049', '.099', '.199'):
            stats.record(timestamp)
        assert stats.pause_count == 2
        saved = stats.model_dump_json()
    finally:
        PAUSE_THRESHOLD_MS.reset(token)
    loaded = PacketGapSummary.model_validate_json(saved)
    assert loaded.pause_threshold_ms == 50
    assert loaded.pause_count == 2
    assert loaded.max_gap_ms == 100


@pytest.mark.parametrize('value', ['0', '-1', 'nan', 'inf'])
def test_cli_rejects_invalid_pause_threshold(value):
    from typer.testing import CliRunner

    from flowpilot.cli import app

    result = CliRunner().invoke(app, ['analyze', 'capture.pcap', '--pause-threshold-ms', value])
    assert result.exit_code != 0
    assert 'pause-threshold-ms' in result.output


@pytest.mark.parametrize('tool,key', [
    ('deep_udp_flow', 'udp_header_samples'), ('deep_rtp_flow', 'rtp_header_samples'),
])
def test_cached_threshold_recomputed_without_mutating_source(tool, key):
    from flowpilot.models import PAUSE_THRESHOLD_MS

    flow = FlowSummary(key=FlowKey(endpoint_a='a', endpoint_b='b', protocol='UDP'))
    flow.deep_details[tool] = {'status': 'ok', key: [
        {'src': 'a', 'frame.time_relative': t, 'rtp.ssrc': '1'} for t in ('0', '.05', '.15')
    ]}
    before = flow.model_dump_json()
    token = PAUSE_THRESHOLD_MS.set(50)
    try:
        result = run_deep_tool(tool, None, flow_id=1, flow=flow, reason='inspect', sample_offset=1)
    finally:
        PAUSE_THRESHOLD_MS.reset(token)
    assert result['packet_gaps']['by_direction'][0]['pause_count'] == 2
    assert result['packet_gaps']['by_direction'][0]['pause_threshold_ms'] == 50
    assert result[key][0]['direction_gap_ms'] == 50
    assert flow.model_dump_json() == before


def test_cli_applies_threshold_and_resets_context(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    from flowpilot import cli
    from flowpilot.models import PAUSE_THRESHOLD_MS

    monkeypatch.setattr(cli, 'FLOWPILOT_PRIVATE_DIR', tmp_path)
    monkeypatch.setattr(cli, '_capture_packet_count', lambda _: None)
    start = datetime(2026, 1, 1)
    packets = [PacketObservation(
        timestamp=start + timedelta(milliseconds=milliseconds),
        src_ip='10.0.0.1', dst_ip='10.0.0.2', protocol='UDP',
        rtp_ssrc='1', rtp_sequence=index,
    ) for index, milliseconds in enumerate((0, 50, 150))]
    monkeypatch.setattr(cli, 'read_capture', lambda *a, **kw: iter(packets))
    result = CliRunner().invoke(cli.app, [
        'analyze', '--pause-threshold-ms', '50', 'capture.pcap', '--no-llm',
    ])
    assert result.exit_code == 0, result.output
    summary = cli._load_summary(tmp_path / 'capture.json')
    assert summary.flows[0].packet_gaps_by_direction[0].pause_count == 2
    assert summary.flows[0].rtp_streams[0].packet_gaps.pause_count == 2
    assert PAUSE_THRESHOLD_MS.get() == 100
