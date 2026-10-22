import json
from datetime import datetime, timedelta
from io import StringIO
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from flowpilot import cli, reasoning
from flowpilot.analysis import summarize_capture
from flowpilot.evidence_offsets import annotate_evidence_offsets
from flowpilot.models import CaptureSummary, PacketObservation


def packets(protocol='TCP', count=301):
    start = datetime(2026, 1, 1)
    return [PacketObservation(
        src_ip='10.0.0.1', dst_ip='10.0.0.2', src_port=1000, dst_port=2000,
        protocol=protocol, frame_number=10000 + i, timestamp=start + timedelta(milliseconds=i),
        decoded_protocols=[protocol],
    ) for i in range(count)]


def test_transport_and_tls_offsets_have_independent_coordinates():
    observations = packets()
    for i in range(0, 301, 2):
        observations[i].decoded_protocols.append('TLS')
    observations[300].issue_tags = ['tcp_retransmission']
    summary = summarize_capture(observations)
    entries = summary.flows[0].recommended_evidence_offsets
    assert [(e['tool'], e['issue_packet_index'], e['sample_offset']) for e in entries] == [
        ('deep_tcp_flow', 300, 200), ('deep_tls_flow', 150, 50),
    ]
    assert all(e['frame_number'] == 10300 for e in entries)
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json())
    assert loaded.compact()['top_flows'][0]['recommended_evidence_offsets'] == entries


def test_start_clamping_rtp_stream_gap_and_sequence_triggers():
    observations = packets('UDP', 5)
    for index, packet in enumerate(observations):
        packet.decoded_protocols.append('RTP')
        packet.rtp_ssrc = '1'
        packet.rtp_sequence = index + (3 if index >= 3 else 0)
    observations[4].timestamp += timedelta(seconds=1)
    summary = summarize_capture(observations)
    entries = summary.flows[0].recommended_evidence_offsets
    assert {e['tool'] for e in entries} == {'deep_udp_flow', 'deep_rtp_flow'}
    assert all(e['sample_offset'] == 0 for e in entries)
    assert any('sequence gap of 3' in str(e['reasons']) for e in entries)
    assert any('gap 1001 ms' in str(e['reasons']) for e in entries)


def test_esp_sequence_and_no_issue_defaults():
    observations = packets('ESP', 2)
    for i, packet in enumerate(observations):
        packet.esp_spi = '0x01'
        packet.esp_sequence = 1 + 6 * i
    entries = summarize_capture(observations).flows[0].recommended_evidence_offsets
    assert len(entries) == 1
    assert entries[0]['tool'] == 'deep_esp_flow'
    assert 'sequence gap of 5' in str(entries[0]['reasons'])
    assert summarize_capture(packets()).flows[0].recommended_evidence_offsets == []


def test_cli_filter_keeps_original_tool_offsets_and_prints(monkeypatch, tmp_path):
    from rich.console import Console

    output = StringIO()
    monkeypatch.setattr(cli, "console", Console(file=output, width=120))
    observations = packets()
    for i, packet in enumerate(observations):
        if i % 2 == 0:
            packet.decoded_protocols.append('TLS')
    observations[300].issue_tags = ['tcp_retransmission']
    monkeypatch.setattr(cli, 'FLOWPILOT_PRIVATE_DIR', tmp_path)
    monkeypatch.setattr(cli, '_capture_packet_count', lambda _: None)
    monkeypatch.setattr(cli, 'read_capture', lambda *a, **kw: iter(observations))
    result = CliRunner().invoke(cli.app, [
        'analyze', 'capture.pcap', '--protocol', 'TLS', '--no-llm',
    ])
    assert result.exit_code == 0, result.output
    assert 'Recommended Evidence Offsets' in output.getvalue()
    summary = cli._load_summary(tmp_path / 'capture.json')
    assert summary.packet_count == 151
    entries = summary.flows[0].recommended_evidence_offsets
    assert entries[0]['issue_packet_index'] == 300
    assert entries[0]['sample_offset'] == 200
    assert entries[1]['sample_offset'] == 50


@pytest.mark.parametrize('api', ['responses', 'chat_completions'])
def test_recommendations_reach_actual_provider_arguments(monkeypatch, api):
    observations = packets()
    observations[250].issue_tags = ['tcp_zero_window']
    summary = summarize_capture(observations)
    calls = []

    def create(**kw):
        calls.append(kw)
        return SimpleNamespace(output_text='Inspect offset 150.', choices=[
            SimpleNamespace(message=SimpleNamespace(content='Inspect offset 150.')),
        ])

    client = SimpleNamespace(responses=SimpleNamespace(create=create),
                             chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(reasoning, 'LLM_REQUESTS_PER_MINUTE', 0)
    provider = (reasoning._chat_with_responses if api == 'responses'
                else reasoning._chat_with_chat_completions)
    provider(client, summary, 'Inspect flow 1', model='test', max_flows=1,
             report=None, history=None)
    messages = calls[0]['input' if api == 'responses' else 'messages']
    context = json.loads(messages[-1]['content'].split('\n\n', 1)[1])
    entries = context['summary']['top_flows'][0]['recommended_evidence_offsets']
    assert entries[0]['sample_offset'] == 150
    assert entries[0]['reasons'] == ['tcp_zero_window']


def test_annotation_is_not_reindexed_after_filtering():
    observations = packets()
    observations[-1].issue_tags = ['tcp_reset']
    annotated = list(annotate_evidence_offsets(observations))
    flow = summarize_capture(annotated[-1:]).flows[0]
    assert flow.recommended_evidence_offsets[0]['sample_offset'] == 200


def test_recommended_offset_targets_real_deep_tool_rows(tmp_path):
    from test_bgp import frame, message
    from test_ike import write_capture

    from flowpilot.capture import read_capture
    from flowpilot.protocols.bgp import deep_bgp_flow
    from flowpilot.protocols.deep_common import tshark_path

    if not tshark_path():
        pytest.skip('TShark required')
    payloads = [message(4)] * 250 + [message(3, bytes([6, 2]))]
    frames, sequence = [], 1
    for payload in payloads:
        frames.append(frame('10.0.0.1', '10.0.0.2', 40000, 179, payload, sequence))
        sequence += len(payload)
    path = tmp_path / 'bgp.pcap'
    write_capture(path, frames)
    flow = summarize_capture(list(read_capture(path))).flows[0]
    recommendation = next(e for e in flow.recommended_evidence_offsets
                          if e['tool'] == 'deep_bgp_flow' and
                          any('NOTIFICATION' in reason for reason in e['reasons']))
    assert recommendation['sample_offset'] == 150
    result = deep_bgp_flow(path, flow_id=1, flow=flow, reason='recommended',
                           sample_offset=recommendation['sample_offset'])
    assert result['status'] == 'ok', result
    assert result['bgp_header_samples'][0]['frame.number'] == '151'
    assert result['bgp_header_samples'][100]['bgp.notify.major_error'] == '6'
