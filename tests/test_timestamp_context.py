import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from flowpilot import reasoning
from flowpilot.analysis import summarize_capture
from flowpilot.models import CaptureSummary, PacketObservation


@pytest.mark.parametrize('api', ['responses', 'chat_completions'])
@pytest.mark.parametrize('tls', [False, True])
def test_saved_tcp_tls_timestamps_reach_provider(monkeypatch, api, tls):
    start = datetime(2026, 10, 21, 10, 0, 0, 123456, tzinfo=timezone.utc)
    packet = PacketObservation(timestamp=start, src_ip='10.0.0.1', dst_ip='10.0.0.2',
                               protocol='TCP', tls_sni='example.test' if tls else None)
    summary = summarize_capture([
        packet, packet.model_copy(update={'timestamp': start + timedelta(seconds=2)}),
    ])
    tool = 'deep_tls_flow' if tls else 'deep_tcp_flow'
    samples = 'tls_deep_samples' if tls else 'tcp_header_samples'
    summary.flows[0].deep_details[tool] = {
        'status': 'ok', 'tool': tool, 'flow_id': 1, 'packet_count': 1,
        samples: [{'frame.number': '7', 'frame.time_relative': '12.345678',
                   'frame.time_epoch': '1792576812.345678901'}],
    }
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json())
    calls = []

    def create(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(output_text='Timing available.', choices=[
            SimpleNamespace(message=SimpleNamespace(content='Timing available.')),
        ])

    client = SimpleNamespace(responses=SimpleNamespace(create=create),
                             chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(reasoning, 'LLM_REQUESTS_PER_MINUTE', 0)
    provider = (reasoning._chat_with_responses if api == 'responses'
                else reasoning._chat_with_chat_completions)
    provider(client, loaded, 'When did flow 1 start?', model='test', max_flows=1,
             report=None, history=None)
    messages = calls[0]['input' if api == 'responses' else 'messages']
    context = json.loads(messages[-1]['content'].split('\n\n', 1)[1])
    flow = context['summary']['top_flows'][0]
    assert flow['first_seen'] == start.isoformat()
    assert flow['last_seen'] == (start + timedelta(seconds=2)).isoformat()
    assert context['additional_tool_evidence'][0][samples][0]['frame.time_relative'] == '12.345678'
    assert context['additional_tool_evidence'][0][samples][0]['frame.time_epoch'] == (
        '1792576812.345678901'
    )


def test_missing_and_naive_timestamp_metadata():
    summary = summarize_capture([PacketObservation(src_ip='a', dst_ip='b', protocol='UDP')])
    assert summary.compact()['top_flows'][0]['first_seen'] is None
    assert summary.compact()['top_flows'][0]['last_seen'] is None
    summary.flows[0].first_seen = datetime(2026, 10, 21)
    assert summary.compact()['top_flows'][0]['first_seen'] == '2026-10-21T00:00:00'


def test_every_deep_field_list_includes_packet_timestamps():
    from flowpilot.protocols.esp import ESP_DEEP_FIELDS
    from flowpilot.protocols.ike import IKE_HEADER_FIELDS
    from flowpilot.protocols.link_security import LINK_FIELDS
    from flowpilot.protocols.rtp import RTP_HEADER_FIELDS
    from flowpilot.protocols.smb import SMB2_DEEP_FIELDS
    from flowpilot.protocols.tcp import TCP_HEADER_FIELDS
    from flowpilot.protocols.tls import TLS_DEEP_FIELDS
    from flowpilot.protocols.udp import UDP_HEADER_FIELDS

    for fields in (ESP_DEEP_FIELDS, IKE_HEADER_FIELDS, LINK_FIELDS, RTP_HEADER_FIELDS,
                   SMB2_DEEP_FIELDS, TCP_HEADER_FIELDS, TLS_DEEP_FIELDS, UDP_HEADER_FIELDS):
        assert {'frame.number', 'frame.time_relative', 'frame.time_epoch'} <= set(fields)


def test_real_packet_timestamps_preserved_in_details_and_batches(tmp_path):
    from test_deep_filters import _frame
    from test_ike import write_capture

    from flowpilot.capture import read_capture
    from flowpilot.deep_tools import run_deep_tool
    from flowpilot.protocols.deep_common import tshark_path
    from flowpilot.protocols.udp import deep_udp_flow

    if not tshark_path():
        pytest.skip('TShark required')
    path = tmp_path / 'timestamps.pcap'
    write_capture(path, [_frame('10.0.0.1', '10.0.0.2', 1000, 2000, 'udp')] * 3)
    packets = list(read_capture(path))
    assert [p.frame_number for p in packets] == [1, 2, 3]
    assert [float(p.timestamp_epoch) for p in packets] == [1, 2, 3]
    assert [float(p.time_relative) for p in packets] == [0, 1, 2]
    summary = summarize_capture(packets)
    flow = summary.flows[0]
    flow.packet_details = packets
    flow.deep_details['deep_udp_flow'] = deep_udp_flow(
        path, flow_id=1, flow=flow, reason='save', sample_limit=None,
    )
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json()).flows[0]
    assert loaded.packet_details == packets
    batch = run_deep_tool('deep_udp_flow', None, flow_id=1, flow=loaded,
                          reason='last', sample_offset=2)
    row = batch['udp_header_samples'][0]
    assert row['frame.number'] == '3'
    assert float(row['frame.time_epoch']) == 3
    assert float(row['frame.time_relative']) == 2
