import ipaddress
import json
import struct
from types import SimpleNamespace

import pytest
from test_ike import write_capture

from flowpilot import reasoning
from flowpilot.analysis import summarize_capture
from flowpilot.capture import read_capture
from flowpilot.deep_tools import collect_flow_details, deep_tool_requests_for_flow, run_deep_tool
from flowpilot.filters import FlowFilter
from flowpilot.models import CaptureSummary
from flowpilot.protocols.bgp import deep_bgp_flow
from flowpilot.protocols.deep_common import tshark_path


def message(kind, body=b''):
    return b'\xff' * 16 + struct.pack('!HB', 19 + len(body), kind) + body


def frame(a, b, sport, dport, payload, seq=1):
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 1, 0x50, 0x18, 65535, 0, 0) + payload
    a, b = ipaddress.ip_address(a), ipaddress.ip_address(b)
    if a.version == 4:
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                             a.packed, b.packed)
        ethertype = b'\x08\x00'
    else:
        header = struct.pack('!IHBB16s16s', 6 << 28, len(tcp), 6, 64, a.packed, b.packed)
        ethertype = b'\x86\xdd'
    return bytes.fromhex('00112233445566778899aabb') + ethertype + header + tcp


@pytest.mark.parametrize('family', [4, 6])
def test_bgp_real_headers_filters_saved_batches_and_provider(tmp_path, monkeypatch, family):
    if not tshark_path():
        pytest.skip('TShark required')
    a, b = ('10.0.0.1', '10.0.0.2') if family == 4 else ('2001:db8::1', '2001:db8::2')
    opening = message(1, struct.pack('!BHH4sB', 4, 65001, 90,
                                     ipaddress.ip_address('192.0.2.1').packed, 0))
    payload = opening + message(4) + message(4)
    path = tmp_path / 'bgp.pcap'
    write_capture(path, [frame(a, b, 40000, 179, payload),
                         frame(b, a, 179, 40000, message(3, bytes([6, 2]))),
                         frame(a, b, 179, 40000, message(4))])
    observations = list(read_capture(path))
    assert FlowFilter(protocol='bgp').matches(observations[0])
    assert observations[0].bgp_fields['bgp.open.myas'] == ['65001']
    summary = summarize_capture(observations[:2])
    flow = summary.flows[0]
    assert flow.bgp.packets_by_direction == [1, 1]
    assert flow.bgp.fields_by_direction[0]['bgp.type'] == {'1': 1, '4': 2}
    assert flow.bgp.fields_by_direction[1]['bgp.notify.major_error'] == {'6': 1}
    assert deep_tool_requests_for_flow(1, flow)['tool'] == 'deep_bgp_flow'
    assert FlowFilter(protocol='bgp', src=a).matches_flow(flow)
    result = deep_bgp_flow(path, flow_id=1, flow=flow, reason='inspect', sample_limit=1)
    assert result['status'] == 'ok', result
    assert result['packet_count'] == 2
    assert result['batch']['returned'] == 1
    assert result['batch']['next_offset'] == 1
    assert result['bgp_header_samples'][0]['bgp.type'] == '1,4,4'
    assert 'frame.time_relative' in result['bgp_header_samples'][0]
    collect_flow_details(path, flow, 1)
    assert len(flow.deep_details['deep_bgp_flow']['bgp_header_samples']) == 2
    loaded = CaptureSummary.model_validate_json(summary.model_dump_json())
    from typer.testing import CliRunner

    from flowpilot.cli import app

    saved_path = tmp_path / 'bgp.json'
    saved_path.write_text(loaded.model_dump_json())
    before = saved_path.read_bytes()
    cli_result = CliRunner().invoke(app, [
        'analyze', str(path), '--load-summary', str(saved_path), '--protocol', 'BGP', '--no-llm',
    ])
    assert cli_result.exit_code == 0, cli_result.output
    assert 'BGP Messages' in cli_result.output
    assert saved_path.read_bytes() == before
    cached = run_deep_tool('deep_bgp_flow', None, flow_id=5, flow=loaded.flows[0],
                           reason='next', sample_offset=1)
    assert cached['flow_id'] == 5
    assert cached['source'] == 'saved_summary'
    assert cached['bgp_header_samples'][0]['bgp.notify.major_error'] == '6'
    calls = []
    def create(**kw):
        calls.append(kw)
        return SimpleNamespace(output_text='Observed NOTIFICATION.', choices=[
            SimpleNamespace(message=SimpleNamespace(content='Observed NOTIFICATION.')),
        ])

    client = SimpleNamespace(responses=SimpleNamespace(create=create),
                             chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    monkeypatch.setattr(reasoning, 'LLM_REQUESTS_PER_MINUTE', 0)
    provider = (reasoning._chat_with_responses if family == 4
                else reasoning._chat_with_chat_completions)
    provider(client, loaded, 'inspect flow id 1', model='test',
             max_flows=1, report=None, history=None)
    messages = calls[0]['input' if family == 4 else 'messages']
    context = json.loads(messages[-1]['content'].split('\n\n', 1)[1])
    assert context['summary']['top_flows'][0]['bgp']['packets_by_direction'] == [1, 1]
    assert any(e['tool'] == 'deep_bgp_flow' for e in context['additional_tool_evidence'])


def test_bgp_update_refresh_and_large_batches(tmp_path):
    if not tshark_path():
        pytest.skip('TShark required')
    # Empty UPDATE (no withdrawals/attributes/NLRI) and ROUTE-REFRESH, then keepalives.
    payloads = [message(2, bytes(4)), message(5, struct.pack('!HBB', 1, 0, 1))]
    payloads += [message(4)] * 1001
    seq, frames = 1, []
    for payload in payloads:
        frames.append(frame('10.0.0.1', '10.0.0.2', 40000, 179, payload, seq))
        seq += len(payload)
    path = tmp_path / 'large.pcap'
    write_capture(path, frames)
    summary = summarize_capture(list(read_capture(path)))
    flow = summary.flows[0]
    result = deep_bgp_flow(path, flow_id=1, flow=flow, reason='page')
    assert result['status'] == 'ok', result
    assert result['batch']['returned'] == 1000
    assert result['batch']['total_matching_packets'] == 1003
    assert flow.bgp.fields_by_direction[0]['bgp.type']['4'] == 1001
    assert flow.bgp.fields_by_direction[0]['bgp.route_refresh.afi'] == {'1': 1}
    result = deep_bgp_flow(path, flow_id=1, flow=flow, reason='last', sample_offset=1000)
    assert result['batch']['returned'] == 3
    assert result['batch']['has_more'] is False


def test_bgp_update_attributes_and_old_summary_defaults(tmp_path):
    if not tshark_path():
        pytest.skip('TShark required')
    attributes = (bytes.fromhex('40010100') +  # ORIGIN IGP
                  bytes.fromhex('4002040201fde9') +  # AS_SEQUENCE 65001
                  bytes.fromhex('400304c0000201'))  # NEXT_HOP 192.0.2.1
    update = struct.pack('!H', 0) + struct.pack('!H', len(attributes)) + attributes
    update += bytes([24, 203, 0, 113])
    path = tmp_path / 'update.pcap'
    write_capture(path, [frame('10.0.0.1', '10.0.0.2', 40000, 179, message(2, update))])
    summary = summarize_capture(list(read_capture(path)))
    fields = summary.flows[0].bgp.fields_by_direction[0]
    assert fields['bgp.nlri_prefix'] == {'203.0.113.0': 1}
    assert fields['bgp.update.path_attribute.next_hop'] == {'192.0.2.1': 1}
    assert fields['bgp.update.path_attribute.as_path_segment.as2'] == {'65001': 1}
    result = deep_bgp_flow(path, flow_id=1, flow=summary.flows[0], reason='update')
    assert result['header_summary']['fields_by_direction'][0] == fields
    old = summary.model_dump()
    del old['flows'][0]['bgp']
    assert CaptureSummary.model_validate(old).flows[0].bgp.packet_count == 0
