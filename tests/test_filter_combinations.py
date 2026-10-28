import pytest
from typer.testing import CliRunner

from flowpilot import cli
from flowpilot.analysis import summarize_capture
from flowpilot.filters import FlowFilter
from flowpilot.models import PacketObservation


def packet(src='10.0.0.1', dst='10.0.0.2', protocol='TCP', src_port=0, dst_port=443):
    return PacketObservation(src_ip=src, dst_ip=dst, protocol=protocol,
                             src_port=src_port, dst_port=dst_port)


@pytest.mark.parametrize('field,values', [
    ('host', ['missing', '10.0.0.1']), ('peer', ['missing', '10.0.0.2']),
    ('protocol', ['ESP', 'tcp']), ('port', [99, 0]),
    ('src', ['missing', '10.0.0.1']), ('dst', ['missing', '10.0.0.2']),
    ('src_port', [99, 0]), ('dst_port', [99, 443]),
])
def test_repeatable_fields_match_any_value_fresh_and_saved(field, values):
    observation = packet()
    flow = summarize_capture([observation]).flows[0]
    rule = FlowFilter(**{field: values})
    assert rule.matches(observation)
    assert rule.matches_flow(flow)
    assert not FlowFilter(**{field: values[:1]}).matches(observation)
    assert not FlowFilter(**{field: values[:1]}).matches_flow(flow)


def test_or_direction_does_not_borrow_unobserved_reverse_but_protocol_can_match():
    observation = packet()
    flow = summarize_capture([observation]).flows[0]
    assert not FlowFilter(src=['10.0.0.2'], protocol=['ESP'], match_any=True).matches_flow(flow)
    assert FlowFilter(src=['10.0.0.2'], protocol=['TCP'], match_any=True).matches_flow(flow)
    assert not FlowFilter(src=['10.0.0.1'], dst_port=[0]).matches_flow(flow)
    assert FlowFilter(src=['10.0.0.1'], dst_port=[0], match_any=True).matches_flow(flow)


def test_host_peer_pairing_and_or():
    p = packet()
    assert not FlowFilter(host=['10.0.0.1'], peer=['10.0.0.1']).matches(p)
    assert FlowFilter(host=['10.0.0.1'], peer=['10.0.0.1'], match_any=True).matches(p)
    assert FlowFilter(host=['other', '10.0.0.1'], peer=['10.0.0.2']).matches(p)
    assert FlowFilter(host=[], protocol=[], match_any=True).matches(p)


@pytest.mark.parametrize('mode,expected', [([], 1), (['--and'], 1), (['--or'], 3)])
@pytest.mark.parametrize('loaded', [False, True])
def test_cli_filter_combinations(tmp_path, monkeypatch, mode, expected, loaded):
    observations = [packet(), packet(src='10.0.0.3', protocol='UDP'),
                    packet(src='10.0.0.4'), packet(src='10.0.0.5', protocol='UDP')]
    monkeypatch.setattr(cli, 'FLOWPILOT_PRIVATE_DIR', tmp_path)
    monkeypatch.setattr(cli, '_capture_packet_count', lambda _: None)
    monkeypatch.setattr(cli, 'read_capture', lambda *a, **kw: iter(observations))
    source = tmp_path / 'source.json'
    source.write_text(summarize_capture(observations).model_dump_json())
    before = source.read_bytes()
    args = ['analyze', 'capture.pcap', '--host', '10.0.0.1', '--host', '10.0.0.3',
            '--protocol', 'TCP', '--protocol', 'ESP', '--no-llm', '--json', 'result.json', *mode]
    if loaded:
        args += ['--load-summary', str(source)]
    result = CliRunner().invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    assert cli._load_summary(tmp_path / 'result.json').packet_count == expected
    assert source.read_bytes() == before


def test_cli_validates_each_protocol_value():
    result = CliRunner().invoke(cli.app, ['analyze', 'capture.pcap', '--protocol', 'tcp',
                                         '--protocol', 'udp or esp', '--no-llm'])
    assert result.exit_code != 0
    assert '--protocol accepts one decoded protocol name' in result.output
