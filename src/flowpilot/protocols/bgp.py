from __future__ import annotations

import subprocess

from ..models import BgpSummary
from .deep_common import (
    DEFAULT_EVIDENCE_BATCH_SIZE,
    evidence_batch,
    field_command,
    parse_field_rows,
    tcp_flow_filter,
    tshark_path,
)

BGP_FIELDS = [
    'bgp.type', 'bgp.length', 'bgp.open.version', 'bgp.open.myas',
    'bgp.open.holdtime', 'bgp.open.identifier', 'bgp.cap.type', 'bgp.cap.4as',
    'bgp.cap.mp.afi', 'bgp.cap.mp.safi', 'bgp.notify.major_error',
    *[f'bgp.notify.minor_error{s}' for s in (
        '', '_open', '_update', '_expired', '_state', '_cease', '_route_refresh', '_unknown')],
    'bgp.nlri_prefix', 'bgp.withdrawn_prefix', 'bgp.prefix_length',
    'bgp.update.path_attribute.origin', 'bgp.update.path_attribute.next_hop',
    'bgp.update.path_attribute.local_pref', 'bgp.update.path_attribute.multi_exit_disc',
    'bgp.update.path_attribute.as_path_segment.as2',
    'bgp.update.path_attribute.as_path_segment.as4',
    'bgp.route_refresh.afi', 'bgp.route_refresh.safi', 'bgp.route_refresh.subtype',
]
ASSESSMENT = (
    'BGP message types: 1 OPEN, 2 UPDATE, 3 NOTIFICATION, 4 KEEPALIVE, 5 ROUTE-REFRESH. '
    'Analyze observed NOTIFICATION codes/subcodes and sender direction first; correlate '
    'with TCP resets/retransmissions. OPEN AS/hold-time/capabilities are advertised values, '
    'not necessarily negotiated values. Different peer AS numbers may be normal eBGP. '
    'Messages are dissector observations, not unique transmissions: retransmission and '
    'TCP reassembly affect counts. One frame may contain multiple BGP messages. '
    'Repeated fields are flattened and cannot safely associate attributes with particular '
    'NLRI or individual messages. Missing messages do not prove loss or a failed session; '
    'KEEPALIVE alone does not prove establishment. Do not infer installed routes, best-path '
    'selection, routing loops, or latency from these headers. No RIB/FSM reconstruction, '
    'complete multiprotocol NLRI decoding, authentication validation, or payload extraction.'
)


def extract_bgp(packet, helpers):
    if helpers.protocol != 'TCP':
        return {}
    fields = {}
    # PyShark may expose multiple BGP layers for coalesced messages.
    layers = [layer for layer in getattr(packet, "layers", []) if layer.layer_name == 'bgp']
    for layer in layers:
        for field in BGP_FIELDS:
            values = getattr(layer, field[4:].replace('.', '_'), None)
            if values is not None:
                fields.setdefault(field, []).extend(
                    str(getattr(value, 'show', None) or value)
                    for value in getattr(values, 'all_fields', [values])
                )
    return {'bgp_fields': fields} if fields else {}


def _record(summary, fields, direction):
    if not fields:
        return
    summary.packet_count += 1
    summary.packets_by_direction[direction] += 1
    for field, values in fields.items():
        counts = summary.fields_by_direction[direction].setdefault(field, {})
        for value in values:
            counts[value] = counts.get(value, 0) + 1


def record_bgp(flow, packet):
    forward = packet.source_endpoint == flow.key.endpoint_a and (
        flow.key.port_a is None or packet.src_port == flow.key.port_a)
    _record(flow.bgp, packet.bgp_fields, 0 if forward else 1)


def deep_bgp_reason(flow):
    return 'Inspect BGP messages, OPEN parameters and NOTIFICATION errors.' if (
        flow.bgp.packet_count or 'BGP' in flow.decoded_protocols) else None


def deep_bgp_flow(capture_path, *, flow_id, flow, reason,
                  sample_limit=DEFAULT_EVIDENCE_BATCH_SIZE, sample_offset=0, timeout=120):
    base = {'tool': 'deep_bgp_flow', 'flow_id': flow_id, 'reason': reason}
    if flow.key.protocol != 'TCP':
        return {**base, 'status': 'skipped', 'message': 'BGP requires a TCP flow.'}
    tshark = tshark_path()
    if not tshark:
        return {**base, 'status': 'unavailable', 'message': 'TShark not found.'}
    fields = ['frame.number', 'frame.time_relative', 'frame.len', 'ip.src', 'ipv6.src',
              'ip.dst', 'ipv6.dst', 'tcp.srcport', 'tcp.dstport', *BGP_FIELDS]
    display_filter = f'({tcp_flow_filter(flow)}) && bgp'
    try:
        command = field_command(tshark, capture_path, display_filter, fields,
                                occurrence='a', aggregator=',')
        command[1:1] = ['-o', 'tcp.desegment_tcp_streams:TRUE']
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                                check=False)
        if result.returncode:
            return {**base, 'status': 'error', 'message': result.stderr.strip()}
        rows = parse_field_rows(result.stdout, fields)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {**base, 'status': 'error', 'message': str(exc)}
    summary = BgpSummary()
    for row in rows:
        forward = row['src'] == flow.key.endpoint_a and (
            flow.key.port_a is None or row.get('tcp.srcport') == str(flow.key.port_a))
        _record(summary, {f: row[f].split(',') for f in BGP_FIELDS if f in row},
                0 if forward else 1)
    return {
        **base, 'status': 'ok', 'display_filter': display_filter,
        'packet_count': len(rows), 'header_summary': summary.model_dump(),
        'assessment': ASSESSMENT, 'bgp_header_fields': fields,
        'bgp_header_samples': rows[sample_offset:sample_offset + sample_limit
                                   if sample_limit is not None else None],
        'sample_limit': sample_limit,
        'truncated': sample_offset > 0 or (sample_limit is not None and len(rows) > sample_limit),
        'batch': evidence_batch(len(rows), sample_offset, sample_limit),
    }


def render_bgp_details(summary, *, show_flows, console):
    from rich.table import Table

    table = Table(title='BGP Messages', caption=ASSESSMENT)
    for name in ('Flow ID', 'Endpoints A ↔ B', 'Packets A/B', 'A → B fields', 'B → A fields'):
        table.add_column(name, overflow='fold')
    for flow_id, flow in enumerate(summary.flows[:show_flows], 1):
        if flow.bgp.packet_count:
            table.add_row(str(flow_id),
                          f'{flow.key.endpoint_a}:{flow.key.port_a} ↔ '
                          f'{flow.key.endpoint_b}:{flow.key.port_b}',
                          str(flow.bgp.packets_by_direction),
                          *[str(fields) for fields in flow.bgp.fields_by_direction])
    if table.row_count:
        console.print(table)
