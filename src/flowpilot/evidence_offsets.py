"""Local evidence bookmarks in each deep tool's matching-packet coordinate space."""
from collections import defaultdict

from .models import FlowKey, PacketGapSummary

CONTEXT_PACKETS = 100


def annotate_evidence_offsets(observations):
    counters = defaultdict(int)
    timing = {}
    sequences = {}
    for packet in observations:
        if packet.evidence_offsets_indexed:
            yield packet
            continue
        key = FlowKey.from_packet(packet)
        direction = 0 if (packet.source_endpoint == key.endpoint_a and
                          (key.port_a is None or packet.src_port == key.port_a)) else 1
        primary = {'TCP': 'deep_tcp_flow', 'UDP': 'deep_udp_flow', 'ESP': 'deep_esp_flow',
                   'MACSEC': 'deep_macsec_flow', 'EAPOL': 'deep_eapol_flow'}.get(key.protocol)
        tools = [primary] if primary else []
        # Only decoded layers satisfy the protocol-specific deep display filters.
        layers = {name.upper() for name in packet.decoded_protocols}
        if key.protocol in {'TCP', 'UDP'} and layers & {'TLS', 'DTLS'}:
            tools.append('deep_tls_flow')
        if key.protocol == 'TCP':
            if 'SMB2' in layers:
                tools.append('deep_smb2_flow')
            if 'BGP' in layers:
                tools.append('deep_bgp_flow')
        if key.protocol == 'UDP':
            if 'RTP' in layers:
                tools.append('deep_rtp_flow')
            if 'ISAKMP' in layers and 'ESP' not in layers:
                tools.append('deep_ike_flow')
        reasons = list(dict.fromkeys(packet.issue_tags))
        if packet.dns_response_code not in (None, '', '0', 'No error'):
            reasons.append(f'DNS response code {packet.dns_response_code}')
        if packet.sip_status_code is not None and packet.sip_status_code >= 400:
            reasons.append(f'SIP status {packet.sip_status_code}')
        if packet.tls_alert_level is not None:
            reasons.append(f'TLS alert {packet.tls_alert_level}: {packet.tls_alert_description}')
        if packet.bgp_fields.get('bgp.notify.major_error'):
            reasons.append('BGP NOTIFICATION: ' + ','.join(
                packet.bgp_fields['bgp.notify.major_error']))
        if '4' in packet.eapol_fields.get('eap.code', []):
            reasons.append('EAP Failure observed')
        if packet.ike and any(0 < code < 16384 for code in packet.ike.notify_types):
            reasons.append('IKE error notification observed')
        seconds = packet.timestamp_epoch or (
            str(packet.timestamp.timestamp()) if packet.timestamp is not None else None)
        stats = timing.setdefault((key, direction, None), PacketGapSummary())
        gap = stats.record(seconds)
        if gap is not None and gap >= stats.pause_threshold_ms:
            reasons.append(f'Direction packet gap {gap:g} ms '
                           f'(threshold {stats.pause_threshold_ms:g} ms)')
        media_reasons = []
        if packet.rtp_ssrc is not None:
            stats = timing.setdefault((key, direction, packet.rtp_ssrc), PacketGapSummary())
            gap = stats.record(seconds)
            if gap is not None and gap >= stats.pause_threshold_ms:
                media_reasons.append(f'RTP SSRC {packet.rtp_ssrc} gap {gap:g} ms')
        for protocol, stream, sequence in (
            ('ESP', packet.esp_spi, packet.esp_sequence),
            ('RTP', packet.rtp_ssrc, packet.rtp_sequence),
        ):
            if stream is None or sequence is None:
                continue
            state = sequences.setdefault(
                (key, direction, protocol, stream), {'high': None, 'seen': set()})
            high = state['high']
            extended = (high + ((sequence - high + 32768) % 65536 - 32768)
                        if protocol == 'RTP' and high is not None else sequence)
            label = None
            if extended in state['seen']:
                label = 'duplicate sequence'
            elif high is not None and extended < high:
                label = 'out-of-order sequence'
            elif high is not None and extended > high + 1:
                label = f'sequence gap of {extended - high - 1}'
            if label:
                target = media_reasons if protocol == 'RTP' else reasons
                target.append(f'{protocol} {stream}: {label} observed (not proven loss)')
            state['seen'].add(extended)
            state['high'] = max(high, extended) if high is not None else extended
        reasons.extend(media_reasons)
        for tool in tools:
            position = counters[(key, tool)]
            counters[(key, tool)] += 1
            if reasons:
                packet.recommended_evidence_offsets.append({
                    'tool': tool, 'sample_offset': max(0, position - CONTEXT_PACKETS),
                    'issue_packet_index': position, 'frame_number': packet.frame_number,
                    'time_relative': packet.time_relative,
                    'timestamp_epoch': packet.timestamp_epoch,
                    'direction': 'A_to_B' if direction == 0 else 'B_to_A',
                    'reasons': list(dict.fromkeys(reasons)),
                })
        packet.evidence_offsets_indexed = True
        yield packet


def merge_evidence_offsets(entries):
    """Keep one window per tool until the next trigger falls outside its 1000 rows."""
    groups = []
    latest = {}
    for entry in entries:
        # Already merged summaries retain their complete local event list.
        events = entry.get('events') or [{k: v for k, v in entry.items()
                                         if k not in {'tool', 'sample_offset'}}]
        for event in events:
            reasons = event.get('reasons')
            if reasons is None:
                reasons = [entry['reasons'][i] for i in event['reason_indices']]
            position = event['issue_packet_index']
            tool = entry['tool']
            group = latest.get(tool)
            if group is None or not (group['sample_offset'] <= position <
                                      group['sample_offset'] + 1000):
                group = {**entry, **{k: v for k, v in event.items()
                                    if k not in {'reasons', 'reason_indices'}},
                         'sample_offset': max(0, position - CONTEXT_PACKETS),
                         'reasons': [], 'events': [], 'issue_count': 0, 'batch_size': 1000}
                groups.append(group)
                latest[tool] = group
            indices = []
            for reason in reasons:
                if reason not in group['reasons']:
                    group['reasons'].append(reason)
                indices.append(group['reasons'].index(reason))
            group['events'].append({k: v for k, v in event.items()
                                    if k not in {'reasons', 'reason_indices'}} |
                                   {'reason_indices': indices})
            group['issue_count'] += 1
    return groups


def render_evidence_offsets(summary, *, console, show_flows):
    from rich.table import Table

    table = Table(title='Recommended Evidence Offsets', caption=(
        'Zero-based matching-packet offsets per tool; 1000-packet windows, '
        'starting up to 100 packets before the first trigger. '
        'Triggers are observations, not confirmed failures. --offset remains a minimum.'
    ))
    for column in ('Flow ID', 'Tool', 'Offset', 'First issue / frame', 'Issues', 'Reason'):
        table.add_column(column, overflow='fold')
    for flow_id, flow in enumerate(summary.flows[:show_flows], 1):
        for item in flow.recommended_evidence_offsets:
            table.add_row(str(flow_id), item['tool'], str(item['sample_offset']),
                          f"{item['issue_packet_index']} / {item.get('frame_number')}",
                          str(item.get('issue_count', 1)), '; '.join(item['reasons']))
    if table.row_count:
        console.print(table)
