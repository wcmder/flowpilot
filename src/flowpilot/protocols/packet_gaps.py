from ..models import PacketGapSummary


def annotate_packet_gaps(rows, flow, *, rtp=False):
    """Compute over all matching rows before paging; preserve cross-page predecessors."""
    directions = [PacketGapSummary(), PacketGapSummary()]
    streams = {}
    for row in rows:
        direction = 0 if (row.get('src') == flow.key.endpoint_a and (
            flow.key.port_a is None or row.get('udp.srcport') == str(flow.key.port_a))) else 1
        seconds = row.get('frame.time_relative')
        row['direction_gap_ms'] = directions[direction].record(seconds)
        row['gap_direction'] = 'A_to_B' if direction == 0 else 'B_to_A'
        if rtp and row.get('rtp.ssrc') is not None:
            key = (direction, row['rtp.ssrc'])
            stats = streams.setdefault(key, PacketGapSummary())
            row['stream_gap_ms'] = stats.record(seconds)
    return {
        'scope': 'All matching packets before pagination; offsets do not reset gap tracking.',
        'by_direction': [stats.compact() for stats in directions],
        'by_ssrc': [
            {'direction': 'A_to_B' if direction == 0 else 'B_to_A', 'ssrc': ssrc,
             **stats.compact()} for (direction, ssrc), stats in streams.items()
        ],
    }
