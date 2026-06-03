from __future__ import annotations

from collections import Counter

from ..models import EspSequenceSummary, FlowSummary, PacketObservation


def record_esp_sequence(flow: FlowSummary, packet: PacketObservation) -> None:
    direction = (
        f"{_endpoint(packet.src_ip, packet.src_port)} -> "
        f"{_endpoint(packet.dst_ip, packet.dst_port)}"
    )
    sequence = next(
        (
            item
            for item in flow.esp_sequences
            if item.spi == packet.esp_spi and item.direction == direction
        ),
        None,
    )
    if sequence is None:
        sequence = EspSequenceSummary(spi=packet.esp_spi, direction=direction)
        flow.esp_sequences = [*flow.esp_sequences, sequence][:25]

    current = packet.esp_sequence
    sequence.packet_count += 1
    if sequence.first_sequence is None:
        sequence.first_sequence = current
    is_duplicate = current in sequence.seen_sequences
    if is_duplicate:
        sequence.duplicate_count += 1
    if sequence.highest_sequence is not None and not is_duplicate:
        if current < sequence.highest_sequence:
            sequence.out_of_order_count += 1
        elif current > sequence.highest_sequence + 1:
            gap_size = current - sequence.highest_sequence
            missing_count = gap_size - 1
            sequence.gap_occurrences = [
                *sequence.gap_occurrences,
                {
                    "after_sequence": sequence.highest_sequence,
                    "next_sequence": current,
                    "gap": missing_count,
                    "missing": missing_count,
                },
            ]
            sequence.largest_sequence_gap = max(
                sequence.largest_sequence_gap,
                missing_count,
            )
    sequence.seen_sequences.add(current)
    sequence.highest_sequence = max(sequence.highest_sequence or current, current)
    sequence.last_sequence = current


def format_esp_sequences(sequences: list[EspSequenceSummary]) -> str:
    lines = []
    for sequence in sequences[:6]:
        lines.append(
            f"{sequence.direction} "
            f"pkts={sequence.packet_count} "
            f"missing={sequence.missing_count} "
            f"ooo={sequence.out_of_order_count} "
            f"dup={sequence.duplicate_count} "
            f"gaps={format_esp_gap_distribution(sequence.gap_occurrences)}"
        )
    if len(sequences) > 6:
        lines.append(f"... {len(sequences) - 6} more ESP directions/SPIs")
    return "\n".join(lines)


def format_esp_gap_distribution(gaps: list[dict[str, int]]) -> str:
    if not gaps:
        return "none"
    counts = Counter(gap["missing"] for gap in gaps)
    return " ".join(f"gap={missing}(x{count})" for missing, count in sorted(counts.items()))


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip
