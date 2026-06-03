from flowpilot.models import FlowKey, FlowSummary, PacketObservation
from flowpilot.protocols.esp import format_esp_sequences, record_esp_sequence


def test_record_esp_sequence_tracks_gaps_duplicates_and_out_of_order() -> None:
    flow = FlowSummary(key=FlowKey(endpoint_a="10.0.0.1", endpoint_b="10.0.0.2", protocol="ESP"))
    for sequence in (1, 2, 5, 5, 4):
        record_esp_sequence(
            flow,
            PacketObservation(
                src_ip="10.0.0.1",
                dst_ip="10.0.0.2",
                protocol="ESP",
                esp_spi="0x1234",
                esp_sequence=sequence,
            ),
        )

    esp = flow.esp_sequences[0]

    assert esp.packet_count == 5
    assert esp.first_sequence == 1
    assert esp.last_sequence == 4
    assert esp.missing_count == 1
    assert esp.largest_sequence_gap == 2
    assert esp.duplicate_count == 1
    assert esp.out_of_order_count == 1
    assert esp.gap_occurrences == [
        {"after_sequence": 2, "next_sequence": 5, "gap": 2, "missing": 2}
    ]
    assert format_esp_sequences(flow.esp_sequences) == (
        "10.0.0.1 -> 10.0.0.2 pkts=5 missing=1 ooo=1 dup=1 gaps=gap=2(x1)"
    )
