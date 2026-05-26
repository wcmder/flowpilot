from flowpilot.cli import _format_esp_gap_distribution, _format_esp_gap_events


def test_format_esp_gap_distribution_groups_missing_counts() -> None:
    gaps = [
        {"after_sequence": 1, "next_sequence": 3, "gap": 2, "missing": 1},
        {"after_sequence": 10, "next_sequence": 12, "gap": 2, "missing": 1},
        {"after_sequence": 20, "next_sequence": 23, "gap": 3, "missing": 2},
    ]

    assert _format_esp_gap_distribution(gaps) == "gap=1(x2) gap=2(x1)"


def test_format_esp_gap_distribution_handles_no_gaps() -> None:
    assert _format_esp_gap_distribution([]) == "none"


def test_format_esp_gap_events_lists_all_gaps() -> None:
    gaps = [
        {"after_sequence": 1, "next_sequence": 3, "gap": 2, "missing": 1},
        {"after_sequence": 10, "next_sequence": 13, "gap": 3, "missing": 2},
    ]

    assert _format_esp_gap_events(gaps) == "1->3(missing=1), 10->13(missing=2)"


def test_format_esp_gap_events_handles_no_gaps() -> None:
    assert _format_esp_gap_events([]) == "none"
