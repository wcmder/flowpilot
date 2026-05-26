from flowpilot.reasoning import _json_object


def test_json_object_extracts_wrapped_json() -> None:
    assert _json_object('Here is the report: {"risk_level": "low"}') == {"risk_level": "low"}
