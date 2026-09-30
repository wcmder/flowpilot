import json

import pytest

import flowpilot.cli as cli


def test_report_write_preserves_all_detailed_rows(tmp_path):
    path = tmp_path / "nested" / "capture.json"
    payload = {"summary": {"flows": [{"deep_details": {"deep_esp_flow": {
        "esp_deep_samples": [{"frame.number": str(i), "detail": "é" * 100}
                             for i in range(1, 5002)],
    }}}]}}
    cli._write_json_report(path, payload)
    assert path.stat().st_size > 0
    assert json.loads(path.read_text(encoding="utf-8")) == payload
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("failure", [OSError("disk full"), MemoryError("encoding failed"),
                                     KeyboardInterrupt()])
def test_partial_write_never_creates_or_truncates_destination(
    tmp_path, monkeypatch, existing, failure,
):
    path = tmp_path / "capture.json"
    original = b'{"previous": "complete report"}'
    if existing:
        path.write_bytes(original)

    def interrupted_dump(payload, stream, **kwargs):
        stream.write('{"summary": ')
        stream.flush()
        assert path.read_bytes() == original if existing else not path.exists()
        raise failure

    monkeypatch.setattr(cli.json, "dump", interrupted_dump)
    expected = KeyboardInterrupt if isinstance(failure, KeyboardInterrupt) else RuntimeError
    with pytest.raises(expected):
        cli._write_json_report(path, {"summary": {}})
    if existing:
        assert path.read_bytes() == original
    else:
        assert not path.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_failed_replace_preserves_original_report(tmp_path, monkeypatch):
    path = tmp_path / "capture.json"
    original = b'{"previous": true}'
    path.write_bytes(original)

    def fail_replace(source, destination):
        assert json.loads(source.read_text()) == {"new": True}
        raise PermissionError("destination locked")

    monkeypatch.setattr(cli.os, "replace", fail_replace)
    with pytest.raises(RuntimeError, match="destination was not replaced"):
        cli._write_json_report(path, {"new": True})
    assert path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [path]
