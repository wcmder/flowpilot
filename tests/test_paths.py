import flowpilot.paths as paths


def test_runtime_private_dir_uses_current_working_directory_when_not_frozen(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(paths.sys, "frozen", False, raising=False)

    assert paths.runtime_private_dir() == tmp_path / "private"


def test_runtime_private_dir_uses_executable_directory_when_frozen(tmp_path, monkeypatch) -> None:
    exe_path = tmp_path / "FlowPilot" / "flowpilot.exe"
    monkeypatch.setattr(paths.sys, "frozen", True, raising=False)
    monkeypatch.setattr(paths.sys, "executable", str(exe_path))

    assert paths.runtime_private_dir() == exe_path.parent / "private"
