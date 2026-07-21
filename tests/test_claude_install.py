import json
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from memattest.errors import MemAttestError
from memattest.integrations.claude_code.install import (
    derive_memory_dir,
    load_filled_template,
    plan_merge,
    project_slug,
    read_settings,
    write_settings,
)


# --- slug derivation (Claude Code convention: non [A-Za-z0-9-] -> dash) ------
# Pinned against the observed real slug on this machine:
# C:\source\agentmemoryvalidation -> C--source-agentmemoryvalidation


def test_project_slug_windows_drive_path():
    assert project_slug(PureWindowsPath(r"C:\source\agentmemoryvalidation")) == \
        "C--source-agentmemoryvalidation"


def test_project_slug_posix_path():
    assert project_slug(PurePosixPath("/home/user/proj")) == "-home-user-proj"


def test_project_slug_dots_and_underscores_become_dashes():
    assert project_slug(PureWindowsPath(r"C:\repos\my.app_v2")) == "C--repos-my-app-v2"


def test_derive_memory_dir_lands_under_claude_projects(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    project = tmp_path / "proj"
    project.mkdir()
    derived = derive_memory_dir(project)
    assert derived == tmp_path / ".claude" / "projects" / project_slug(project.resolve()) / "memory"


# --- template fill ------------------------------------------------------------


def test_load_filled_template_fills_and_strips_comment(tmp_path):
    data = load_filled_template(Path("C:/repo/.venv/Scripts/memattest.exe"),
                                Path("C:/users/me/.claude/projects/x/memory"))
    assert "//" not in data
    assert set(data["hooks"]) == {"SessionStart", "PreToolUse", "PostToolUse"}
    for groups in data["hooks"].values():
        command = groups[0]["hooks"][0]["command"]
        assert "C:/repo/.venv/Scripts/memattest.exe" in command
        assert "C:/users/me/.claude/projects/x/memory" in command
        assert "<" not in command  # no placeholder survived
    assert any("adopt" in rule for rule in data["permissions"]["deny"])


# --- merge semantics -----------------------------------------------------------


def _template():
    def cmd(sub):
        return {"type": "command",
                "command": f"C:/bin/memattest hook {sub} --memory-dir C:/mem"}
    return {
        "hooks": {
            "SessionStart": [{"hooks": [cmd("session-start")]}],
            "PreToolUse": [{"matcher": "Bash|PowerShell|Write|Edit",
                            "hooks": [cmd("pre-tool-use")]}],
            "PostToolUse": [{"matcher": "Write|Edit", "hooks": [cmd("post-tool-use")]}],
        },
        "permissions": {"deny": ["rule-a", "rule-b"]},
    }


def test_plan_merge_into_empty_settings_adds_everything():
    merged, actions = plan_merge({}, _template())
    assert merged["hooks"] == _template()["hooks"]
    assert merged["permissions"]["deny"] == ["rule-a", "rule-b"]
    assert actions["SessionStart"] == "added"
    assert actions["deny rules"] == "2 added"


def test_plan_merge_preserves_unrelated_entries():
    existing = {
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "other-tool --greet"}]}]},
        "permissions": {"deny": ["Bash(rm -rf *)"], "allow": ["Bash(ls*)"]},
        "model": "opus",
    }
    merged, actions = plan_merge(existing, _template())
    session_cmds = [h["command"] for g in merged["hooks"]["SessionStart"] for h in g["hooks"]]
    assert "other-tool --greet" in session_cmds  # untouched
    assert any("session-start" in c for c in session_cmds)  # ours appended
    assert "Bash(rm -rf *)" in merged["permissions"]["deny"]
    assert merged["permissions"]["allow"] == ["Bash(ls*)"]
    assert merged["model"] == "opus"
    assert actions["SessionStart"] == "added"


def test_plan_merge_updates_stale_memattest_command_in_place():
    stale = _template()
    stale["hooks"]["SessionStart"][0]["hooks"][0]["command"] = \
        "D:/old-venv/Scripts/memattest hook session-start --memory-dir D:/old"
    merged, actions = plan_merge(stale, _template())
    cmds = [h["command"] for g in merged["hooks"]["SessionStart"] for h in g["hooks"]]
    assert cmds == ["C:/bin/memattest hook session-start --memory-dir C:/mem"]
    assert actions["SessionStart"] == "updated"


def test_plan_merge_is_idempotent():
    merged1, _ = plan_merge({}, _template())
    merged2, actions = plan_merge(merged1, _template())
    assert merged2 == merged1
    assert actions["SessionStart"] == "unchanged"
    assert actions["deny rules"] == "unchanged"


# --- settings I/O ---------------------------------------------------------------


def test_read_settings_absent_file_is_empty(tmp_path):
    assert read_settings(tmp_path / "settings.json") == {}


def test_read_settings_unparseable_is_operational_error(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text("{ not json", encoding="utf-8")
    with pytest.raises(MemAttestError, match="settings.json"):
        read_settings(f)


def test_read_settings_non_object_is_operational_error(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text('["a list"]', encoding="utf-8")
    with pytest.raises(MemAttestError, match="JSON object"):
        read_settings(f)


@pytest.mark.parametrize("bad", [
    {"hooks": []},
    {"hooks": "x"},
    {"hooks": {"SessionStart": "x"}},
    {"hooks": {"SessionStart": ["x"]}},
    {"hooks": {"SessionStart": [{"hooks": "x"}]}},
    {"permissions": []},
    {"permissions": {"deny": "x"}},
])
def test_plan_merge_rejects_malformed_shapes(bad):
    with pytest.raises(MemAttestError, match="unexpected shape"):
        plan_merge(bad, _template())


def test_write_settings_roundtrip_creates_parent(tmp_path):
    f = tmp_path / ".claude" / "settings.json"
    write_settings(f, {"hooks": {}})
    assert json.loads(f.read_text(encoding="utf-8")) == {"hooks": {}}
    assert f.read_text(encoding="utf-8").endswith("\n")


# --- ceremony (CLI-level, adopt-test style) -----------------------------------

import io

from memattest import cli


def _tty_stdin(monkeypatch, answers):
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))


def _project_and_memory(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    mem = tmp_path / "memory"
    mem.mkdir()
    (mem / "MEMORY.md").write_text("index", encoding="utf-8")
    return project, mem


def test_install_refuses_without_tty(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    fake = io.StringIO()
    fake.isatty = lambda: False
    monkeypatch.setattr("sys.stdin", fake)
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert not (project / ".claude").exists()


def test_install_eof_at_choice_aborts_cleanly(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)  # input() raises EOFError
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 2
    assert "aborted" in capsys.readouterr().err
    assert not (project / ".claude").exists()


def test_install_full_drive_through(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["1", "install"])
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "initialized; adopted 1 pre-existing file(s)" in out
    assert "OK 2 entries verified" in out
    assert "next Claude Code session" in out
    settings = json.loads(
        (project / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert "//" not in settings
    cmds = [h["command"]
            for groups in settings["hooks"].values()
            for g in groups for h in g["hooks"]]
    assert len(cmds) == 3
    assert all(mem.resolve().as_posix() in c for c in cmds)
    assert any("session-start" in c for c in cmds)
    assert any("adopt" in r for r in settings["permissions"]["deny"])


def test_install_local_choice_writes_local_file(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["2", "install"])
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 0
    assert (project / ".claude" / "settings.local.json").exists()
    assert not (project / ".claude" / "settings.json").exists()


def test_install_rerun_is_idempotent(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["1", "install"])
    assert cli.main(["install", "--project", str(project),
                     "--memory-dir", str(mem), "--keystore", "file"]) == 0
    first = (project / ".claude" / "settings.json").read_text(encoding="utf-8")
    _tty_stdin(monkeypatch, ["1", "install"])
    capsys.readouterr()
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "already initialized" in out
    assert (project / ".claude" / "settings.json").read_text(encoding="utf-8") == first


def test_install_nonexistent_project_is_operational_error(tmp_path, monkeypatch, capsys):
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)
    rc = cli.main(["install", "--project", str(tmp_path / "no-such-dir")])
    assert rc == 2
    # "project directory" discriminates the project check from the
    # derived-memory-dir error, which also says "does not exist".
    assert "project directory" in capsys.readouterr().err


def test_install_plan_flags_absent_given_memory_dir(tmp_path, monkeypatch, capsys):
    project = tmp_path / "proj"
    project.mkdir()
    absent = tmp_path / "not-yet"
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["1", "install"])
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(absent), "--keystore", "file"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "does not exist yet; init will create it" in out
    assert "initialized; adopted 0 pre-existing file(s)" in out


def test_install_watches_the_settings_file(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["1", "install"])
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 0
    from memattest.core import MemAttest
    from memattest.identity import FileKeyStore
    ma = MemAttest(mem, keystore=FileKeyStore(mem / ".memattest" / "key.sealed", b"pw"))
    watched = ma.derived_watch_state()
    target = (project / ".claude" / "settings.json").resolve().as_posix()
    assert target in watched


def test_install_does_not_watch_local_settings(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["2", "install"])  # choice 2 = local
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "settings.local.json" in out
    assert "not watched" in out  # the skip note
    from memattest.core import MemAttest
    from memattest.identity import FileKeyStore
    ma = MemAttest(mem, keystore=FileKeyStore(mem / ".memattest" / "key.sealed", b"pw"))
    target = (project / ".claude" / "settings.local.json").resolve().as_posix()
    assert target not in ma.derived_watch_state()


def test_install_derived_memory_dir_missing_is_operational_error(tmp_path, monkeypatch, capsys):
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "fakehome"))
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)

    def fail_if_prompted(prompt=""):
        raise AssertionError("no prompt may be reached when derivation fails")

    monkeypatch.setattr("builtins.input", fail_if_prompted)
    rc = cli.main(["install", "--project", str(project)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--memory-dir" in err and "does not exist" in err
