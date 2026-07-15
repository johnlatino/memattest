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


def test_write_settings_roundtrip_creates_parent(tmp_path):
    f = tmp_path / ".claude" / "settings.json"
    write_settings(f, {"hooks": {}})
    assert json.loads(f.read_text(encoding="utf-8")) == {"hooks": {}}
    assert f.read_text(encoding="utf-8").endswith("\n")
