import json

import pytest

from memattest import cli


@pytest.fixture
def memdir(tmp_path, monkeypatch):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "test-pw")
    return d


def run(*args):
    return cli.main(list(args))


def base(d):
    return ["--memory-dir", str(d), "--keystore", "file"]


def test_init_then_verify_clean(memdir, capsys):
    assert run("init", *base(memdir)) == 0
    assert run("verify", *base(memdir)) == 0
    assert "OK" in capsys.readouterr().out


def test_record_and_tamper_flow(memdir, capsys):
    run("init", *base(memdir))
    f = memdir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    assert run("record", *base(memdir), "--path", str(f)) == 0
    f.write_text("tampered", encoding="utf-8")
    assert run("verify", *base(memdir)) == 1
    out = capsys.readouterr().out
    assert "kind=modified" in out and "path=notes.md" in out
    assert "Remediation:" in out


def test_record_derives_memory_dir_from_file_parent(memdir, capsys):
    run("init", *base(memdir))
    f = memdir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    # no --memory-dir: derived from the file's containing folder
    assert run("record", "--keystore", "file", "--path", str(f)) == 0
    assert run("verify", *base(memdir)) == 0


def test_record_without_memory_dir_does_not_walk_up(memdir, capsys):
    run("init", *base(memdir))
    sub = memdir / "sub"
    sub.mkdir()
    f = sub / "note.md"
    f.write_text("x", encoding="utf-8")
    capsys.readouterr()
    rc = run("record", "--keystore", "file", "--path", str(f))
    assert rc == 2
    err = capsys.readouterr().err
    assert "run init" in err and "--memory-dir" in err


def test_record_nonexistent_path_is_operational_error(memdir, capsys):
    run("init", *base(memdir))
    rc = run("record", *base(memdir), "--path", str(memdir / "no-such-file.md"))
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_prove_negative_index_is_operational_error(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    rc = run("prove", *base(memdir), "--index", "-1")
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_prove_out_of_range_index_is_operational_error(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    rc = run("prove", *base(memdir), "--index", "5")
    assert rc == 2
    assert "error:" in capsys.readouterr().err


def test_verify_positional_path_hints_at_memory_dir_flag(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        run("verify", str(memdir))  # forgot --memory-dir
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "unrecognized arguments" in err
    assert "--memory-dir" in err  # the hint names the flag that was missed


def test_verify_uninitialized_is_operational_error(memdir, capsys):
    assert run("verify", *base(memdir)) == 2
    assert "error:" in capsys.readouterr().err


def test_verify_on_wrong_dir_leaves_no_state_behind(memdir, capsys):
    run("verify", *base(memdir))
    # A failed verify must not plant .memattest state in the directory it was
    # (mistakenly) pointed at — stray state dirs mislead memory-dir derivation.
    assert not (memdir / ".memattest").exists()


def test_verify_failure_emits_one_line_stderr_alert(memdir, capsys):
    run("init", *base(memdir))
    (memdir / "MEMORY.md").write_text("tampered", encoding="utf-8")
    capsys.readouterr()
    assert run("verify", *base(memdir)) == 1
    captured = capsys.readouterr()
    assert "PROBLEM" in captured.out  # full report stays on stdout
    # stderr carries a single concise alert for harnesses that only surface
    # stderr of failing hooks (the pre-hook-session-start snippet did this)
    err_lines = [line for line in captured.err.splitlines() if line.strip()]
    assert len(err_lines) == 1
    assert "FAILED" in err_lines[0]


def test_cli_module_import_stays_lightweight():
    # 'hook pre-tool-use' runs on every shell command; importing the cli
    # module must not drag in cryptography (or anything comparably heavy).
    import subprocess
    import sys
    code = "import sys; from memattest import cli; print('cryptography' in sys.modules)"
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"


def test_log_prints_entries_as_json_lines(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    assert run("log", *base(memdir)) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["op"] == "adopt"


def test_prove_inclusion(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    assert run("prove", *base(memdir), "--index", "0") == 0
    proof = json.loads(capsys.readouterr().out)
    assert proof == []  # single-leaf tree has an empty audit path


def test_hook_post_tool_use_records_write(memdir, capsys, monkeypatch):
    run("init", *base(memdir))
    f = memdir / "notes.md"
    f.write_text("from hook", encoding="utf-8")
    payload = json.dumps({"tool_input": {"file_path": str(f)}})
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert run("hook", "post-tool-use", *base(memdir)) == 0
    assert run("verify", *base(memdir)) == 0


def test_hook_ignores_files_outside_memory_dir(memdir, tmp_path, monkeypatch):
    run("init", *base(memdir))
    outside = tmp_path / "elsewhere.md"
    outside.write_text("x", encoding="utf-8")
    payload = json.dumps({"tool_input": {"file_path": str(outside)}})
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert run("hook", "post-tool-use", *base(memdir)) == 0
    assert run("verify", *base(memdir)) == 0  # nothing recorded, still clean


def test_hook_malformed_stdin_is_operational_error(memdir, capsys, monkeypatch):
    run("init", *base(memdir))
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("{ not json"))
    assert run("hook", "post-tool-use", *base(memdir)) == 2
    assert "malformed hook payload" in capsys.readouterr().err


# --- hook session-start: verify wrapped in Claude Code hook JSON ------------
# Claude Code only injects a SessionStart hook's stdout into agent context on
# exit 0, so the tamper report must travel as JSON additionalContext, not as
# a non-zero exit code.


def test_hook_session_start_clean_emits_context_json(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    assert run("hook", "session-start", *base(memdir)) == 0
    out = json.loads(capsys.readouterr().out)
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "SessionStart"
    assert "OK 1 entries verified" in hso["additionalContext"]
    assert "systemMessage" not in out  # quiet on success


def test_hook_session_start_tampered_exits_zero_with_full_report(memdir, capsys):
    run("init", *base(memdir))
    (memdir / "MEMORY.md").write_text("tampered", encoding="utf-8")
    capsys.readouterr()
    assert run("hook", "session-start", *base(memdir)) == 0  # exit 0 or JSON is dropped
    out = json.loads(capsys.readouterr().out)
    context = out["hookSpecificOutput"]["additionalContext"]
    assert "PROBLEM" in context and "kind=modified" in context
    assert "path=MEMORY.md" in context
    assert "Remediation:" in context
    assert "PROBLEM" in out["systemMessage"]  # user sees the report too


def test_hook_session_start_uninitialized_reports_instead_of_failing(memdir, capsys):
    # An operational error (e.g. the whole .memattest dir deleted) must reach
    # the agent as JSON just like a tamper report — exit 2 would drop it.
    assert run("hook", "session-start", *base(memdir)) == 0
    out = json.loads(capsys.readouterr().out)
    context = out["hookSpecificOutput"]["additionalContext"]
    assert "verification could not run" in context
    assert "not initialized" in context
    assert "verification could not run" in out["systemMessage"]


# --- hook pre-tool-use: block agent-initiated adopt ------------------------
# Permission glob rules proved unable to match quoted or path-prefixed adopt
# invocations; this hook inspects the proposed command string instead.


def _pre_tool_use(monkeypatch, tool_name, command):
    import io
    payload = json.dumps({"tool_name": tool_name, "tool_input": {"command": command}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))


def _assert_denied(capsys):
    out = json.loads(capsys.readouterr().out)
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "adopt" in hso["permissionDecisionReason"]


def test_hook_pre_tool_use_denies_bare_adopt(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash", "memattest adopt notes.md --reason r")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied(capsys)


def test_hook_pre_tool_use_denies_quoted_path_prefixed_adopt(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "PowerShell",
                  '& "C:/repo/.venv/Scripts/memattest" adopt notes.md --reason r')
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied(capsys)


def test_hook_pre_tool_use_denies_exe_suffix_adopt(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash",
                  "/c/repo/.venv/Scripts/memattest.exe adopt notes.md --reason r")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied(capsys)


def _pre_tool_use_file(monkeypatch, tool_name, file_path):
    import io
    payload = json.dumps({"tool_name": tool_name, "tool_input": {"file_path": file_path}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))


def _assert_denied_for_settings(capsys):
    out = json.loads(capsys.readouterr().out)
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "settings" in hso["permissionDecisionReason"]


def test_hook_pre_tool_use_denies_write_to_project_settings(memdir, capsys, monkeypatch):
    _pre_tool_use_file(monkeypatch, "Write", "C:/some/project/.claude/settings.json")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied_for_settings(capsys)


def test_hook_pre_tool_use_denies_edit_to_local_settings(memdir, capsys, monkeypatch):
    _pre_tool_use_file(monkeypatch, "Edit", r"C:\some\project\.claude\settings.local.json")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied_for_settings(capsys)


def test_hook_pre_tool_use_denies_shell_write_to_settings(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash", "echo '{}' > ~/.claude/settings.json")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied_for_settings(capsys)


def test_hook_pre_tool_use_denies_hook_disabling_flag(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "PowerShell", "claude config set disableAllHooks true")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied_for_settings(capsys)


def test_hook_pre_tool_use_allows_write_to_ordinary_files(memdir, capsys, monkeypatch):
    _pre_tool_use_file(monkeypatch, "Write", str(memdir / "notes.md"))
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    assert capsys.readouterr().out.strip() == ""


def test_hook_pre_tool_use_allows_edit_of_snippet_template(memdir, capsys, monkeypatch):
    # The template ships as settings-snippet.json under claude_code/ — editing
    # the template itself is normal development, not a trust-surface edit.
    _pre_tool_use_file(monkeypatch, "Edit",
                       "C:/repo/src/memattest/integrations/claude_code/settings-snippet.json")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    assert capsys.readouterr().out.strip() == ""


def test_hook_pre_tool_use_allows_verify(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash", "memattest verify --memory-dir .")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    assert capsys.readouterr().out.strip() == ""  # no decision: normal flow


def test_hook_pre_tool_use_ignores_payload_without_command(memdir, capsys, monkeypatch):
    import io
    payload = json.dumps({"tool_name": "Write", "tool_input": {"file_path": "x.md"}})
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    assert capsys.readouterr().out.strip() == ""


def test_hook_pre_tool_use_malformed_stdin_is_operational_error(memdir, capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("{ not json"))
    assert run("hook", "pre-tool-use", *base(memdir)) == 2
    assert "malformed hook payload" in capsys.readouterr().err


# --- verify --no-key-check and the signing-key cross-check ------------------


def test_verify_reports_key_missing_when_keystore_entry_deleted(memdir, capsys):
    run("init", *base(memdir))
    (memdir / ".memattest" / "key.sealed").unlink()  # FileKeyStore backing file
    capsys.readouterr()
    assert run("verify", *base(memdir)) == 1
    out = capsys.readouterr().out
    assert "kind=key-missing" in out


def test_verify_wrong_passphrase_is_operational_error_naming_the_flag(memdir, capsys, monkeypatch):
    run("init", *base(memdir))
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "wrong")
    capsys.readouterr()
    assert run("verify", *base(memdir)) == 2
    assert "--no-key-check" in capsys.readouterr().err


def test_verify_no_key_check_skips_cross_check(memdir, capsys):
    run("init", *base(memdir))
    (memdir / ".memattest" / "key.sealed").unlink()
    capsys.readouterr()
    assert run("verify", *base(memdir), "--no-key-check") == 0
    assert "OK" in capsys.readouterr().out


def test_verify_no_key_check_works_without_passphrase(memdir, capsys, monkeypatch):
    # Audit of a copied log: no MEMATTEST_PASSPHRASE on the auditing machine.
    run("init", *base(memdir))
    monkeypatch.delenv("MEMATTEST_PASSPHRASE")
    capsys.readouterr()
    assert run("verify", *base(memdir), "--no-key-check") == 0
    assert "OK" in capsys.readouterr().out


def test_hook_session_start_key_missing_reaches_agent_and_user(memdir, capsys):
    run("init", *base(memdir))
    (memdir / ".memattest" / "key.sealed").unlink()
    capsys.readouterr()
    assert run("hook", "session-start", *base(memdir)) == 0
    out = json.loads(capsys.readouterr().out)
    assert "kind=key-missing" in out["hookSpecificOutput"]["additionalContext"]
    assert "kind=key-missing" in out["systemMessage"]
