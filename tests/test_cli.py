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


def test_verify_uninitialized_is_operational_error(memdir, capsys):
    assert run("verify", *base(memdir)) == 2
    assert "error:" in capsys.readouterr().err


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
