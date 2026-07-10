import io

import pytest

from memattest import cli
from memattest.core import MemAttest
from memattest.identity import KeyStore
from memattest.errors import KeyStoreError


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyStoreError(name)
        return self.data[name]


@pytest.fixture
def mem(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    m = MemAttest(d, keystore=MemoryKeyStore())
    m.init()
    return m


def test_adopt_reconciles_out_of_band_edit(mem):
    f = mem.memory_dir / "MEMORY.md"
    f.write_text("hand-edited on a saturday", encoding="utf-8")
    assert not mem.verify().ok
    mem.adopt([f], reason="my own weekend edit")
    report = mem.verify()
    assert report.ok and report.exit_code == 0


def test_adopt_appends_never_rewrites(mem):
    f = mem.memory_dir / "MEMORY.md"
    original_entry_bytes = (mem.store.entries_dir / "000000.json").read_bytes()
    f.write_text("changed", encoding="utf-8")
    mem.adopt([f], reason="r")
    # The pre-existing entry file is byte-identical; history was extended, not edited.
    assert (mem.store.entries_dir / "000000.json").read_bytes() == original_entry_bytes
    entries = mem.store.load_all()
    assert len(entries) == 2 and entries[1]["op"] == "adopt" and entries[1]["reason"] == "r"
    # The old (contradicted) hash remains visible in history:
    assert entries[0]["content_hash"] != entries[1]["content_hash"]


def test_adopt_records_reason_and_provenance(mem):
    f = mem.memory_dir / "MEMORY.md"
    f.write_text("x", encoding="utf-8")
    (entry,) = mem.adopt([f], reason="because tests")
    assert entry["reason"] == "because tests"
    assert "interactive_tty" in entry["provenance"]["session"]
    assert "parent_chain" in entry["provenance"]["process"]


def test_cli_adopt_refuses_without_tty(tmp_path, monkeypatch):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO("adopt\n")
    fake_stdin.isatty = lambda: False  # simulate piped/non-interactive stdin
    monkeypatch.setattr("sys.stdin", fake_stdin)
    rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    assert rc == 2
    # A refused adopt must leave the log untouched: no entry may have been recorded.
    assert list((d / ".memattest" / "entries").glob("*.json")) == []


def test_cli_adopt_derives_memory_dir_from_file_parent(tmp_path, monkeypatch, capsys):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    (d / "MEMORY.md").write_text("hand-edited", encoding="utf-8")
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)
    monkeypatch.setattr("builtins.input", lambda prompt="": "adopt")
    # no --memory-dir: derived from the file's containing folder
    rc = cli.main(["adopt", str(d / "MEMORY.md"), "--reason", "r", "--keystore", "file"])
    assert rc == 0
    assert cli.main(["verify", "--memory-dir", str(d), "--keystore", "file"]) == 0


def test_cli_adopt_without_memory_dir_does_not_walk_up(tmp_path, monkeypatch, capsys):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    sub = d / "sub"
    sub.mkdir()
    f = sub / "note.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)

    def fail_if_prompted(prompt=""):
        raise AssertionError("confirmation prompt must not be reached")

    monkeypatch.setattr("builtins.input", fail_if_prompted)
    capsys.readouterr()
    # sub/ has no .memattest of its own; the guarded ancestor must NOT be found
    rc = cli.main(["adopt", str(f), "--reason", "r", "--keystore", "file"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "run init" in captured.err and "--memory-dir" in captured.err
    assert "About to adopt" not in captured.out


def test_cli_adopt_paths_in_different_directories_require_explicit_flag(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    dirs = []
    for name in ("a", "b"):
        d = tmp_path / name
        d.mkdir()
        f = d / "note.md"
        f.write_text("x", encoding="utf-8")
        cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
        dirs.append(f)
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)
    capsys.readouterr()
    rc = cli.main(["adopt", str(dirs[0]), str(dirs[1]), "--reason", "r", "--keystore", "file"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "--memory-dir" in captured.err


def test_cli_adopt_uninitialized_fails_before_prompting(tmp_path, monkeypatch, capsys):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)

    def fail_if_prompted(prompt=""):
        raise AssertionError("confirmation prompt must not be reached on an uninitialized dir")

    monkeypatch.setattr("builtins.input", fail_if_prompted)
    rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    captured = capsys.readouterr()
    assert rc == 2
    assert "not initialized" in captured.err
    assert "About to adopt" not in captured.out


def test_cli_adopt_eof_at_confirmation_aborts_cleanly(tmp_path, monkeypatch, capsys):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO()  # isatty True but no input: input() raises EOFError
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)
    rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    assert rc == 2
    assert "aborted" in capsys.readouterr().err
    assert list((d / ".memattest" / "entries").glob("*.json")) == []


def test_cli_adopt_interrupt_at_confirmation_aborts_cleanly(tmp_path, monkeypatch, capsys):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)

    def interrupt(prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", interrupt)
    rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    assert rc == 2
    assert "aborted" in capsys.readouterr().err
    assert list((d / ".memattest" / "entries").glob("*.json")) == []


def test_cli_adopt_requires_typed_confirmation(tmp_path, monkeypatch):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    assert rc == 2
    # A refused adopt must leave the log untouched: no entry may have been recorded.
    assert list((d / ".memattest" / "entries").glob("*.json")) == []
