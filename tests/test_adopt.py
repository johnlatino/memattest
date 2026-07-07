import io
import json

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
