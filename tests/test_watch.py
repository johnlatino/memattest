from pathlib import Path

import pytest

from memattest.core import MemAttest
from memattest.entry import build_entry, file_content_hash
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


def test_build_entry_defaults_scope_memory():
    e = build_entry(0, "adopt", "MEMORY.md", "sha256:x", {}, scope="memory")
    assert e["scope"] == "memory"


def test_build_entry_rejects_unknown_scope():
    with pytest.raises(ValueError, match="unknown scope"):
        build_entry(0, "adopt", "x", None, {}, scope="bogus")


def test_memory_entries_carry_scope_memory(mem):
    entries = mem.store.load_all()
    assert entries and all(e["scope"] == "memory" for e in entries)


def test_adopt_external_path_creates_watch_entry(mem, tmp_path):
    external = tmp_path / "outside" / "CLAUDE.md"
    external.parent.mkdir()
    external.write_text("instructions", encoding="utf-8")
    (entry,) = mem.adopt([external], reason="watch it")
    assert entry["scope"] == "watch"
    assert entry["path"] == external.resolve().as_posix()
    assert entry["content_hash"] == file_content_hash(external)


def test_derived_state_excludes_watch_entries(mem, tmp_path):
    external = tmp_path / "outside.md"
    external.write_text("x", encoding="utf-8")
    mem.adopt([external], reason="watch it")
    state = mem.derived_state()
    assert external.resolve().as_posix() not in state
    assert "MEMORY.md" in state


def test_adopt_memory_path_still_memory_scope(mem):
    f = mem.memory_dir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    (entry,) = mem.adopt([f], reason="memory adopt")
    assert entry["scope"] == "memory" and entry["path"] == "notes.md"
