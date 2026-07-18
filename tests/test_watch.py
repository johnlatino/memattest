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


def kinds(report):
    return [p["kind"] for p in report.problems]


def _watched(mem, tmp_path):
    external = tmp_path / "watched.md"
    external.write_text("baseline", encoding="utf-8")
    mem.adopt([external], reason="watch it")
    return external


def test_clean_watched_file_verifies(mem, tmp_path):
    _watched(mem, tmp_path)
    r = mem.verify()
    assert r.ok and r.exit_code == 0


def test_modified_watched_file_reported(mem, tmp_path):
    external = _watched(mem, tmp_path)
    external.write_text("tampered", encoding="utf-8")
    r = mem.verify()
    assert not r.ok and r.exit_code == 1
    (p,) = [p for p in r.problems if p["kind"] == "modified"]
    assert p["path"] == external.resolve().as_posix()
    assert "scope=watch" in p["detail"]


def test_deleted_watched_file_reported_missing(mem, tmp_path):
    external = _watched(mem, tmp_path)
    external.unlink()
    r = mem.verify()
    assert "missing" in kinds(r)
    (p,) = [p for p in r.problems if p["kind"] == "missing"]
    assert p["path"] == external.resolve().as_posix()


def test_unreadable_watched_file_is_operational_error(mem, tmp_path, monkeypatch):
    external = _watched(mem, tmp_path)
    import memattest.core as core_mod

    orig_file_content_hash = core_mod.file_content_hash

    def boom(p):
        if Path(p) == external:
            raise PermissionError("locked")
        return orig_file_content_hash(p)

    monkeypatch.setattr(core_mod, "file_content_hash", boom)
    from memattest.errors import MemAttestError
    with pytest.raises(MemAttestError, match="cannot read watched file"):
        mem.verify()


def test_memory_verification_unaffected_by_watch(mem, tmp_path):
    _watched(mem, tmp_path)
    (mem.memory_dir / "MEMORY.md").write_text("changed", encoding="utf-8")
    r = mem.verify()
    mem_mods = [p for p in r.problems if p["kind"] == "modified" and p["path"] == "MEMORY.md"]
    assert len(mem_mods) == 1


def test_unwatch_drops_file_and_clears_missing(mem, tmp_path):
    external = _watched(mem, tmp_path)
    external.unlink()
    assert "missing" in kinds(mem.verify())
    mem.unwatch([external], reason="stopped using it")
    assert external.resolve().as_posix() not in mem.derived_watch_state()
    assert mem.verify().ok


def test_unwatch_unwatched_file_errors(mem, tmp_path):
    from memattest.errors import MemAttestError
    never = tmp_path / "never.md"
    never.write_text("x", encoding="utf-8")
    with pytest.raises(MemAttestError, match="not currently watched"):
        mem.unwatch([never], reason="typo")


def test_legacy_scopeless_log_still_verifies(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    m = MemAttest(d, keystore=MemoryKeyStore())
    m.init()
    # Simulate a pre-feature log: strip scope from the on-disk entry files.
    import json as _json
    for f in m.store.entries_dir.glob("*.json"):
        e = _json.loads(f.read_text(encoding="utf-8"))
        e.pop("scope", None)
        from memattest.canonical import canonical_json
        f.write_bytes(canonical_json(e))
    # Re-seal so the STH matches the scope-less bytes.
    import shutil
    shutil.rmtree(m.sth_chain.sth_dir)
    m._seal_current_tree(m._identity())
    r = m.verify()
    assert r.ok and r.exit_code == 0
    assert "MEMORY.md" in m.derived_state()
