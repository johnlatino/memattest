import json
from pathlib import Path

import pytest

from memattest.canonical import canonical_json
from memattest.core import MemAttest
from memattest.identity import Identity, KeyStore
from memattest.errors import KeyStoreError
from memattest.seal import build_sth
from memattest import merkle


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
    for name, text in [("a.md", "alpha"), ("b.md", "beta"), ("c.md", "gamma")]:
        f = d / name
        f.write_text(text, encoding="utf-8")
        m.record(f)
    return m


def entry_files(m):
    return sorted(m.store.entries_dir.glob("*.json"))


def kinds(report):
    return [p["kind"] for p in report.problems]


def test_clean_history_verifies(mem):
    r = mem.verify()
    assert r.ok and r.exit_code == 0 and r.problems == []


def test_bitflip_guarded_file_detected(mem):
    (mem.memory_dir / "b.md").write_text("Beta", encoding="utf-8")
    r = mem.verify()
    assert not r.ok and r.exit_code == 1
    (p,) = r.problems
    assert p["kind"] == "modified" and p["path"] == "b.md"
    assert p["last_valid_index"] == 2  # b.md was recorded at entry index 2


def test_delete_guarded_file_detected(mem):
    (mem.memory_dir / "c.md").unlink()
    r = mem.verify()
    assert kinds(r) == ["missing"] and r.problems[0]["path"] == "c.md"


def test_unlogged_file_detected(mem):
    (mem.memory_dir / "planted.md").write_text("evil", encoding="utf-8")
    r = mem.verify()
    assert kinds(r) == ["unlogged"] and r.problems[0]["path"] == "planted.md"


def test_reorder_entries_detected(mem):
    files = entry_files(mem)
    e1, e2 = json.loads(files[1].read_text()), json.loads(files[2].read_text())
    e1["index"], e2["index"] = 2, 1  # swap positions in the sequence
    files[1].write_bytes(canonical_json(e2))
    files[2].write_bytes(canonical_json(e1))
    r = mem.verify()
    assert not r.ok and "root-mismatch" in kinds(r)


def test_replace_entry_wholesale_detected(mem):
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["content_hash"] = "sha256:" + "00" * 32
    f.write_bytes(canonical_json(e))
    assert "root-mismatch" in kinds(mem.verify())


def test_backdate_timestamp_detected(mem):
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["timestamp"] = "2020-01-01T00:00:00Z"
    f.write_bytes(canonical_json(e))
    assert "root-mismatch" in kinds(mem.verify())


def test_truncate_log_detected(mem):
    entry_files(mem)[-1].unlink()
    r = mem.verify()
    assert not r.ok and "log-truncated" in kinds(r)


def test_forged_sth_without_key_detected(mem):
    # Attacker rewrites an entry AND recomputes a matching root, but must sign
    # with their own key because they cannot unseal ours.
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["content_hash"] = "sha256:" + "ff" * 32
    f.write_bytes(canonical_json(e))
    attacker = Identity.generate(MemoryKeyStore(), "attacker")
    leaves = mem.store.leaf_bytes()
    forged = build_sth(len(leaves), merkle.root_hash(leaves), attacker)
    sth_files = sorted(mem.sth_chain.sth_dir.glob("*.json"))
    sth_files[-1].write_bytes(canonical_json(forged))
    r = mem.verify()
    assert not r.ok and "bad-signature" in kinds(r)


def test_unknown_scheme_reported_not_guessed(mem):
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["scheme"] = "v99"
    f.write_bytes(canonical_json(e))
    r = mem.verify()
    assert not r.ok and r.exit_code == 3
    assert "unknown-scheme" in kinds(r)
