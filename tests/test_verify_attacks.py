import json
from pathlib import Path

import pytest

from memattest.canonical import canonical_json
from memattest.core import MemAttest
from memattest.identity import Identity, KeyStore
from memattest.errors import KeyNotFoundError, KeyStoreError, MemAttestError
from memattest.seal import build_sth
from memattest import merkle


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyNotFoundError(name)
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
    assert "expected sha256:" in p["detail"]
    assert "found sha256:" in p["detail"]


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


def test_missing_pubkey_is_operational_error_not_tamper(mem):
    mem.pubkey_path.unlink()
    with pytest.raises(MemAttestError, match="cannot load public key"):
        mem.verify()


def test_corrupted_pubkey_is_operational_error_not_tamper(mem):
    mem.pubkey_path.write_text("zz-not-hex", encoding="ascii")
    with pytest.raises(MemAttestError, match="cannot load public key"):
        mem.verify()


# --- signing-key cross-check (spec 2026-07-12) -------------------------------
# The backend keystore entry is the trust anchor; pubkey.ed25519 on disk is
# only the claim being checked.


def test_keystore_entry_deleted_reports_key_missing(mem):
    mem.keystore.data.clear()
    r = mem.verify()
    assert not r.ok and r.exit_code == 1
    assert "key-missing" in kinds(r)
    p = next(p for p in r.problems if p["kind"] == "key-missing")
    assert p["path"] is None
    assert "review" in p["detail"]  # remediation seed: manual review before re-init


def test_key_missing_still_runs_disk_checks(mem):
    mem.keystore.data.clear()
    (mem.memory_dir / "b.md").write_text("Beta", encoding="utf-8")
    r = mem.verify()
    assert "key-missing" in kinds(r) and "modified" in kinds(r)


def test_swapped_pubkey_without_resign_reports_only_key_mismatch(mem):
    other = Identity.generate(MemoryKeyStore(), "other")
    mem.pubkey_path.write_text(other.public_key_bytes.hex(), encoding="ascii")
    r = mem.verify()
    assert not r.ok and r.exit_code == 1
    # Genuine STHs verify against the derived (true) key: exactly one finding.
    assert kinds(r) == ["key-mismatch"]
    assert other.public_key_bytes.hex() in r.problems[0]["detail"]


def test_full_rewrite_attack_detected_by_cross_check(mem):
    # The v1-spec §2 trust-anchor attack: modify a memory file, rewrite its
    # log entry to match, re-sign every STH with the attacker's key, and swap
    # the on-disk pubkey to the attacker's.
    from memattest.entry import file_content_hash
    target = mem.memory_dir / "b.md"
    target.write_text("poisoned", encoding="utf-8")
    f = entry_files(mem)[2]  # b.md was recorded at entry index 2
    e = json.loads(f.read_text())
    e["content_hash"] = file_content_hash(target)
    f.write_bytes(canonical_json(e))
    attacker = Identity.generate(MemoryKeyStore(), "attacker")
    leaves = mem.store.leaf_bytes()
    for sth_file in sorted(mem.sth_chain.sth_dir.glob("*.json")):
        size = json.loads(sth_file.read_text())["tree_size"]
        sth_file.write_bytes(canonical_json(
            build_sth(size, merkle.root_hash(leaves[:size]), attacker)))
    mem.pubkey_path.write_text(attacker.public_key_bytes.hex(), encoding="ascii")

    # Premise check: skipping the cross-check is the pre-feature behavior,
    # under which this attack verifies cleanly.
    assert mem.verify(key_check=False).ok

    r = mem.verify()
    assert not r.ok and r.exit_code == 1
    assert "key-mismatch" in kinds(r)
    assert "bad-signature" in kinds(r)  # forged STHs fail against the derived key


def test_unreachable_keystore_is_operational_error_naming_the_flag(mem):
    class UnreachableKeyStore(KeyStore):
        def seal(self, name, secret):
            raise KeyStoreError("backend keystore unavailable")

        def unseal(self, name):
            raise KeyStoreError("backend keystore unavailable")

    mem.keystore = UnreachableKeyStore()
    with pytest.raises(MemAttestError, match="no-key-check"):
        mem.verify()
    assert mem.verify(key_check=False).ok


def test_key_check_false_never_touches_keystore(mem):
    class ExplodingKeyStore(KeyStore):
        def seal(self, name, secret):
            raise AssertionError("backend keystore touched")

        def unseal(self, name):
            raise AssertionError("backend keystore touched")

    mem.keystore = ExplodingKeyStore()
    assert mem.verify(key_check=False).ok


def test_unknown_scheme_early_return_includes_key_missing(mem):
    mem.keystore.data.clear()
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["scheme"] = "v99"
    f.write_bytes(canonical_json(e))
    r = mem.verify()
    assert r.exit_code == 3  # unknown scheme still wins the exit code
    assert "unknown-scheme" in kinds(r) and "key-missing" in kinds(r)
