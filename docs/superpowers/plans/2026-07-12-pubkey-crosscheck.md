# Keystore-Sealed Pubkey Cross-Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** At verify time, re-derive the public key from the backend-keystore-held signing seed and cross-check it against `.memattest/pubkey.ed25519`, so a replaced disk pubkey is reported as `key-mismatch` and a deleted keystore entry as `key-missing` (both exit 1), with `--no-key-check` as the explicit opt-out for auditing copied logs.

**Architecture:** No new persistent state and no entry/STH format change (no scheme bump). One new exception type (`KeyNotFoundError`) lets verify distinguish "backend keystore answered: no such key" (evidence-grade problem) from "backend keystore unreachable" (operational error, exit 2). On mismatch, the derived key replaces the disk pubkey as the STH verification key, so a re-signed forged history additionally fails as `bad-signature`.

**Tech Stack:** Python ≥ 3.12, `cryptography` (Ed25519), `keyring`, pytest. Spec: `docs/superpowers/specs/2026-07-12-pubkey-crosscheck-design.md`.

## Global Constraints

- **venv only** — every `pip`, `pytest`, and `memattest` invocation uses `.venv\Scripts\...` (Windows dev machine). Never touch the global interpreter.
- Runtime deps stay exactly `cryptography>=42`, `keyring>=24`, `psutil>=5.9`; dev dep `pytest>=8`. No new dependencies.
- Exit codes: `0` clean · `1` tamper detected · `2` operational error · `3` unknown scheme version. `key-mismatch` and `key-missing` are new problem kinds under exit 1; the code set gains no values.
- Entry `scheme` stays `"v1"`; this feature changes no on-disk format and never rehashes or rewrites existing entries/STHs.
- The hot `hook pre-tool-use` path must keep importing nothing heavy: all changes to `cli.py` stay inside functions or argparse wiring; `tests/test_cli.py::test_cli_module_import_stays_lightweight` must keep passing.
- Wording, everywhere (docs, docstrings, messages, commits): say "backend keystore", never bare "backend"; never use the word "dogfood" or variants; no contrastive-reframe constructions ("X isn't just Y", "more than just", "goes beyond") in public-facing text.
- Commit messages: subject + body only, **no attribution/Co-Authored-By lines**.
- Shell commands and commit messages must not contain the literal phrase `memattest adopt`, paths shaped like `.claude/settings*.json`, or the hook-disabling flag name — the live PreToolUse guard on this machine denies them.

## File Structure

- `src/memattest/errors.py` — add `KeyNotFoundError(KeyStoreError)` (Task 1).
- `src/memattest/identity.py` — both backend keystores raise `KeyNotFoundError` for a not-found lookup (Task 1).
- `src/memattest/core.py` — `MemAttest.verify(key_check: bool = True)` gains the cross-check (Task 2).
- `src/memattest/cli.py` — `verify --no-key-check`, passphrase gate relaxation, help-text touch-up (Task 3).
- `tests/test_identity.py`, `tests/test_verify_attacks.py`, `tests/test_cli.py` — new tests per task.
- `README.md`, `docs/superpowers/specs/2026-07-06-memattest-design.md`, `docs/superpowers/plans/2026-07-06-memattest.md` — documentation updates (Task 4).

---

### Task 1: `KeyNotFoundError` and backend-keystore not-found typing

**Files:**
- Modify: `src/memattest/errors.py`
- Modify: `src/memattest/identity.py:40-48` (KeyringKeyStore.unseal), `src/memattest/identity.py:82-96` (FileKeyStore.unseal)
- Test: `tests/test_identity.py`

**Interfaces:**
- Consumes: existing `KeyStoreError` in `memattest.errors`; existing `KeyringKeyStore`/`FileKeyStore` in `memattest.identity`.
- Produces: `class KeyNotFoundError(KeyStoreError)` in `memattest.errors`, raised by both backend keystores' `unseal()` when the lookup succeeds but nothing is stored under that name. Task 2 catches it in `core.verify`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_identity.py`:

```python
# --- KeyNotFoundError: "the backend keystore answered: no such key" ---------
# Verify (spec 2026-07-12) must distinguish a genuinely absent key
# (evidence-grade key-missing problem) from an unreachable backend keystore
# (operational error), so both backend keystores type their not-found case.


def test_keynotfounderror_is_a_keystoreerror():
    from memattest.errors import KeyNotFoundError
    assert issubclass(KeyNotFoundError, KeyStoreError)


def test_keyring_keystore_missing_key_raises_keynotfounderror(monkeypatch):
    import keyring
    from memattest.errors import KeyNotFoundError
    monkeypatch.setattr(keyring, "get_password", lambda service, name: None)
    with pytest.raises(KeyNotFoundError):
        KeyringKeyStore(service="memattest-test").unseal("absent")


def test_file_keystore_missing_file_raises_keynotfounderror(tmp_path):
    from memattest.errors import KeyNotFoundError
    ks = FileKeyStore(tmp_path / "no-such-file.sealed", passphrase=b"pw")
    with pytest.raises(KeyNotFoundError):
        ks.unseal("k1")


def test_file_keystore_absent_name_raises_keynotfounderror(tmp_path):
    from memattest.errors import KeyNotFoundError
    ks = FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw")
    ks.seal("k1", b"\x01" * 32)
    with pytest.raises(KeyNotFoundError):
        ks.unseal("other")


def test_file_keystore_wrong_passphrase_is_not_keynotfound(tmp_path):
    from memattest.errors import KeyNotFoundError
    FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw").seal("k1", b"\x01" * 32)
    with pytest.raises(KeyStoreError) as exc_info:
        FileKeyStore(tmp_path / "key.sealed", passphrase=b"wrong").unseal("k1")
    assert not isinstance(exc_info.value, KeyNotFoundError)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_identity.py -v -k keynotfound`
Expected: FAIL/ERROR with `ImportError: cannot import name 'KeyNotFoundError'`

- [ ] **Step 3: Write the implementation**

`src/memattest/errors.py` — append:

```python
class KeyNotFoundError(KeyStoreError):
    """The backend keystore answered the lookup: nothing stored under that name.

    A statement about the key (evidence-grade), unlike its parent
    KeyStoreError, which covers the unreachable-backend-keystore case
    (operational).
    """
```

`src/memattest/identity.py` — change the import line:

```python
from .errors import KeyNotFoundError, KeyStoreError
```

In `KeyringKeyStore.unseal`, replace:

```python
        if value is None:
            raise KeyStoreError(f"no key named {name!r} in keyring service {self.service!r}")
```

with:

```python
        if value is None:
            raise KeyNotFoundError(f"no key named {name!r} in keyring service {self.service!r}")
```

In `FileKeyStore.unseal`, replace:

```python
        if name not in blobs:
            raise KeyStoreError(f"no key named {name!r} in {self.path}")
```

with:

```python
        if name not in blobs:
            raise KeyNotFoundError(f"no key named {name!r} in {self.path}")
```

(A missing key file already lands here: `_load()` returns `{}` when the file does not exist. Unreadable/corrupted file and wrong-passphrase `InvalidTag` stay plain `KeyStoreError`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_identity.py -v`
Expected: all PASS (including the pre-existing tests — `KeyNotFoundError` is-a `KeyStoreError`, so `test_load_missing_key_raises` and the corruption tests are unaffected).

- [ ] **Step 5: Run the full suite to prove no behavior change**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass (append's fail-closed `except KeyStoreError` handling still catches the subclass).

- [ ] **Step 6: Commit**

```bash
git add src/memattest/errors.py src/memattest/identity.py tests/test_identity.py
git commit -m "Add KeyNotFoundError for backend keystore not-found lookups

Both backend keystores now raise KeyNotFoundError (a KeyStoreError
subclass) when the lookup succeeds but nothing is stored under the
name, so verify can distinguish a genuinely absent signing key from an
unreachable backend keystore. Existing except KeyStoreError handlers,
including append's fail-closed path, are unchanged."
```

---

### Task 2: Cross-check in `MemAttest.verify`

**Files:**
- Modify: `src/memattest/core.py:6-7` (imports), `src/memattest/core.py:111-136` (verify signature + new check)
- Test: `tests/test_verify_attacks.py`

**Interfaces:**
- Consumes: `KeyNotFoundError` (Task 1); existing `Identity.load(keystore, name)` whose `.public_key_bytes` is the derived public key.
- Produces: `MemAttest.verify(key_check: bool = True) -> VerifyReport`; new problem kinds `"key-mismatch"` and `"key-missing"` (both with `path: None`); `MemAttestError` message containing `--no-key-check` when the backend keystore is unreachable. Task 3 maps the CLI flag onto `key_check`.

- [ ] **Step 1: Write the failing tests**

In `tests/test_verify_attacks.py`, first update the test double so it types its not-found case like the real backend keystores. Replace the `MemoryKeyStore` class and its imports:

```python
from memattest.errors import KeyNotFoundError, KeyStoreError, MemAttestError
```

```python
class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyNotFoundError(name)
        return self.data[name]
```

Then append the new tests:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_verify_attacks.py -v`
Expected: the seven new tests FAIL (`verify() got an unexpected keyword argument 'key_check'` / missing problem kinds); all pre-existing tests still PASS.

- [ ] **Step 3: Write the implementation**

`src/memattest/core.py` — change the errors import:

```python
from .errors import KeyNotFoundError, KeyStoreError, MemAttestError
```

Change the verify signature:

```python
    def verify(self, key_check: bool = True) -> VerifyReport:
```

Immediately after the second `raise MemAttestError("not initialized; run init first")` block (the one following the pubkey load) and before the scheme-dispatch comment, insert:

```python
        # Cross-check (spec 2026-07-12): re-derive the public key from the
        # signing seed held in the backend keystore and compare it with the
        # on-disk pubkey. The backend keystore entry is the trust anchor; the
        # disk file is only the claim being checked. On mismatch the derived
        # key takes over as the STH verification key below, so a re-signed
        # forged history also fails as bad-signature instead of verifying
        # against the attacker's planted pubkey.
        if key_check:
            try:
                derived = Identity.load(self.keystore, self.key_name).public_key_bytes
            except KeyNotFoundError:
                problems.append(_problem(
                    "key-missing", None,
                    f"backend keystore has no signing key for {self.key_name!r}; "
                    "the log's authorship cannot be established (accidental key "
                    "loss and a hostile rewrite are indistinguishable) and "
                    "appends will fail — manually review memory contents "
                    "before re-initializing",
                ))
            except KeyStoreError as exc:
                raise MemAttestError(
                    f"keystore unavailable for signing-key cross-check: {exc}; "
                    "pass --no-key-check to verify without it"
                ) from exc
            else:
                if derived != pub:
                    problems.append(_problem(
                        "key-mismatch", None,
                        f"pubkey.ed25519 contains {pub.hex()} but the key "
                        f"derived from the backend keystore is {derived.hex()}; "
                        "the on-disk pubkey was replaced",
                    ))
                    pub = derived
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_verify_attacks.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass. (CLI tests exercise the FileKeyStore path with the correct passphrase, so the now-default cross-check succeeds silently; `test_core.py` doubles hold the key they sealed at init.)

- [ ] **Step 6: Commit**

```bash
git add src/memattest/core.py tests/test_verify_attacks.py
git commit -m "Cross-check disk pubkey against backend keystore in verify

verify(key_check=True) re-derives the public key from the
backend-keystore-held signing seed and compares it with
pubkey.ed25519. A replaced disk pubkey is reported as key-mismatch and
a deleted keystore entry as key-missing (both exit 1); an unreachable
backend keystore is an operational error naming --no-key-check. On
mismatch the derived key becomes the STH verification key, so a
re-signed forged history additionally fails as bad-signature. Runs
before scheme dispatch so key problems survive the exit-3 early
return."
```

---

### Task 3: CLI `--no-key-check` and hook coverage

**Files:**
- Modify: `src/memattest/cli.py:38-50` (`_make_ma`), `src/memattest/cli.py:93-97` (`cmd_verify`), `src/memattest/cli.py:277-279` (verify parser)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `MemAttest.verify(key_check: bool)` (Task 2).
- Produces: `memattest verify --no-key-check`; verify without `MEMATTEST_PASSPHRASE` works under the flag with `--keystore file`. No new flags on any other subcommand; hooks keep the check on.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v -k "key_check or key_missing or wrong_passphrase"`
Expected: the two `--no-key-check` tests FAIL with argparse `SystemExit` (unrecognized argument); the key-missing/wrong-passphrase tests PASS already (Task 2 made the check the default) — they are regression locks for the CLI surface.

- [ ] **Step 3: Write the implementation**

`src/memattest/cli.py` — in `_make_ma`, replace the file-keystore branch:

```python
    if args.keystore == "file":
        passphrase = os.environ.get("MEMATTEST_PASSPHRASE")
        if not passphrase and not getattr(args, "no_key_check", False):
            raise MemAttestError("keystore 'file' requires MEMATTEST_PASSPHRASE to be set")
        # Under --no-key-check the backend keystore is never consulted, so a
        # missing passphrase must not block a copied-log audit.
        ks = FileKeyStore(memory_dir / ".memattest" / "key.sealed",
                          (passphrase or "").encode("utf-8"))
```

Replace `cmd_verify`:

```python
def cmd_verify(args) -> int:
    ma = _make_ma(args)
    report = ma.verify(key_check=not args.no_key_check)
    _print_report(report, ma.store.count())
    return report.exit_code
```

In `main()`, replace the verify parser block:

```python
    p = sub.add_parser("verify", help="run the integrity checks")
    _add_common(p)
    p.add_argument("--no-key-check", action="store_true",
                   help="skip the signing-key cross-check against the backend "
                        "keystore (for auditing a copied log on a machine "
                        "without the key)")
    p.set_defaults(fn=cmd_verify)
```

(The help string previously said "run the three integrity checks"; there are now four. No other parser changes — `init`/`record`/`adopt` need the private key to sign, and the hook subcommands must never skip the check, so none of them get the flag; their handlers call `ma.verify()` with the default.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v`
Expected: all PASS, including `test_cli_module_import_stays_lightweight`.

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/memattest/cli.py tests/test_cli.py
git commit -m "Add verify --no-key-check for auditing copied logs

The signing-key cross-check is on for every verify, including the
session-start hook; the flag is the one deliberate opt-out, for a
copied log on a machine that never had the key (backup restore before
re-init, incident response, third-party or CI audit). Under the flag a
missing MEMATTEST_PASSPHRASE no longer blocks --keystore file, since
the backend keystore is never consulted."
```

---

### Task 4: Documentation updates

**Files:**
- Modify: `README.md` (Keystores section end ~line 248, Hardening list ~line 290, Security limitations "Trust anchor" bullet lines 385-390, Exit codes table lines 402-403)
- Modify: `docs/superpowers/specs/2026-07-06-memattest-design.md` (§2 line 60, §7 lines 161-166, §11 line 205)
- Modify: `docs/superpowers/plans/2026-07-06-memattest.md` (roadmap item 1, lines 2206-2211)

**Interfaces:**
- Consumes: behavior implemented in Tasks 1-3; spec `docs/superpowers/specs/2026-07-12-pubkey-crosscheck-design.md` §6 lists these edits.
- Produces: documentation consistent with shipped behavior. (Note: the design spec's §6 mentions dropping the item from v1-spec §13; §13 never listed it — the roadmap lives in the plan document instead, which is what gets marked done.)

- [ ] **Step 1: README — audit paragraph at the end of the Keystores section**

Append after the paragraph ending "…no longer unseal the original key." (line 248):

```markdown
Every `verify` — including the session-start hook — cross-checks
`pubkey.ed25519` on disk against the public key re-derived from the signing
seed in the backend keystore. To audit a *copied* log on a machine that never
had the key — a restored backup before re-initializing, incident response on
a clean machine, a third-party or CI audit — pass `--no-key-check`:

```bash
memattest verify --memory-dir <COPY_OF_MEMORY_DIR> --no-key-check
```

This skips only the backend-keystore cross-check; signatures, tree
consistency, and file state are still fully verified against the pubkey file
that travels with the log. After restoring a backup onto a new machine,
verify with `--no-key-check` first and re-init only once the report is clean
and you have reviewed the memory contents — re-init adopts whatever is on
disk.
```

- [ ] **Step 2: README — Hardening bullet**

Insert a new bullet in "Hardening your installation" immediately after the "Protect the memattest installation itself." bullet (after line 271):

```markdown
- **The backend keystore is the trust anchor.** `verify` re-derives the
  public key from the keystore-held signing seed and cross-checks the disk
  copy, so your OS credential store (or the `MEMATTEST_PASSPHRASE` for the
  file backend keystore) is part of the trust surface. A `key-missing`
  finding at session start means the keystore entry is gone and the log's
  authorship can no longer be established locally — treat the memory
  contents as untrusted and review them manually before re-initializing.
```

- [ ] **Step 3: README — rewrite the Security limitations "Trust anchor" bullet**

Replace lines 385-390 (`- **Trust anchor.** v1 verification trusts …` through `… root anchoring (v2).`) with:

```markdown
- **Trust anchor.** `verify` re-derives the public key from the signing seed
  in the backend keystore and cross-checks `pubkey.ed25519` on disk, so an
  attacker with write access to the memory directory who swaps the pubkey
  and re-signs history is reported (`key-mismatch`, plus `bad-signature` on
  the forged tree heads), and a deleted keystore entry is reported
  (`key-missing`) at the next session start instead of surfacing later as a
  failed append. A `key-missing` log's authorship cannot be established —
  accidental key loss and a hostile rewrite that also deleted the keystore
  entry are indistinguishable — so review memory contents manually before
  re-adopting them under a new key. Same-user malware can rewrite the
  keystore entry itself and defeat the cross-check; that gap remains until
  the v2 validator service, as does rollback (next bullet). External root
  anchoring (v2) hardens this further.
```

- [ ] **Step 4: README — Exit codes table**

Replace the exit-1 row (line 402):

```markdown
| 1 | Tamper detected — see the printed `PROBLEM` lines for file, hashes, and last-valid entry; includes `key-mismatch` and `key-missing` from the signing-key cross-check |
```

Replace the exit-2 row (line 403):

```markdown
| 2 | Operational error — e.g. not initialized, backend keystore unreachable for the signing-key cross-check (`--no-key-check` skips it when auditing a copied log), malformed hook payload; appends fail closed rather than record an unverifiable entry |
```

- [ ] **Step 5: v1 spec §2 — Trust anchor bullet**

In `docs/superpowers/specs/2026-07-06-memattest-design.md`, replace line 60 with:

```markdown
- **Trust anchor (mitigated 2026-07-12).** v1 verification trusted the public key file stored in `.memattest/`; an attacker with write access to the memory directory could replace it, rewrite history, and re-sign with their own key undetected. The signing-key cross-check (spec 2026-07-12) closes this: verify re-derives the public key from the backend-keystore-held seed and reports `key-mismatch`/`key-missing`. Remaining exposure: same-user malware that rewrites the keystore entry itself (v2 validator service), and rollback (below). External root anchoring (v2) hardens this further.
```

- [ ] **Step 6: v1 spec §7 — verify gains a fourth check**

Replace lines 161-166 (the "**Verify**" paragraph through "…exit codes distinguish…") with:

```markdown
**Verify** (session-start hook, or on demand). Four independent checks, all must pass:
0. **Signing-key cross-check** (added by spec 2026-07-12): re-derive the public key from the signing seed in the backend keystore and compare with `pubkey.ed25519` on disk. A replaced disk pubkey is `key-mismatch`; a missing keystore entry is `key-missing`; on mismatch the derived key becomes the verification key for the checks below. Skippable only with the explicit `--no-key-check` flag (copied-log audit on a machine without the key).
1. **Tree integrity:** recompute the Merkle tree from entries; root must match the latest STH, whose signature must verify against the public key.
2. **History consistency:** every successive STH pair must satisfy an RFC 6962 consistency proof (today's log is an append-only extension of yesterday's — no rewrite, reorder, or truncation).
3. **State conformance:** derive expected current state (latest event per path); diff against actual files. Divergence = out-of-band tampering, reported as *file X, expected hash H₁, found H₂, last valid at entry N (timestamp T)*.

Verification of tree structure and file state requires only the **public** key; the cross-check additionally consults the backend keystore unless `--no-key-check` is passed. The sealed private key is needed only to append/seal. Exit codes distinguish: 0 clean · 1 tamper detected · 2 operational error · 3 unknown scheme version.
```

- [ ] **Step 7: v1 spec §11 — error table row**

Replace the "KeyStore unavailable" row (line 205) with:

```markdown
| KeyStore unavailable (locked keyring, headless without Secret Service) | Verify exits 2: the backend keystore is unreachable for the signing-key cross-check, and only the explicit `--no-key-check` flag (copied-log audit) skips it. Appends fail **closed**: refuse to record unverifiable entries and tell the agent memory recording is paused; exit 2 |
```

- [ ] **Step 8: Mark roadmap item 1 done**

In `docs/superpowers/plans/2026-07-06-memattest.md`, replace the item-1 block (lines 2206-2211) with:

```markdown
1. **Keystore-sealed pubkey cross-check** — **done 2026-07-12**
   (spec `docs/superpowers/specs/2026-07-12-pubkey-crosscheck-design.md`,
   plan `docs/superpowers/plans/2026-07-12-pubkey-crosscheck.md`).
   Verify re-derives the public key from the backend-keystore-held signing
   seed and cross-checks the on-disk `pubkey.ed25519`; divergence is
   `key-mismatch`, a missing keystore entry is `key-missing` (both exit-1
   `PROBLEM`s), and `--no-key-check` is the explicit opt-out for copied-log
   audits.
```

- [ ] **Step 9: Verify docs and commit**

Run: `.venv\Scripts\python -m pytest -q` (docs cannot break code; this is the pre-commit sanity pass)
Expected: all pass.

```bash
git add README.md docs/superpowers/specs/2026-07-06-memattest-design.md docs/superpowers/plans/2026-07-06-memattest.md
git commit -m "Document the signing-key cross-check

Update the README trust-anchor limitation, hardening list, Keystores
audit workflow, and exit-code table; amend the v1 spec (trust-anchor
scope, verify as four checks, error table); mark roadmap item 1 done."
```

---

### Task 5: End-to-end validation on this machine

**Files:** none (validation only; scratch state under `%TEMP%`).

**Interfaces:**
- Consumes: the installed editable package (`.venv\Scripts\memattest`) with Tasks 1-3 merged; the real Windows Credential Manager; the live installation's memory directory.
- Produces: evidence that the shipped behavior matches the spec outside pytest.

- [ ] **Step 1: Scratch-directory lifecycle with the real Credential Manager**

```powershell
$scratch = "$env:TEMP\memattest-e2e"
New-Item -ItemType Directory -Force $scratch | Out-Null
Set-Content -Encoding utf8 "$scratch\note.md" "hello"
.venv\Scripts\memattest init --memory-dir $scratch
.venv\Scripts\memattest verify --memory-dir $scratch
```

Expected: `initialized; adopted 1 pre-existing file(s)`, then `OK 1 entries verified`, exit 0.

- [ ] **Step 2: Delete the credential and observe `key-missing`**

```powershell
.venv\Scripts\python -c "import keyring, pathlib, os; keyring.delete_password('memattest', str((pathlib.Path(os.environ['TEMP']) / 'memattest-e2e').resolve()))"
.venv\Scripts\memattest verify --memory-dir $scratch
```

Expected: `PROBLEM kind=key-missing path=None detail=backend keystore has no signing key…`, one-line `verification FAILED` alert on stderr, exit 1.

- [ ] **Step 3: Confirm the opt-out and clean up**

```powershell
.venv\Scripts\memattest verify --memory-dir $scratch --no-key-check
Remove-Item -Recurse -Force $scratch
```

Expected: `OK 1 entries verified`, exit 0; scratch directory removed. (The orphaned credential was already deleted in Step 2, so no keystore cleanup remains.)

- [ ] **Step 4: Live installation regression check**

```powershell
.venv\Scripts\memattest verify --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory
```

Expected: `OK <n> entries verified`, exit 0 — the live log's seed is already sealed, so the upgrade needs no migration and the cross-check passes silently.

- [ ] **Step 5: Full suite, final**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass. Report results to the user; no commit (nothing changed).
