# Per-Log Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `init` records the backend keystore in `.memattest/config.toml`; the config is authoritative for later commands (no `--keystore` flag needed, a contradicting flag is exit 2), and pre-feature logs auto-migrate on their next successful append.

**Architecture:** One new light module (`per_log_config.py`, stdlib `tomllib` reader + template-string writer), a `config_name` class attribute on the `KeyStore` ABC so core can record proven backend names, auto-create hooks in `init`/`record`/`adopt`, and config-aware resolution in the CLI's `_make_ma` funnel. No cryptographic protection in this item (spec §6 carries the fail-noisy analysis; sealing arrives with the watch list). Every config problem is an operational error (exit 2), never a tamper finding.

**Tech Stack:** Python ≥ 3.12 (`tomllib` is stdlib), pytest. Spec: `docs/superpowers/specs/2026-07-13-per-log-config-design.md`.

## Global Constraints

- **venv only** — every `pip`, `pytest`, and `memattest` invocation uses `.venv\Scripts\...` (Windows dev machine). Never touch the global interpreter.
- Runtime deps stay exactly `cryptography>=42`, `keyring>=24`, `psutil>=5.9`; dev dep `pytest>=8`. `tomllib` is stdlib — no new dependencies.
- Exit codes: `0` clean · `1` tamper detected · `2` operational error · `3` unknown scheme version. All config problems are exit 2; no new problem kinds.
- Entry `scheme` stays `"v1"`; no on-disk log format changes. The only new file is `.memattest/config.toml` with `config_version = 1`.
- `verify` stays strictly read-only — it never creates or rewrites the config (the no-stray-state guarantee stays under test).
- The hot `hook pre-tool-use` path must keep importing nothing heavy; `per_log_config` is imported lazily inside `_make_ma`; `tests/test_cli.py::test_cli_module_import_stays_lightweight` must keep passing.
- Wording, everywhere (docs, docstrings, messages, commits): say "backend keystore", never bare "backend"; say "self-testing" or "testing the tool on its own repository" for the practice of running memattest on this repo's own memory — the informal industry term for that practice is banned in all its variants; no contrastive-reframe constructions ("X isn't just Y", "more than just", "goes beyond") in public-facing text.
- Commit messages: subject + body only, **no attribution/Co-Authored-By lines**.
- Shell commands and commit messages must not contain the literal phrase `memattest adopt`, paths shaped like `.claude/settings*.json`, or the hook-disabling flag name — the live PreToolUse guard on this machine denies them.

## File Structure

- `src/memattest/per_log_config.py` — new: `load_config` / `write_config` (Task 1).
- `src/memattest/identity.py` — `KeyStore.config_name` class attribute; both backend keystores name themselves (Task 2).
- `src/memattest/core.py` — init writes the config; record/adopt auto-create it (Task 2).
- `src/memattest/cli.py` — config-aware backend-keystore resolution in `_make_ma`; `--keystore` default becomes `None` (Task 3).
- `tests/test_per_log_config.py` (new), `tests/test_core.py`, `tests/test_cli.py` — tests per task.
- `README.md`, `docs/superpowers/specs/2026-07-06-memattest-design.md`, `docs/superpowers/plans/2026-07-06-memattest.md` — documentation (Task 4).

---

### Task 1: `per_log_config` module

**Files:**
- Create: `src/memattest/per_log_config.py`
- Test: `tests/test_per_log_config.py` (new)

**Interfaces:**
- Consumes: `MemAttestError` from `memattest.errors`.
- Produces (module `memattest.per_log_config`): `CONFIG_NAME = "config.toml"`, `CONFIG_VERSION = 1`, `KNOWN_KEYSTORES = ("keyring", "file")`, `load_config(state_dir: Path) -> dict | None` (None when absent; `MemAttestError` naming the file on any defect), `write_config(state_dir: Path, keystore: str) -> None`. Tasks 2 and 3 call both.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_per_log_config.py`:

```python
import pytest

from memattest.errors import MemAttestError
from memattest.per_log_config import CONFIG_VERSION, load_config, write_config


def test_write_then_load_roundtrip(tmp_path):
    write_config(tmp_path, "keyring")
    assert load_config(tmp_path) == {"config_version": CONFIG_VERSION, "keystore": "keyring"}


def test_absent_config_returns_none(tmp_path):
    assert load_config(tmp_path) is None


def test_unparseable_toml_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text("keystore = [unclosed", encoding="utf-8")
    with pytest.raises(MemAttestError, match="config.toml"):
        load_config(tmp_path)


def test_missing_keystore_key_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text("config_version = 1\n", encoding="utf-8")
    with pytest.raises(MemAttestError, match="backend keystore"):
        load_config(tmp_path)


def test_unknown_key_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text(
        'config_version = 1\nkeystore = "keyring"\ncolor = "red"\n', encoding="utf-8")
    with pytest.raises(MemAttestError, match="unknown keys"):
        load_config(tmp_path)


def test_unknown_keystore_value_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text(
        'config_version = 1\nkeystore = "tpm"\n', encoding="utf-8")
    with pytest.raises(MemAttestError, match="unknown backend keystore"):
        load_config(tmp_path)


def test_unknown_config_version_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text(
        'config_version = 99\nkeystore = "keyring"\n', encoding="utf-8")
    with pytest.raises(MemAttestError, match="newer memattest"):
        load_config(tmp_path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_per_log_config.py -v`
Expected: all ERROR with `ModuleNotFoundError: No module named 'memattest.per_log_config'`

- [ ] **Step 3: Write the implementation**

Create `src/memattest/per_log_config.py`:

```python
"""Per-log configuration stored at .memattest/config.toml (spec 2026-07-13).

Records choices made at init — today only the backend keystore — so later
invocations need no flags. Ships without cryptographic protection: the
signing-key cross-check makes every lie this file can tell fail-noisy
(spec 2026-07-13 §6); sealing arrives with the watch list.

Deliberately light: no heavy imports, safe anywhere in the CLI.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from .errors import MemAttestError

CONFIG_NAME = "config.toml"
CONFIG_VERSION = 1
KNOWN_KEYSTORES = ("keyring", "file")

_TEMPLATE = """\
# memattest per-log configuration
config_version = {version}
keystore = "{keystore}"
"""


def load_config(state_dir: Path) -> dict | None:
    """Return the parsed config, or None when the file is absent.

    Raises MemAttestError (operational, exit 2) naming the file for any
    defect: unparseable TOML, missing or unknown keys, an unknown backend
    keystore name, or an unknown config_version (refuse-to-guess, like the
    entry scheme).
    """
    path = Path(state_dir) / CONFIG_NAME
    if not path.exists():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise MemAttestError(f"unreadable or invalid config {path}: {exc}") from exc
    version = data.get("config_version")
    if version != CONFIG_VERSION:
        raise MemAttestError(
            f"config {path} has config_version {version!r}; this memattest "
            f"understands only {CONFIG_VERSION} (config written by a newer memattest?)"
        )
    unknown = set(data) - {"config_version", "keystore"}
    if unknown:
        raise MemAttestError(f"config {path} has unknown keys: {sorted(unknown)}")
    keystore = data.get("keystore")
    if keystore not in KNOWN_KEYSTORES:
        raise MemAttestError(
            f"config {path} names unknown backend keystore {keystore!r}; "
            f"expected one of {list(KNOWN_KEYSTORES)}"
        )
    return data


def write_config(state_dir: Path, keystore: str) -> None:
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / CONFIG_NAME).write_text(
        _TEMPLATE.format(version=CONFIG_VERSION, keystore=keystore), encoding="utf-8"
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_per_log_config.py -v`
Expected: 7 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/memattest/per_log_config.py tests/test_per_log_config.py
git commit -m "Add per-log config module

Reads and writes .memattest/config.toml (config_version 1, backend
keystore name). Absent file is None; unparseable TOML, missing or
unknown keys, unknown backend keystore names, and unknown
config_version are operational errors naming the file. Reading uses
stdlib tomllib; writing is a template string, so the dependency list
is unchanged."
```

---

### Task 2: Init writes the config; appends auto-migrate pre-feature logs

**Files:**
- Modify: `src/memattest/identity.py:17-24` (KeyStore ABC), `:27-31` (KeyringKeyStore), `:51-56` (FileKeyStore)
- Modify: `src/memattest/core.py` (`init`, `record`, `adopt`; new `_write_config_if_named` helper)
- Test: `tests/test_core.py`

**Interfaces:**
- Consumes: `load_config` / `write_config` (Task 1).
- Produces: `KeyStore.config_name: str | None = None` class attribute; `KeyringKeyStore.config_name = "keyring"`; `FileKeyStore.config_name = "file"`; `MemAttest.init/record/adopt` write the config when absent and the keystore is named. Task 3's resolution relies on init/append having written it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_core.py`:

```python
# --- per-log config auto-creation (spec 2026-07-13 §7) -----------------------
# Only backend keystores that name themselves (config_name) are recorded;
# unnamed test doubles never plant a config the CLI could not resolve.


class NamedKeyStore(MemoryKeyStore):
    config_name = "keyring"


def named_mem(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    return MemAttest(d, keystore=NamedKeyStore())


def test_init_writes_config_for_named_keystore(tmp_path):
    from memattest.per_log_config import load_config
    m = named_mem(tmp_path)
    m.init()
    assert load_config(m.state_dir) == {"config_version": 1, "keystore": "keyring"}


def test_init_with_unnamed_keystore_writes_no_config(mem):
    mem.init()
    assert not (mem.state_dir / "config.toml").exists()


def test_first_record_auto_creates_config(tmp_path):
    from memattest.per_log_config import load_config
    m = named_mem(tmp_path)
    m.init()
    (m.state_dir / "config.toml").unlink()  # simulate a pre-feature log
    f = m.memory_dir / "notes.md"
    f.write_text("x", encoding="utf-8")
    m.record(f)
    assert load_config(m.state_dir) == {"config_version": 1, "keystore": "keyring"}


def test_first_adopt_auto_creates_config(tmp_path):
    from memattest.per_log_config import load_config
    m = named_mem(tmp_path)
    m.init()
    (m.state_dir / "config.toml").unlink()
    f = m.memory_dir / "notes.md"
    f.write_text("x", encoding="utf-8")
    m.adopt([f], reason="test reconcile")
    assert load_config(m.state_dir) == {"config_version": 1, "keystore": "keyring"}


def test_append_does_not_rewrite_existing_config(tmp_path):
    m = named_mem(tmp_path)
    m.init()
    (m.state_dir / "config.toml").write_text(
        '# custom marker\nconfig_version = 1\nkeystore = "keyring"\n', encoding="utf-8")
    f = m.memory_dir / "notes.md"
    f.write_text("x", encoding="utf-8")
    m.record(f)
    assert "# custom marker" in (m.state_dir / "config.toml").read_text(encoding="utf-8")


def test_verify_never_writes_config(tmp_path):
    m = named_mem(tmp_path)
    m.init()
    (m.state_dir / "config.toml").unlink()
    m.verify()
    assert not (m.state_dir / "config.toml").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_core.py -v -k config`
Expected: the four positive tests FAIL (no config written); the two negative tests (`unnamed`, `verify_never`) PASS already — they are regression locks.

- [ ] **Step 3: Write the implementation**

`src/memattest/identity.py` — the `KeyStore` ABC gains a class attribute:

```python
class KeyStore(ABC):
    """seal/unseal named secrets. Backends decide where and how they are protected."""

    # Canonical name recorded in the per-log config (spec 2026-07-13 §7).
    # None (e.g. in-memory test doubles) opts out of config auto-creation, so
    # nothing ever records a backend keystore the CLI cannot resolve.
    config_name: str | None = None

    @abstractmethod
    def seal(self, name: str, secret: bytes) -> None: ...

    @abstractmethod
    def unseal(self, name: str) -> bytes: ...
```

`KeyringKeyStore` — add as the first line of the class body, before `__init__`:

```python
    config_name = "keyring"
```

`FileKeyStore` — add as the first line of the class body, before `__init__`:

```python
    config_name = "file"
```

`src/memattest/core.py` — add the import:

```python
from . import merkle, per_log_config, provenance
```

Add the helper method to `MemAttest` (after `_identity`):

```python
    def _write_config_if_named(self) -> None:
        # Called only after the backend keystore has demonstrably held the
        # signing key (init just sealed it; record/adopt just unsealed it),
        # so the recorded name is proven, not guessed (spec 2026-07-13 §7).
        if self.keystore.config_name is None:
            return
        if per_log_config.load_config(self.state_dir) is None:
            per_log_config.write_config(self.state_dir, self.keystore.config_name)
```

In `init()`, after `self.pubkey_path.write_text(...)`:

```python
        self._write_config_if_named()
```

In `record()`, after `identity = self._identity()`:

```python
        self._write_config_if_named()
```

In `adopt()`, after `identity = self._identity()`:

```python
        self._write_config_if_named()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_core.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass (CLI tests pass explicit `--keystore file`, which init now also records — resolution is unchanged until Task 3).

- [ ] **Step 6: Commit**

```bash
git add src/memattest/identity.py src/memattest/core.py tests/test_core.py
git commit -m "Write the per-log config at init and on first append

Backend keystores name themselves via KeyStore.config_name; init
records the name right after the pubkey, and record/adopt auto-create
the config for pre-feature logs at the first moment the backend
keystore has demonstrably unsealed the signing key. Unnamed keystores
(test doubles) opt out, existing configs are never rewritten, and
verify stays strictly read-only."
```

---

### Task 3: Config-authoritative CLI resolution

**Files:**
- Modify: `src/memattest/cli.py:38-53` (`_make_ma`), `:253-254` (`_add_common` --keystore default and help)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `load_config` (Task 1); configs written by Task 2.
- Produces: `--keystore` default `None`; `_make_ma` resolves config-first with the contradiction error "this log's config records backend keystore '<name>'…". No new flags.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
# --- per-log config resolution (spec 2026-07-13 §4) --------------------------


def test_init_writes_config_and_flag_becomes_unnecessary(memdir, capsys):
    run("init", *base(memdir))
    cfg = (memdir / ".memattest" / "config.toml").read_text(encoding="utf-8")
    assert 'keystore = "file"' in cfg
    capsys.readouterr()
    # No --keystore flag: the config decides (passphrase still via env).
    assert run("verify", "--memory-dir", str(memdir)) == 0
    assert "OK" in capsys.readouterr().out


def test_contradicting_keystore_flag_is_operational_error(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    rc = run("verify", "--memory-dir", str(memdir), "--keystore", "keyring")
    assert rc == 2
    captured = capsys.readouterr()
    assert "records backend keystore 'file'" in captured.err
    # Regression lock: the wrong flag used to reach the wrong backend
    # keystore and report a false key-missing tamper finding.
    assert "key-missing" not in captured.out


def test_config_absent_explicit_flag_still_works(memdir, capsys):
    run("init", *base(memdir))
    (memdir / ".memattest" / "config.toml").unlink()  # pre-feature log
    capsys.readouterr()
    assert run("verify", *base(memdir)) == 0  # legacy behavior preserved


def test_record_auto_creates_config_for_pre_feature_log(memdir, capsys):
    run("init", *base(memdir))
    (memdir / ".memattest" / "config.toml").unlink()
    f = memdir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    assert run("record", *base(memdir), "--path", str(f)) == 0
    cfg = (memdir / ".memattest" / "config.toml").read_text(encoding="utf-8")
    assert 'keystore = "file"' in cfg


def test_corrupted_config_surfaces_in_session_start(memdir, capsys):
    run("init", *base(memdir))
    (memdir / ".memattest" / "config.toml").write_text("not = [valid", encoding="utf-8")
    capsys.readouterr()
    assert run("hook", "session-start", *base(memdir)) == 0
    out = json.loads(capsys.readouterr().out)
    assert "verification could not run" in out["systemMessage"]
    assert "config" in out["systemMessage"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v -k "config or contradicting"`
Expected: `test_init_writes_config_and_flag_becomes_unnecessary` FAILs at the no-flag verify only if the keyring default misroutes — on this machine it fails with exit 1/2 instead of 0; `test_contradicting_keystore_flag_is_operational_error` FAILs (currently exit 1 with a false `key-missing`); `test_corrupted_config_surfaces_in_session_start` FAILs (config not read yet); the other two PASS already (Task 2 behavior) — regression locks.

- [ ] **Step 3: Write the implementation**

`src/memattest/cli.py` — replace `_make_ma`:

```python
def _make_ma(args) -> MemAttest:
    from .core import STATE_DIR_NAME, MemAttest
    from .identity import FileKeyStore, KeyringKeyStore
    from .per_log_config import load_config

    memory_dir = Path(args.memory_dir)
    config = load_config(memory_dir / STATE_DIR_NAME)
    if config is not None:
        recorded = config["keystore"]
        if args.keystore is not None and args.keystore != recorded:
            raise MemAttestError(
                f"this log's config records backend keystore {recorded!r}; "
                "omit --keystore, or edit .memattest/config.toml if the "
                "config is wrong"
            )
        backend = recorded
    else:
        # Pre-config log (or init): pre-feature behavior, keyring by default.
        backend = args.keystore or "keyring"
    if backend == "file":
        passphrase = os.environ.get("MEMATTEST_PASSPHRASE")
        if not passphrase and not getattr(args, "no_key_check", False):
            raise MemAttestError("keystore 'file' requires MEMATTEST_PASSPHRASE to be set")
        # Under --no-key-check the backend keystore is never consulted, so a
        # missing passphrase must not block a copied-log audit.
        ks = FileKeyStore(memory_dir / STATE_DIR_NAME / "key.sealed",
                          (passphrase or "").encode("utf-8"))
    else:
        ks = KeyringKeyStore()
    return MemAttest(memory_dir, keystore=ks)
```

In `_add_common`, replace the `--keystore` line:

```python
    p.add_argument("--keystore", choices=["keyring", "file"], default=None,
                   help="backend keystore; recorded in the log's config.toml "
                        "at init, so it is only needed before init or for "
                        "pre-config logs")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v`
Expected: all PASS, including `test_cli_module_import_stays_lightweight` (`per_log_config` is imported lazily inside `_make_ma`).

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass (adopt/hook tests pass `--keystore file` explicitly, which now matches the recorded config).

- [ ] **Step 6: Commit**

```bash
git add src/memattest/cli.py tests/test_cli.py
git commit -m "Resolve the backend keystore from the per-log config

The config is authoritative: with it present the --keystore flag is
unnecessary, and a contradicting flag is an operational error naming
the recorded backend keystore instead of a lookup in the wrong one
ending in a false key-missing finding. Pre-config logs keep the
pre-feature behavior (keyring default, explicit flag obeyed), and a
corrupted config surfaces at session start as 'verification could not
run'."
```

---

### Task 4: Documentation updates

**Files:**
- Modify: `README.md` (Keystores section, the paragraph starting "Use the same `--keystore` choice consistently" at ~line 245)
- Modify: `docs/superpowers/specs/2026-07-06-memattest-design.md:226` (§13 future-work bullet)
- Modify: `docs/superpowers/plans/2026-07-06-memattest.md:2215-2221` (roadmap item 2)

**Interfaces:**
- Consumes: behavior from Tasks 1-3; spec §8 lists these edits. (The README enumerates state-directory contents nowhere else — `entries/`/`sth/` are never listed — so the Keystores section is the only README edit.)
- Produces: documentation consistent with shipped behavior.

- [ ] **Step 1: README — replace the consistency paragraph**

In `README.md`, replace:

```markdown
Use the same `--keystore` choice consistently for a given memory directory.
Each backend seals the key under a name derived from the memory directory's
resolved path, so switching backends after `init` means memattest can no
longer unseal the original key.
```

with:

```markdown
The choice is recorded in the log's `.memattest/config.toml` at `init`, and
the config is authoritative from then on: later commands need no
`--keystore` flag, and passing one that contradicts the config is an
operational error rather than a lookup in the wrong backend keystore (which
used to end in a false `key-missing` alarm). Logs initialized before this
feature record their config automatically on their next successful append.
Each backend keystore seals the key under a name derived from the memory
directory's resolved path, so there is no way to move a key between backend
keystores after `init`; the manual escape hatch, should the config ever be
wrong, is editing `config.toml` by hand. The config file ships unsigned —
every lie it can tell ends in a loud failure at the next session start, and
cryptographic sealing is planned together with the watch list.
```

- [ ] **Step 2: v1 spec §13 — mark the bullet done**

In `docs/superpowers/specs/2026-07-06-memattest-design.md`, replace line 226 (the bullet beginning `- Per-log \`config.toml\` in \`.memattest/\` recording the keystore backend chosen at init`) with:

```markdown
- ~~Per-log `config.toml`~~ — done 2026-07-13 (spec `2026-07-13-per-log-config-design.md`): init records the backend keystore in `.memattest/config.toml`, the config is authoritative (contradicting `--keystore` is an operational error), and pre-feature logs auto-migrate on their next successful append. Future provider config and guard globs still land here, gated by `config_version`.
```

- [ ] **Step 3: Plan roadmap — mark item 2 done**

In `docs/superpowers/plans/2026-07-06-memattest.md`, replace the item-2 block (from `2. **Per-log \`config.toml\` in \`.memattest/\`** (spec §13). Record the keystore` through `…(hash it into the log or seal it with the key).`) with:

```markdown
2. **Per-log `config.toml` in `.memattest/`** — **done 2026-07-13**
   (spec `docs/superpowers/specs/2026-07-13-per-log-config-design.md`,
   plan `docs/superpowers/plans/2026-07-13-per-log-config.md`).
   Init records the backend keystore; the config is authoritative (a
   contradicting `--keystore` flag is an operational error) and pre-feature
   logs auto-migrate on their next successful append. Shipped without
   cryptographic protection — the signing-key cross-check makes every config
   lie fail-noisy — and the sealing + reconciliation ceremony is explicitly
   deferred to the watch list (item 3), which is where an unprotected config
   would first enable a silent weakening.
```

- [ ] **Step 4: Sanity pass and commit**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

```bash
git add README.md docs/superpowers/specs/2026-07-06-memattest-design.md docs/superpowers/plans/2026-07-06-memattest.md
git commit -m "Document the per-log config

Rewrite the README Keystores consistency paragraph around the recorded
config, mark the v1 spec section 13 bullet done, and mark roadmap
item 2 done with pointers to the new spec and plan."
```

---

### Task 5: End-to-end validation on this machine

**Files:** none (validation only; scratch state under `%TEMP%`).

**Interfaces:**
- Consumes: the installed editable package (`.venv\Scripts\memattest`) with Tasks 1-3 merged; the real Windows Credential Manager; the live installation's memory directory.
- Produces: evidence that shipped behavior matches the spec outside pytest.

- [ ] **Step 1: Scratch lifecycle — init records, config resolves, contradiction errors**

```powershell
$scratch = "$env:TEMP\memattest-config-e2e"
New-Item -ItemType Directory -Force $scratch | Out-Null
Set-Content -Encoding utf8 "$scratch\note.md" "hello"
.venv\Scripts\memattest init --memory-dir $scratch
Get-Content "$scratch\.memattest\config.toml"
.venv\Scripts\memattest verify --memory-dir $scratch
.venv\Scripts\memattest verify --memory-dir $scratch --keystore file
```

Expected: init adopts 1 file; config shows `config_version = 1` and `keystore = "keyring"`; the flagless verify prints `OK 1 entries verified` (exit 0); the contradicting `--keystore file` verify exits 2 with `records backend keystore 'keyring'` on stderr (and no `MEMATTEST_PASSPHRASE` complaint — the error fires before the passphrase gate).

- [ ] **Step 2: Pre-feature migration — delete the config, append recreates it**

```powershell
Remove-Item "$scratch\.memattest\config.toml"
.venv\Scripts\memattest verify --memory-dir $scratch
.venv\Scripts\memattest record --memory-dir $scratch --path "$scratch\note.md"
Get-Content "$scratch\.memattest\config.toml"
.venv\Scripts\memattest verify --memory-dir $scratch
```

Expected: the config-less verify still passes (legacy keyring default finds the key); `record` succeeds and recreates the config with `keystore = "keyring"`; the final verify prints `OK 2 entries verified`.

- [ ] **Step 3: Clean up the scratch log and its credential**

```powershell
.venv\Scripts\python -c "import keyring, pathlib, os; keyring.delete_password('memattest', str((pathlib.Path(os.environ['TEMP']) / 'memattest-config-e2e').resolve()))"
Remove-Item -Recurse -Force $scratch
```

Expected: both commands succeed silently.

- [ ] **Step 4: Live installation — flagless verify, auto-migration, flagless verify again**

```powershell
.venv\Scripts\memattest verify --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory
.venv\Scripts\memattest record --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory --path C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory/MEMORY.md
Get-Content C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory/.memattest/config.toml
.venv\Scripts\memattest verify --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory
```

Expected: first verify passes with no flag (config absent → legacy keyring path); the `record` of `MEMORY.md` (an unchanged-content write event — harmless and permanently logged) auto-creates the config with `keystore = "keyring"`; the final flagless verify passes with one more entry than before.

- [ ] **Step 5: Full suite, final**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass. Report results to the user; no commit (nothing changed).
