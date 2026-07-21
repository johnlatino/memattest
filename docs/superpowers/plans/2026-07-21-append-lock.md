# Append Concurrency Lock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serialize memattest's append-and-seal operations with a cross-process file lock so concurrent processes cannot drop writes or reorder tree heads, and give verify a consistent snapshot read.

**Architecture:** Add `filelock`. A `MemAttest._append_lock()` context manager wraps the full body of every append-and-seal method (`init`, `record`, `adopt`, `unwatch`), with precondition checks placed so concurrent operations serialize cleanly. `verify` takes the same lock only around the entries-and-tree-head snapshot read, then computes on the in-memory snapshot.

**Tech Stack:** Python >= 3.12, `filelock`, pytest, `multiprocessing`. Spec: `docs/superpowers/specs/2026-07-21-append-lock-design.md`.

## Global Constraints

- **venv only** - every `pip`, `pytest`, and `memattest` invocation uses `.venv\Scripts\...` (Windows dev machine). Branch: `append-lock`.
- New runtime dependency: `filelock>=3` (pure Python, no transitive deps). Add to `pyproject.toml` and install into the venv. No other new dependencies.
- The lock file is `.memattest/append.lock`; it must stay inside `.memattest/` (excluded from guarding, not matched by the `entries/*.json` or `sth/*.json` globs). Lock timeout default 10s; on timeout raise `MemAttestError` -> exit 2.
- `verify` stays read-only and must NOT create `.memattest` when it does not exist (the `test_verify_on_wrong_dir_leaves_no_state_behind` guarantee): acquire the lock only when `state_dir` already exists.
- No on-disk log format change; scheme stays `"v1"`. Exit codes unchanged.
- The hot `hook pre-tool-use` path imports nothing heavy: `filelock` is imported lazily inside `_append_lock`; `test_cli_module_import_stays_lightweight` must keep passing.
- Wording, everywhere (docs, messages, commits): plain phrasing; NO em-dashes (single hyphens, commas); "backend keystore" never bare "backend"; never "load-bearing"; no contrastive-reframe constructions; "procedure" not "ceremony".
- Commit messages: concise (short subject plus at most a one-or-two-sentence body); subject + body only, **no attribution lines**.
- Guard note: shell commands and commit messages must not contain the two-word phrases `memattest adopt`/`memattest install`/`memattest unwatch`, `.claude/settings*.json`-shaped paths, or the hook-disabling flag name. Run the suite via pytest paths.

## File Structure

- `pyproject.toml` - add `filelock>=3` (Task 1).
- `src/memattest/core.py` - `_append_lock` helper and lock-wrapping of `init`/`record`/`adopt`/`unwatch` (Task 1); `verify` snapshot read plus optional `entries` param on `derived_state`/`derived_watch_state` (Task 2).
- `tests/test_concurrency.py` (new) - timeout and cross-process tests (Tasks 1 and 3).
- `tests/test_watch.py` / `tests/test_core.py` - snapshot behavior assertions (Task 2).

---

### Task 1: filelock dependency and the append lock

**Files:**
- Modify: `pyproject.toml` (add `filelock>=3`)
- Modify: `src/memattest/core.py` (imports; add `_append_lock`; wrap `init`, `record`, `adopt`, `unwatch`)
- Test: `tests/test_concurrency.py` (new)

**Interfaces:**
- Produces: `MemAttest._append_lock()` - a context manager acquiring `FileLock(str(self.state_dir / "append.lock"), timeout=10)` and translating `filelock.Timeout` to `MemAttestError`. `init`/`record`/`adopt`/`unwatch` hold it across their full append-and-seal body. Task 2 reuses `_append_lock` in `verify`.

- [ ] **Step 1: Add the dependency and install it**

In `pyproject.toml`, extend `dependencies`:

```toml
dependencies = [
    "cryptography>=42",
    "keyring>=24",
    "psutil>=5.9",
    "filelock>=3",
]
```

Run: `.venv\Scripts\python -m pip install filelock>=3`
Expected: filelock installs (or "already satisfied").

- [ ] **Step 2: Write the failing tests**

Create `tests/test_concurrency.py`:

```python
from pathlib import Path

import pytest

from memattest.core import MemAttest
from memattest.identity import FileKeyStore


def _file_ma(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    ks = FileKeyStore(d / ".memattest" / "key.sealed", b"pw")
    return MemAttest(d, keystore=ks)


def test_lock_file_lives_in_state_dir(tmp_path):
    ma = _file_ma(tmp_path)
    ma.init()
    f = ma.memory_dir / "note.md"
    f.write_text("x", encoding="utf-8")
    ma.record(f)
    assert (ma.state_dir / "append.lock").exists()
    # The lock file must not be counted as an entry or flagged unlogged.
    assert ma.verify().ok


def test_timeout_becomes_operational_error(tmp_path, monkeypatch):
    # filelock is reentrant within one process, so a real same-process hold
    # would not time out. Force the Timeout deterministically instead and
    # assert record translates it to an operational error.
    import filelock
    from memattest.errors import MemAttestError
    ma = _file_ma(tmp_path)
    ma.init()
    f = ma.memory_dir / "note.md"
    f.write_text("x", encoding="utf-8")

    class _AlwaysTimeout:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            raise filelock.Timeout("busy")

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(filelock, "FileLock", _AlwaysTimeout)
    with pytest.raises(MemAttestError, match="could not acquire the append lock"):
        ma.record(f)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_concurrency.py -v`
Expected: FAIL - `append.lock` is not created (no lock yet), and `record` does not raise on a held lock.

- [ ] **Step 4: Write the implementation**

In `src/memattest/core.py`, add imports at the top (after the existing `from pathlib import Path`):

```python
from contextlib import contextmanager

from .canonical import canonical_json
```

Add a `_timeout` default and the lock helper to `MemAttest`. Put `_timeout` as a class attribute after the docstring, and `_append_lock` after `_identity`:

```python
    _timeout = 10.0  # seconds to wait for the append lock before erroring

    @contextmanager
    def _append_lock(self):
        # Serialize the whole append-and-seal body across processes. filelock
        # uses OS advisory locks, so a process killed mid-append releases the
        # lock instantly. Imported lazily to keep the hot hook path light.
        from filelock import FileLock, Timeout
        lock = FileLock(str(self.state_dir / "append.lock"), timeout=self._timeout)
        try:
            with lock:
                yield
        except Timeout as exc:
            raise MemAttestError(
                f"could not acquire the append lock at "
                f"{self.state_dir / 'append.lock'} within {self._timeout}s; "
                "another memattest process may be holding it"
            ) from exc
```

Replace `init` with (mkdir before the lock so the lock file has a home on a fresh log; the "already initialized" check moves inside so two concurrent inits serialize):

```python
    def init(self, reason: str = "initial baseline") -> list[dict]:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        with self._append_lock():
            if self.initialized:
                raise MemAttestError(f"{self.memory_dir} is already initialized")
            identity = Identity.generate(self.keystore, self.key_name)
            self.pubkey_path.write_text(identity.public_key_bytes.hex(), encoding="ascii")
            self._write_config_if_named()
            entries = [self._append(identity, "adopt", p, reason) for p in self.guarded_files()]
            self._seal_current_tree(identity)
        return entries
```

Replace `record` (the not-initialized check stays outside the lock, so a failed record on an uninitialized directory creates no state; once initialized, `state_dir` already exists for the lock file):

```python
    def record(self, path: Path, op: str = "write", reason: str | None = None) -> dict:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        with self._append_lock():
            identity = self._identity()
            entry = self._append(identity, op, path, reason)
            self._seal_current_tree(identity)
            self._write_config_if_named()
        return entry
```

Replace `adopt`:

```python
    def adopt(self, paths: list[Path], reason: str) -> list[dict]:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        with self._append_lock():
            identity = self._identity()
            entries = [self._append(identity, "adopt", p, reason, scope=self._scope_for(p))
                       for p in paths]
            self._seal_current_tree(identity)
            self._write_config_if_named()
        return entries
```

Replace `unwatch` (the watch-existence check moves inside the lock so two concurrent unwatches of the same path serialize: the second re-checks and fails cleanly):

```python
    def unwatch(self, paths: list[Path], reason: str) -> list[dict]:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        with self._append_lock():
            watched = self.derived_watch_state()
            for p in paths:
                if Path(p).resolve().as_posix() not in watched:
                    raise MemAttestError(f"{Path(p).resolve().as_posix()} is not currently watched")
            identity = self._identity()
            entries = [self._append(identity, "delete", p, reason, scope="watch") for p in paths]
            self._seal_current_tree(identity)
            self._write_config_if_named()
        return entries
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_concurrency.py -v`
Expected: both PASS.

- [ ] **Step 6: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass. The lock is transparent to existing single-threaded tests. `test_cli_module_import_stays_lightweight` still passes (filelock is imported lazily inside `_append_lock`).

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml src/memattest/core.py tests/test_concurrency.py
git commit -m "Serialize append-and-seal operations with a file lock

init, record, adopt, and unwatch now hold a filelock across their whole
append-and-seal body, so concurrent memattest processes cannot drop
writes or reorder tree heads. A lock timeout is an operational error."
```

---

### Task 2: verify reads a consistent snapshot

**Files:**
- Modify: `src/memattest/core.py` (`derived_state`, `derived_watch_state` gain an optional `entries` argument; `verify` reads entries and tree heads under the lock, then computes on the snapshot)
- Test: `tests/test_watch.py`

**Interfaces:**
- Consumes: `_append_lock` (Task 1).
- Produces: `derived_state(entries=None)`, `derived_watch_state(entries=None)`; `verify` computes leaves and derived state from a single snapshot.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_watch.py`:

```python
def test_derived_state_accepts_entries_snapshot(mem):
    f = mem.memory_dir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    mem.record(f)
    snapshot = mem.store.load_all()
    # Passing the snapshot yields the same result as reading from disk.
    assert mem.derived_state(snapshot) == mem.derived_state()
    assert "notes.md" in mem.derived_state(snapshot)


def test_derived_watch_state_accepts_entries_snapshot(mem, tmp_path):
    external = tmp_path / "watched.md"
    external.write_text("x", encoding="utf-8")
    mem.adopt([external], reason="watch it")
    snapshot = mem.store.load_all()
    assert mem.derived_watch_state(snapshot) == mem.derived_watch_state()
    assert external.resolve().as_posix() in mem.derived_watch_state(snapshot)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py -v -k snapshot`
Expected: FAIL - `derived_state()` / `derived_watch_state()` take no positional argument.

- [ ] **Step 3: Write the implementation**

In `src/memattest/core.py`, give both derived-state methods an optional `entries` parameter. Replace `derived_state`:

```python
    def derived_state(self, entries: list[dict] | None = None) -> dict[str, str]:
        if entries is None:
            entries = self.store.load_all()
        state: dict[str, str] = {}
        for e in entries:
            if e.get("scope", "memory") != "memory":
                continue
            if e["op"] in ("write", "adopt"):
                state[e["path"]] = e["content_hash"]
            elif e["op"] == "delete":
                state.pop(e["path"], None)
        return state
```

Replace `derived_watch_state`:

```python
    def derived_watch_state(self, entries: list[dict] | None = None) -> dict[str, str]:
        if entries is None:
            entries = self.store.load_all()
        state: dict[str, str] = {}
        for e in entries:
            if e.get("scope", "memory") != "watch":
                continue
            if e["op"] in ("write", "adopt"):
                state[e["path"]] = e["content_hash"]
            elif e["op"] == "delete":
                state.pop(e["path"], None)
        return state
```

In `verify`, replace the opening reads (currently `entries = self.store.load_all()` / `sths = self.sth_chain.load_all()`) with a snapshot read that takes the lock only when the state directory exists (so verify never creates `.memattest`):

```python
        problems: list[dict] = []
        if self.state_dir.is_dir():
            with self._append_lock():
                entries = self.store.load_all()
                sths = self.sth_chain.load_all()
        else:
            entries = self.store.load_all()
            sths = self.sth_chain.load_all()
```

Replace `leaves = self.store.leaf_bytes()` with the in-memory computation from the snapshot (so leaves and entries are one consistent snapshot):

```python
        leaves = [canonical_json(e) for e in entries]
```

Replace `expected = self.derived_state()` with `expected = self.derived_state(entries)`, and `watch_expected = self.derived_watch_state()` with `watch_expected = self.derived_watch_state(entries)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py -v -k snapshot`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass, including `test_verify_on_wrong_dir_leaves_no_state_behind` (verify skips the lock when `.memattest` is absent, so it creates nothing).

- [ ] **Step 6: Commit**

```bash
git add src/memattest/core.py tests/test_watch.py
git commit -m "Verify reads entries and tree heads under the lock

verify takes the append lock only for the snapshot read (when the state
directory exists), then computes leaves and derived state from that one
in-memory snapshot, closing the mid-append root-mismatch false alarm
without holding the lock across the crypto and file-hashing work."
```

---

### Task 3: cross-process contention test

**Files:**
- Modify: `tests/test_concurrency.py`

**Interfaces:**
- Consumes: the lock from Tasks 1-2.
- Produces: an integration test proving N concurrent `record`s all land and verify stays clean.

- [ ] **Step 1: Write the test**

Append to `tests/test_concurrency.py` (a module-level worker is required so `multiprocessing` spawn on Windows can pickle it):

```python
import multiprocessing as mp


def _record_worker(memory_dir, key_path, passphrase, filename, content, barrier):
    from memattest.core import MemAttest
    from memattest.identity import FileKeyStore
    ma = MemAttest(Path(memory_dir), keystore=FileKeyStore(Path(key_path), passphrase))
    f = Path(memory_dir) / filename
    f.write_text(content, encoding="utf-8")
    barrier.wait()  # all workers hit record() together, forcing contention
    ma.record(f)


def test_concurrent_records_all_land_and_verify_clean(tmp_path):
    ma = _file_ma(tmp_path)
    ma.init()
    base = ma.store.count()
    key_path = str(ma.state_dir / "key.sealed")
    n = 8
    barrier = mp.Barrier(n)
    procs = [
        mp.Process(target=_record_worker,
                   args=(str(ma.memory_dir), key_path, b"pw", f"note{i}.md", f"c{i}", barrier))
        for i in range(n)
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join(timeout=60)
    for p in procs:
        assert p.exitcode == 0  # no worker crashed on a collision

    reader = MemAttest(ma.memory_dir, keystore=FileKeyStore(Path(key_path), b"pw"))
    assert reader.store.count() == base + n  # every write landed, none dropped
    report = reader.verify()
    assert report.ok and report.exit_code == 0  # tree-head chain stayed consistent
```

- [ ] **Step 2: Run the test**

Run: `.venv\Scripts\python -m pytest tests/test_concurrency.py::test_concurrent_records_all_land_and_verify_clean -v`
Expected: PASS. (Against the pre-lock code this fails - workers crash on index collisions and/or verify reports `root-mismatch` - so it genuinely exercises the fix. Re-run it a few times to confirm stability under scheduling variance.)

- [ ] **Step 3: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_concurrency.py
git commit -m "Add a cross-process append contention test

Eight processes record against one log simultaneously through a
barrier; the test asserts every write lands and verify stays clean,
which fails on the pre-lock code."
```

---

### Task 4: Validation on this machine

**Files:** none (validation only).

**Interfaces:**
- Consumes: the installed editable package with Tasks 1-3 merged and `filelock` in the venv.
- Produces: evidence outside the suite.

- [ ] **Step 1: Confirm filelock is installed and the suite is green**

```powershell
.venv\Scripts\python -c "import filelock; print(filelock.__version__)"
.venv\Scripts\python -m pytest -q
```

Expected: prints a filelock 3.x version; all tests pass. Report the count.

- [ ] **Step 2: Run the contention test repeatedly for stability**

```powershell
1..5 | ForEach-Object { .venv\Scripts\python -m pytest tests/test_concurrency.py -q }
```

Expected: all five runs pass (the cross-process test is scheduling-sensitive, so repeating it checks for flakiness).

- [ ] **Step 3: Live-log regression check**

```powershell
.venv\Scripts\memattest verify --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory
```

Expected: `OK <n> entries verified`, exit 0 - the lock is transparent to the existing live log, and a `.memattest/append.lock` file appears there after a verify (harmless, excluded from guarding). No commit (nothing changed).
