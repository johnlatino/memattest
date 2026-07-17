# Watch List Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** memattest guards designated external files (Claude Code settings, `CLAUDE.md`) by recording them as scope-tagged log entries, so out-of-band edits surface at the next session start; reconciliation reuses `adopt`, removal is a new guarded `unwatch`.

**Architecture:** Every entry gains a `scope` field (`"memory"` | `"watch"`); the scheme stays `"v1"`, extended not versioned. Watch data lives in the signed log, so its integrity is the existing tree/STH checks — no new mechanism. Verify partitions replayed state by scope and checks watched files at their absolute paths. `adopt` infers scope from path location; `unwatch` appends a watch `delete`.

**Tech Stack:** Python ≥ 3.12, pytest. Spec: `docs/superpowers/specs/2026-07-17-watch-list-design.md`.

## Global Constraints

- **venv only** — every `pytest` and `memattest` invocation uses `.venv\Scripts\...` (Windows dev machine). Branch: `watch-list`.
- No new dependencies. The append-only log format is extended by one optional field, not versioned: `SCHEME` stays `"v1"`.
- Existing on-disk entries (no `scope`) must keep verifying — leaf hashes come from the bytes on disk, so only newly built entries carry `scope`; readers use `e.get("scope", "memory")`.
- `verify` stays read-only. Exit codes unchanged: `0` clean · `1` tamper (`modified`/`missing`) · `2` operational · `3` unknown scheme.
- The hot `hook pre-tool-use` path imports nothing heavy; `test_cli_module_import_stays_lightweight` must keep passing.
- All watch operations get adopt-level protection: interactive TTY, typed confirmation, `--reason`, `PreToolUse` deny for agents.
- Wording, everywhere (docs, help, messages, commits): plain phrasing over fancy; "backend keystore", never bare "backend"; never "load-bearing"; never the informal self-testing term; no contrastive-reframe constructions; use "procedure" not "ceremony" and describe the missing-startup-message signal plainly (no "canary").
- Commit messages: concise — short subject plus at most a one-or-two-sentence body; subject + body only, **no attribution lines**.
- **Guard phrase discipline:** from Task 3 onward the editable install makes the new `unwatch` deny pattern live, joining the existing adopt/install/settings ones. Shell commands and commit messages must never contain the literal two-word phrases `memattest adopt`, `memattest install`, or `memattest unwatch`, paths shaped like `.claude/settings*.json`, or the hook-disabling flag name. Write "the unwatch command" etc. in commit messages. File content written via Edit/Write tools may contain these.

## File Structure

- `src/memattest/entry.py` — `build_entry` gains `scope` (Task 1).
- `src/memattest/core.py` — `_scope_for`, scope-aware `_append`, `adopt` scope detection, `derived_state` memory filter (Task 1); `derived_watch_state`, verify watch branch (Task 2); `unwatch` (Task 3).
- `src/memattest/cli.py` — `cmd_unwatch`, parser, `_UNWATCH_INVOCATION` guard (Task 3).
- `src/memattest/integrations/claude_code/install.py` — `run_install` adopt-watches the settings file (Task 4).
- `src/memattest/integrations/claude_code/settings-snippet.json` — unwatch deny globs (Task 3).
- `tests/test_watch.py` (new), `tests/test_entry_store.py`, `tests/test_core.py`, `tests/test_adopt.py`, `tests/test_cli.py`, `tests/test_claude_install.py` — tests per task.
- `README.md`, `docs/manual-test-full-lifecycle.md` — docs (Task 5).

---

### Task 1: `scope` field, scope-aware append, adopt scope detection

**Files:**
- Modify: `src/memattest/entry.py` (`build_entry`), `src/memattest/core.py` (`_append`, `adopt`, `derived_state`; add `_scope_for`)
- Test: `tests/test_watch.py` (new), `tests/test_entry_store.py`

**Interfaces:**
- Produces: `build_entry(..., scope="memory")` adds `"scope"` to the entry; `MemAttest._scope_for(path) -> "memory"|"watch"`; `_append(identity, op, path, reason, scope="memory")`; `adopt` tags each path by location; `derived_state()` returns memory-scope files only. Task 2 adds `derived_watch_state`; Task 3 adds `unwatch`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_watch.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py -v`
Expected: FAIL — `build_entry` has no `scope` param, `adopt` doesn't tag scope.

- [ ] **Step 3: Write the implementation**

`src/memattest/entry.py` — replace `build_entry`:

```python
def build_entry(
    index: int,
    op: str,
    path: str,
    content_hash: str | None,
    provenance: dict,
    reason: str | None = None,
    timestamp: str | None = None,
    scope: str = "memory",
) -> dict:
    if op not in ("write", "delete", "adopt"):
        raise ValueError(f"unknown op: {op}")
    if scope not in ("memory", "watch"):
        raise ValueError(f"unknown scope: {scope}")
    entry = {
        "scheme": SCHEME,
        "index": index,
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "op": op,
        "scope": scope,
        "path": path,
        "content_hash": content_hash,
        "provenance": provenance,
    }
    if reason is not None:
        entry["reason"] = reason
    return entry
```

`src/memattest/core.py` — add `_scope_for` (after `_rel`):

```python
    def _scope_for(self, path: Path) -> str:
        # A path under the memory directory is a memory file; anything else
        # is a watched external file (spec 2026-07-17).
        try:
            Path(path).resolve().relative_to(self.memory_dir.resolve())
        except ValueError:
            return "watch"
        return "memory"
```

Replace `_append`:

```python
    def _append(self, identity: Identity, op: str, path: Path, reason: str | None,
                scope: str = "memory") -> dict:
        if scope == "memory":
            path_str = self._rel(path)
        else:
            path_str = Path(path).resolve().as_posix()
        content_hash = None if op == "delete" else file_content_hash(Path(path))
        entry = build_entry(
            index=self.store.count(),
            op=op,
            path=path_str,
            content_hash=content_hash,
            provenance=provenance.collect(),
            reason=reason,
            scope=scope,
        )
        self.store.append(entry)
        return entry
```

Replace `adopt`:

```python
    def adopt(self, paths: list[Path], reason: str) -> list[dict]:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        identity = self._identity()
        entries = [self._append(identity, "adopt", p, reason, scope=self._scope_for(p))
                   for p in paths]
        self._seal_current_tree(identity)
        self._write_config_if_named()
        return entries
```

Replace `derived_state` (filter to memory scope):

```python
    def derived_state(self) -> dict[str, str]:
        state: dict[str, str] = {}
        for e in self.store.load_all():
            if e.get("scope", "memory") != "memory":
                continue
            if e["op"] in ("write", "adopt"):
                state[e["path"]] = e["content_hash"]
            elif e["op"] == "delete":
                state.pop(e["path"], None)
        return state
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass. If any existing test asserts a full entry dict by equality, add `"scope": "memory"` to the expected dict (the additive default keeps `entry["op"]`-style assertions working). `leaf_bytes` over on-disk entries is unchanged, so STH/tree tests are unaffected.

- [ ] **Step 6: Commit**

```bash
git add src/memattest/entry.py src/memattest/core.py tests/test_watch.py
git commit -m "Tag log entries with a memory/watch scope

Entries now carry a scope field; adopt tags a path outside the memory
directory as a watch entry storing its absolute path, and derived_state
returns only memory-scope files. Scheme stays v1."
```

---

### Task 2: Verify checks watched files

**Files:**
- Modify: `src/memattest/core.py` (add `derived_watch_state`; watch branch in `verify` after the memory Check 3, before `ok = not problems`)
- Test: `tests/test_watch.py`

**Interfaces:**
- Consumes: `_scope_for`, scope-aware `adopt` (Task 1).
- Produces: `derived_watch_state() -> dict[str, str]`; verify reports `modified`/`missing` for watched files, operational error on unreadable ones, no `unlogged`. Task 3's `unwatch` consumes `derived_watch_state`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_watch.py`:

```python
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

    def boom(p):
        if Path(p) == external:
            raise PermissionError("locked")
        return core_mod.file_content_hash(p)

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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py -v -k "watched or watch"`
Expected: the watched-file tests FAIL — verify does not check watch entries yet, so `test_modified_watched_file_reported` sees a clean report.

- [ ] **Step 3: Write the implementation**

`src/memattest/core.py` — add `derived_watch_state` (after `derived_state`):

```python
    def derived_watch_state(self) -> dict[str, str]:
        state: dict[str, str] = {}
        for e in self.store.load_all():
            if e.get("scope", "memory") != "watch":
                continue
            if e["op"] in ("write", "adopt"):
                state[e["path"]] = e["content_hash"]
            elif e["op"] == "delete":
                state.pop(e["path"], None)
        return state
```

In `verify`, immediately before `ok = not problems` (currently the last two lines), insert:

```python
        # Check 3 (watch): designated external files, keyed by absolute path.
        watch_expected = self.derived_watch_state()
        for wpath, exp_hash in watch_expected.items():
            e = last_entry[wpath]
            wf = Path(wpath)
            if not wf.exists():
                problems.append(_problem(
                    "missing", wpath,
                    f"watched file absent on disk; last recorded at entry "
                    f"{e['index']} ({e['timestamp']}) [scope=watch]", e["index"]))
                continue
            try:
                actual_hash = file_content_hash(wf)
            except OSError as exc:
                raise MemAttestError(f"cannot read watched file {wpath}: {exc}") from exc
            if actual_hash != exp_hash:
                problems.append(_problem(
                    "modified", wpath,
                    f"expected {exp_hash}, found {actual_hash}; last recorded at "
                    f"entry {e['index']} ({e['timestamp']}) [scope=watch]", e["index"]))
```

(`last_entry`, built at the top of Check 3 keyed by each entry's `path`, already contains watch entries under their absolute-path keys, so `last_entry[wpath]` resolves.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/memattest/core.py tests/test_watch.py
git commit -m "Check watched external files in verify

verify hashes each watched file at its recorded absolute path and
reports modified or missing (no unlogged, since the watch list is a
named set, not a swept directory); an unreadable watched file is an
operational error. Memory checks are unchanged."
```

---

### Task 3: `unwatch` command and guard

**Files:**
- Modify: `src/memattest/core.py` (add `unwatch`), `src/memattest/cli.py` (add `cmd_unwatch`, parser, `_UNWATCH_INVOCATION`, deny branch), `src/memattest/integrations/claude_code/settings-snippet.json` (deny globs)
- Test: `tests/test_watch.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `derived_watch_state` (Task 2); adopt-external via CLI (Task 1).
- Produces: `MemAttest.unwatch(paths, reason)`; `memattest unwatch --memory-dir <dir> --path <file> --reason <r>`; guard denies agent-run unwatch.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_watch.py`:

```python
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
```

Append to `tests/test_cli.py`:

```python
def test_cli_unwatch_stops_watching(tmp_path, monkeypatch, capsys):
    import io
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    external = tmp_path / "watched.md"
    external.write_text("x", encoding="utf-8")
    fake = io.StringIO(); fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)
    monkeypatch.setattr("builtins.input", lambda prompt="": "adopt")
    cli.main(["adopt", "--path", str(external), "--memory-dir", str(d), "--keystore", "file",
              "--reason", "watch it"])
    monkeypatch.setattr("builtins.input", lambda prompt="": "unwatch")
    rc = cli.main(["unwatch", "--path", str(external), "--memory-dir", str(d),
                   "--keystore", "file", "--reason", "done"])
    assert rc == 0
    assert "stopped watching" in capsys.readouterr().out


def test_cli_unwatch_refuses_without_tty(tmp_path, monkeypatch, capsys):
    import io
    d = tmp_path / "memory"; d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    fake = io.StringIO(); fake.isatty = lambda: False
    monkeypatch.setattr("sys.stdin", fake)
    rc = cli.main(["unwatch", "--path", str(tmp_path / "x.md"), "--memory-dir", str(d),
                   "--keystore", "file", "--reason", "r"])
    assert rc == 2
    assert "interactive terminal" in capsys.readouterr().err


def test_hook_pre_tool_use_denies_unwatch(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash", "memattest unwatch --path x --memory-dir . --reason r")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "unwatch" in out["hookSpecificOutput"]["permissionDecisionReason"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py tests/test_cli.py -v -k unwatch`
Expected: FAIL — no `unwatch` method, no `unwatch` subcommand, no guard branch.

- [ ] **Step 3: Write the implementation**

`src/memattest/core.py` — add `unwatch` (after `adopt`):

```python
    def unwatch(self, paths: list[Path], reason: str) -> list[dict]:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
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

`src/memattest/cli.py` — add `cmd_unwatch` (after `cmd_adopt`):

```python
def cmd_unwatch(args) -> int:
    if not sys.stdin.isatty():
        print("error: unwatch requires an interactive terminal", file=sys.stderr)
        return 2
    ma = _make_ma(args)
    if not ma.initialized:
        raise MemAttestError("not initialized; run init first")
    print(f"About to stop watching {len(args.paths)} file(s). Reason: {args.reason}")
    try:
        confirmed = input("Type 'unwatch' to confirm: ").strip() == "unwatch"
    except (EOFError, KeyboardInterrupt):
        confirmed = False
    if not confirmed:
        print("aborted", file=sys.stderr)
        return 2
    ma.unwatch([Path(p) for p in args.paths], reason=args.reason)
    print(f"stopped watching {len(args.paths)} file(s)")
    return 0
```

Add the guard regex after `_INSTALL_INVOCATION`:

```python
# unwatch narrows tamper-detection coverage, so agent-run invocations are
# denied like adopt and install.
_UNWATCH_INVOCATION = re.compile(r"\bmemattest(\.exe)?\s+unwatch\b", re.IGNORECASE)
```

In `cmd_hook_pre_tool_use`, add a branch after the `_INSTALL_INVOCATION` one:

```python
    elif _UNWATCH_INVOCATION.search(normalized):
        _deny("memattest unwatch narrows tamper-detection coverage and may "
              "only be run by a human at an interactive terminal, not by "
              "the agent")
```

In `main()`, add the `unwatch` subparser after the `adopt` block:

```python
    p = sub.add_parser("unwatch", help="stop watching an external file (interactive only)")
    p.add_argument("--memory-dir", required=True)
    p.add_argument("--keystore", choices=["keyring", "file"], default=None,
                   help="backend keystore; only needed for pre-config logs")
    p.add_argument("--path", action="append", required=True, dest="paths",
                   help="watched file to stop watching; repeat the flag for multiple files")
    p.add_argument("--reason", required=True)
    p.set_defaults(fn=cmd_unwatch)
```

In `settings-snippet.json`, extend the deny list with the pair:

```json
      "Bash(*memattest unwatch*)",
      "PowerShell(*memattest unwatch*)"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_watch.py tests/test_cli.py -v`
Expected: all PASS (including the existing adopt guard/deny tests, unaffected).

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass, including `test_cli_module_import_stays_lightweight`.

- [ ] **Step 6: Commit**

```bash
git add src/memattest/core.py src/memattest/cli.py src/memattest/integrations/claude_code/settings-snippet.json tests/test_watch.py tests/test_cli.py
git commit -m "Add the guarded unwatch command

unwatch appends a watch delete entry to stop watching a file (and to
clear a missing finding for one legitimately removed); it is
interactive-only with typed confirmation and, like adopt and install,
denied to agents by the PreToolUse guard and the template deny globs."
```

---

### Task 4: Install onboarding — watch the settings file

**Files:**
- Modify: `src/memattest/integrations/claude_code/install.py` (`run_install`)
- Test: `tests/test_claude_install.py`

**Interfaces:**
- Consumes: scope-aware `adopt` (Task 1). `run_install` already holds `ma` and the resolved `target` settings path.
- Produces: after writing settings, `run_install` adopt-watches the settings file; the closing verify then covers it.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_claude_install.py`:

```python
def test_install_watches_the_settings_file(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["1", "install"])
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 0
    from memattest.core import MemAttest
    from memattest.identity import FileKeyStore
    ma = MemAttest(mem, keystore=FileKeyStore(mem / ".memattest" / "key.sealed", b"pw"))
    watched = ma.derived_watch_state()
    target = (project / ".claude" / "settings.json").resolve().as_posix()
    assert target in watched
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v -k watches_the_settings`
Expected: FAIL — the settings file is written but not watched.

- [ ] **Step 3: Write the implementation**

In `src/memattest/integrations/claude_code/install.py`, in `run_install`, after the `write_settings(target, merged)` / "wrote hooks…" print and before the closing `report = ma.verify()`, add:

```python
    ma.adopt([target], reason="watched by memattest install")
    print(f"watching {target.as_posix()} for out-of-band changes")
```

Add one line to the printed plan (in the plan block that lists actions), so the watch is disclosed before confirmation:

```python
    print(f"  watch:       {target.as_posix()} (added to tamper detection)")
```

(`target` is `project / ".claude" / name`, outside the memory directory, so `adopt` tags it `scope: "watch"`. It exists because `write_settings` just created it.)

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v`
Expected: all PASS (the full drive-through test's closing verify stays clean — the watched file was just baselined).

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/memattest/integrations/claude_code/install.py tests/test_claude_install.py
git commit -m "Watch the settings file the installer writes

install now adopt-watches the settings file it just wrote, so
out-of-band edits to the hook configuration are reported at the next
session start; the watch is disclosed in the plan before confirmation."
```

---

### Task 5: Documentation

**Files:**
- Modify: `README.md` (new "Watching the trust surface" section after "Auditing with proofs"), `docs/manual-test-full-lifecycle.md` (a watch part)

**Interfaces:**
- Consumes: behavior from Tasks 1–4.
- Produces: docs consistent with shipped behavior.

- [ ] **Step 1: README — new section**

Insert after the "## Auditing with proofs" section, before "## Hardening your installation":

````markdown
## Watching the trust surface

memattest guards the files in your memory directory, but the hook
configuration that makes it run — the Claude Code settings file, and
instruction files like `CLAUDE.md` — lives outside that directory. The
watch list extends coverage to designated external files: an out-of-band
edit to a watched file is reported at the next session start, exactly like
a tampered memory file.

`memattest install` automatically watches the settings file it writes, so
the hook configuration is covered out of the box. To watch another file,
adopt it — a path outside the memory directory is recorded as a watched
file rather than a memory file:

```bash
memattest adopt --path <PROJECT>/CLAUDE.md --memory-dir <MEMORY_DIR> --reason "baseline project instructions"
```

When a watched file legitimately changes, re-baseline it by adopting it
again with a reason. To stop watching a file (or to clear the report for
one you deliberately deleted), use `unwatch`:

```bash
memattest unwatch --path <PROJECT>/CLAUDE.md --memory-dir <MEMORY_DIR> --reason "no longer used"
```

Both `adopt` and `unwatch` run only from an interactive terminal with typed
confirmation, and the `PreToolUse` guard denies agent-run invocations, since
changing what is watched changes your tamper-detection coverage.

Two limits worth knowing. If someone removes the memattest hook from the
settings file entirely, verification never runs and the watch on that file
never fires — the remaining signal is that memattest goes silent at session
start (no `OK N entries verified` line), which a person has to notice.
And same-user malware can delete watch entries and re-sign the log, the same
limit that applies to memory entries. Both are addressed by the planned
validator that runs under a separate account.
````

- [ ] **Step 2: manual-test doc — a watch part**

In `docs/manual-test-full-lifecycle.md`, add a new part after Part E (before the cleanup part), matching the file's PowerShell + expected-output style:

```markdown
## Part F — the watch list (reversible)

Watch an external file, tamper with it, and confirm the report; then stop
watching it. Run the `adopt`/`unwatch` commands yourself in an interactive
terminal — the guard denies them to agents, and they require typed
confirmation.

```powershell
Set-Content -Encoding utf8 "$mem\..\WATCHED.md" "baseline"
$watched = (Resolve-Path "$mem\..\WATCHED.md").Path
.venv\Scripts\memattest adopt --path $watched --memory-dir $mem --reason "watch test"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: after typing `adopt`, `adopted 1 file(s)`; verify prints
`OK <n> entries verified`, exit 0.

```powershell
Set-Content -Encoding utf8 $watched "tampered"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: exit 1, `PROBLEM kind=modified path=<absolute path to WATCHED.md>`
with `[scope=watch]` in the detail.

```powershell
.venv\Scripts\memattest unwatch --path $watched --memory-dir $mem --reason "done"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
Remove-Item $watched
```

Expected: after typing `unwatch`, `stopped watching 1 file(s)`; verify is
`OK` again, exit 0.
```

(Renumber the existing cleanup part if it was lettered; the watch part is reversible and belongs before cleanup.)

- [ ] **Step 3: Sanity pass and commit**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

```bash
git add README.md docs/manual-test-full-lifecycle.md
git commit -m "Document the watch list

Add a README section on watching the trust surface (adopt an external
file, re-baseline, unwatch, and the two honest limits) and a reversible
watch part to the manual-test procedure."
```

---

### Task 6: Validation and the live-log re-init

**Files:** none tracked (validation + a one-time live migration).

**Interfaces:**
- Consumes: the installed editable package with Tasks 1–5 merged.
- Produces: evidence outside pytest, and this repo's log re-initialized so every entry carries `scope` explicitly.

- [ ] **Step 1: Core-level watch flow on a scratch directory (agent-runnable)**

The guard denies agent-run `adopt`/`unwatch` shell commands, so drive the flow through the core API in one script rather than the CLI. Write it to the scratchpad and run it:

```powershell
@'
import os, tempfile, pathlib
from memattest.core import MemAttest
from memattest.identity import FileKeyStore
os.environ["MEMATTEST_PASSPHRASE"] = "pw"
d = pathlib.Path(tempfile.mkdtemp()) / "memory"; d.mkdir()
(d / "MEMORY.md").write_text("index", encoding="utf-8")
ks = FileKeyStore(d / ".memattest" / "key.sealed", b"pw")
m = MemAttest(d, keystore=ks); m.init()
ext = d.parent / "WATCHED.md"; ext.write_text("baseline", encoding="utf-8")
m.adopt([ext], reason="watch test")
print("clean:", m.verify().ok)
ext.write_text("tampered", encoding="utf-8")
r = m.verify(); print("after edit ok:", r.ok, "kinds:", [p["kind"] for p in r.problems])
m.unwatch([ext], reason="done"); print("after unwatch ok:", m.verify().ok)
'@ | .venv\Scripts\python -
```

Expected: `clean: True`; `after edit ok: False kinds: ['modified']`;
`after unwatch ok: True`.

- [ ] **Step 2: Full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass. Report the count.

- [ ] **Step 3: Live-log re-init (manual — the user runs this)**

This operates on the live installation and uses guarded commands (`adopt`),
so it is a manual step for the user, not the agent. Document it in the task
report for the user to run:

```powershell
$live = "C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory"
Remove-Item -Recurse -Force "$live/.memattest"
.venv\Scripts\python -c "import keyring; keyring.delete_password('memattest', (__import__('pathlib').Path('$live').resolve().as_posix()))"
.venv\Scripts\memattest init --memory-dir $live
.venv\Scripts\memattest verify --memory-dir $live
```

Then, in an interactive terminal, adopt-watch this project's live hook
settings file if desired:

```powershell
.venv\Scripts\memattest adopt --path "C:/source/agentmemoryvalidation/.claude/settings.local.json" --memory-dir $live --reason "watch live hook config"
```

Expected: re-init reports the adopted memory files, every new entry carries
`scope: "memory"`, verify is `OK`; the adopt-watch adds the settings file as
a watch entry. The agent does not run these — it records them here and the
user runs them. No commit (validation only).
```
