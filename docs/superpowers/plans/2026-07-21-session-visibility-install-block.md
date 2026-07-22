# Visible Session Start and Install Duplicate-Hook Block Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make session-start success visible in the user's console, and stop the installer from creating a memattest hook registration that duplicates one already present in another settings scope.

**Architecture:** Two independent changes. Component 1 sets `systemMessage` unconditionally in `cmd_hook_session_start` so a clean verify reaches the user, not only the agent. Component 2 adds two pure helpers to the installer and a pre-write check in `run_install` that stops with exit 2 when another settings scope already holds a memattest hook.

**Tech Stack:** Python >= 3.12, pytest. Spec: `docs/superpowers/specs/2026-07-21-session-start-visible-and-install-warn-design.md`.

## Global Constraints

- **venv only** - every `pytest` and `memattest` invocation uses `.venv\Scripts\...` (Windows dev machine). Branch: `session-visibility-install-block`.
- No new dependencies. No on-disk log format change; scheme stays `"v1"`. Exit codes unchanged (the install block reuses the existing exit 2 for an aborted install).
- Wording, everywhere (docs, messages, comments, commits): plain phrasing; NO em-dashes (use single hyphens or commas); "backend keystore" never bare "backend"; never "load-bearing"; no contrastive-reframe constructions; "procedure" not "ceremony"; no metaphorical jargon.
- Commit messages: concise (short subject plus at most a one-or-two-sentence body); subject + body only, **no attribution lines**.
- Guard note: this session runs under the memattest PreToolUse guard. Shell commands and commit messages must NOT contain the two-word phrases `memattest adopt` / `memattest install` / `memattest unwatch`, `.claude/settings*.json`-shaped paths, or the hook-disabling flag name. Refer to the tool as "the installer" in commit messages. Editing `README.md` and running `pytest` by path are fine; test code that passes `"install"` as a Python list element is fine (it is not the two-word shell phrase).

## File Structure

- `src/memattest/cli.py` - `cmd_hook_session_start` sets `systemMessage` unconditionally (Task 1).
- `src/memattest/integrations/claude_code/install.py` - new `_has_memattest_hook` and `other_scope_hook_conflicts` helpers, the pre-write conflict check in `run_install`, and the "ceremony" -> plain wording tidy (Task 2).
- `tests/test_cli.py` - flip the clean-session assertion (Task 1).
- `tests/test_claude_install.py` - hermetic-home refactor of `_project_and_memory`, helper tests, and the block integration test (Task 2).
- `README.md` - session-start hook wording correction (Task 1) and the install-block note (Task 2).

---

### Task 1: Visible success at session start

**Files:**
- Modify: `src/memattest/cli.py` (`cmd_hook_session_start`, currently lines 256-279)
- Modify: `tests/test_cli.py` (`test_hook_session_start_clean_emits_context_json`, currently line 188-196)
- Modify: `README.md` (session-start hook description, lines 157-163)

**Interfaces:**
- Produces: `cmd_hook_session_start` emits hook JSON with `systemMessage` set on every session start (one-line `OK` on a clean log, full report on a problem). No signature change.

- [ ] **Step 1: Update the clean-session test to expect a visible success message**

In `tests/test_cli.py`, replace the last two lines of `test_hook_session_start_clean_emits_context_json` (currently line 195-196):

```python
    assert "OK 1 entries verified" in hso["additionalContext"]
    assert "systemMessage" not in out  # quiet on success
```

with:

```python
    assert "OK 1 entries verified" in hso["additionalContext"]
    assert "OK 1 entries verified" in out["systemMessage"]  # user sees success too
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py::test_hook_session_start_clean_emits_context_json -v`
Expected: FAIL - `out` has no `systemMessage` key on a clean session (KeyError), because the current code sets it only on failure.

- [ ] **Step 3: Set systemMessage unconditionally**

In `src/memattest/cli.py`, replace the whole body of `cmd_hook_session_start` (currently lines 256-279):

```python
def cmd_hook_session_start(args) -> int:
    # Claude Code injects a SessionStart hook's stdout into agent context only
    # on exit 0, so the outcome must be delivered as hook JSON, never as a
    # non-zero exit. That includes operational failures like a deleted
    # .memattest directory, which would otherwise leave the agent silently
    # trusting unguarded memory. systemMessage carries the result to the
    # user's console on every session start, so a healthy session is visibly
    # distinct from one where the hook was removed.
    try:
        ma = _make_ma(args)
        report = ma.verify()
        text = "memattest: " + "\n".join(_report_lines(report, ma.store.count()))
    except MemAttestError as exc:
        text = f"memattest: verification could not run: {exc}"
    out = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text,
        },
        "systemMessage": text,
    }
    print(json.dumps(out))
    return 0
```

This drops the now-unused `ok` variable and the `if not ok:` guard; `systemMessage` is always present.

- [ ] **Step 4: Run the session-start tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v -k session_start`
Expected: PASS - the clean test now finds `systemMessage`, and the tampered / uninitialized / key-missing / invalid-seed / corrupted-config tests (which already assert `systemMessage`) stay green.

- [ ] **Step 5: Correct the README hook description**

In `README.md`, replace the `SessionStart` bullet (lines 157-163):

```
- A `SessionStart` hook runs `memattest hook session-start`, which verifies
  the log and delivers the result as hook JSON: `additionalContext` places
  the report in the agent's context, and on failure `systemMessage` shows
  the same report to you, untruncated. The subcommand always exits 0 by
  design, because Claude Code discards a SessionStart hook's stdout on a
  non-zero exit — wiring plain `memattest verify` here alerts the user but
  leaves the agent, the party about to act on the memory, uninformed.
```

with:

```
- A `SessionStart` hook runs `memattest hook session-start`, which verifies
  the log and delivers the result as hook JSON: `additionalContext` places
  the report in the agent's context, and `systemMessage` shows the result
  in your console on every session start (a one-line `OK N entries verified`
  on a clean log, the full report on a problem). Seeing that line each
  session is how you tell a healthy session from one where the hook was
  removed. The subcommand always exits 0 by design, because Claude Code
  discards a SessionStart hook's stdout on a non-zero exit; wiring plain
  `memattest verify` here alerts the user but leaves the agent, the party
  about to act on the memory, uninformed.
```

- [ ] **Step 6: Commit**

```bash
git add src/memattest/cli.py tests/test_cli.py README.md
git commit -m "Show session-start verify result to the user

cmd_hook_session_start now sets systemMessage on every session start, not
only on failure, so a clean 'OK N entries verified' reaches the console and
a healthy session is visibly distinct from one where the hook was removed."
```

---

### Task 2: Block install on a cross-scope duplicate registration

**Files:**
- Modify: `src/memattest/integrations/claude_code/install.py` (new helpers; conflict check in `run_install`; "ceremony" -> plain wording)
- Modify: `tests/test_claude_install.py` (hermetic-home refactor; helper tests; block integration test)
- Modify: `README.md` (install-block note in the hook-configuration hardening bullet)

**Interfaces:**
- Consumes: `_is_memattest_hook(hook: dict) -> bool` and `read_settings(path: Path) -> dict` (existing, install.py:60 and :137).
- Produces:
  - `_has_memattest_hook(settings: dict) -> bool` - True if any hook in a settings dict's `hooks` is a memattest hook; tolerant of malformed shapes (returns False rather than raising).
  - `other_scope_hook_conflicts(project: Path, target: Path) -> list[Path]` - the settings scopes other than `target` (the two project files and the user-level `~/.claude/settings.json`) that contain a memattest hook; skips the target and any scope it cannot read.

- [ ] **Step 1: Write the failing pure-helper tests**

Append to `tests/test_claude_install.py`:

```python
def _memattest_settings(command="/x/memattest hook post-tool-use --memory-dir /m"):
    return {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}}


def test_has_memattest_hook_detects_and_rejects():
    from memattest.integrations.claude_code.install import _has_memattest_hook
    assert _has_memattest_hook(_memattest_settings()) is True
    assert _has_memattest_hook({"hooks": {}}) is False
    assert _has_memattest_hook({}) is False
    # A non-memattest command is not a match.
    assert _has_memattest_hook(
        {"hooks": {"PostToolUse": [{"hooks": [{"command": "prettier --write"}]}]}}
    ) is False
    # Malformed shapes are tolerated (no raise, treated as no match).
    assert _has_memattest_hook({"hooks": "oops"}) is False
    assert _has_memattest_hook({"hooks": {"PostToolUse": "oops"}}) is False


def test_other_scope_hook_conflicts_finds_other_scopes(tmp_path, monkeypatch):
    from memattest.integrations.claude_code.install import (
        other_scope_hook_conflicts, write_settings,
    )
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    target = project / ".claude" / "settings.json"
    other_local = project / ".claude" / "settings.local.json"
    user = home / ".claude" / "settings.json"
    write_settings(other_local, _memattest_settings())
    write_settings(user, _memattest_settings())
    conflicts = other_scope_hook_conflicts(project, target)
    assert set(conflicts) == {other_local, user}


def test_other_scope_hook_conflicts_ignores_target_and_tolerates_bad_scope(tmp_path, monkeypatch):
    from memattest.integrations.claude_code.install import (
        other_scope_hook_conflicts, write_settings,
    )
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    target = project / ".claude" / "settings.json"
    # The target itself holding a memattest hook is an in-place update, not a conflict.
    write_settings(target, _memattest_settings())
    # A malformed other scope must be skipped, not raise.
    (project / ".claude" / "settings.local.json").write_text("{ not json", encoding="utf-8")
    assert other_scope_hook_conflicts(project, target) == []
```

- [ ] **Step 2: Run the helper tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v -k "has_memattest_hook or other_scope"`
Expected: FAIL with `ImportError` / `AttributeError` - `_has_memattest_hook` and `other_scope_hook_conflicts` do not exist yet.

- [ ] **Step 3: Add the two helpers**

In `src/memattest/integrations/claude_code/install.py`, add `_has_memattest_hook` immediately after `_is_memattest_hook` (after line 62):

```python
def _has_memattest_hook(settings: dict) -> bool:
    """True if any hook in a settings dict is a memattest hook. Defensive:
    a malformed hooks shape is treated as no match, never raised, because
    this scans scopes the installer does not own."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return False
    for groups in hooks.values():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for hook in group.get("hooks", []) or []:
                if isinstance(hook, dict) and _is_memattest_hook(hook):
                    return True
    return False
```

Then add `other_scope_hook_conflicts` immediately after `read_settings` (after line 146):

```python
def other_scope_hook_conflicts(project: Path, target: Path) -> list[Path]:
    """Settings scopes other than target that already hold a memattest hook.

    Claude Code merges hooks across scopes, so a memattest hook in another
    scope would fire in addition to the one being installed. The scan is
    advisory: a scope it cannot read is skipped, never fatal."""
    candidates = [
        project / ".claude" / "settings.json",
        project / ".claude" / "settings.local.json",
        Path.home() / ".claude" / "settings.json",
    ]
    conflicts: list[Path] = []
    for path in candidates:
        if path == target:
            continue
        try:
            settings = read_settings(path)
        except MemAttestError:
            continue
        if _has_memattest_hook(settings):
            conflicts.append(path)
    return conflicts
```

- [ ] **Step 4: Run the helper tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v -k "has_memattest_hook or other_scope"`
Expected: PASS.

- [ ] **Step 5: Make the install tests hermetic against the real home directory**

`other_scope_hook_conflicts` reads `~/.claude/settings.json`, so every test that drives `run_install` must control `Path.home()` or it depends on the developer's real home. Centralize this in the shared helper. In `tests/test_claude_install.py`, replace `_project_and_memory` (lines 177-183):

```python
def _project_and_memory(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    mem = tmp_path / "memory"
    mem.mkdir()
    (mem / "MEMORY.md").write_text("index", encoding="utf-8")
    return project, mem
```

with a version that points `Path.home()` at a hermetic empty home:

```python
def _project_and_memory(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    project = tmp_path / "proj"
    project.mkdir()
    mem = tmp_path / "memory"
    mem.mkdir()
    (mem / "MEMORY.md").write_text("index", encoding="utf-8")
    return project, mem
```

Then update every caller to pass `monkeypatch`. There are seven, each currently reading `project, mem = _project_and_memory(tmp_path)`: `test_install_refuses_without_tty`, `test_install_eof_at_choice_aborts_cleanly`, `test_install_full_drive_through`, `test_install_local_choice_writes_local_file`, `test_install_rerun_is_idempotent`, `test_install_watches_the_settings_file`, and `test_install_does_not_watch_local_settings`. Change each to `project, mem = _project_and_memory(tmp_path, monkeypatch)`. Every one of these tests already takes `monkeypatch` in its signature.

One more test drives the installer past the scan but builds its project inline instead of through the helper: `test_install_plan_flags_absent_given_memory_dir` (it constructs `project = tmp_path / "proj"` directly). Give it a hermetic home too by adding this line right after `project.mkdir()`:

```python
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "fakehome"))
```

(`tmp_path / "fakehome"` does not exist, so the user-level scope read returns no settings and no conflict. The remaining run_install tests either fail before the scan or already monkeypatch `Path.home`.)

- [ ] **Step 6: Run the full install-test file to confirm the refactor is green**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -q`
Expected: PASS - the hermetic-home refactor is transparent (the real home is not read; the empty tmp home yields no conflicts).

- [ ] **Step 7: Write the failing block integration test**

Append to `tests/test_claude_install.py`:

```python
def test_install_blocks_on_cross_scope_duplicate(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path, monkeypatch)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    # A memattest hook already lives in the local scope; installing into the
    # shared scope would duplicate it, so install must stop.
    (project / ".claude").mkdir(exist_ok=True)
    write_settings(project / ".claude" / "settings.local.json", _memattest_settings())
    _tty_stdin(monkeypatch, ["1"])  # choose shared settings.json; blocked before confirm
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "already registered" in err
    assert "settings.local.json" in err
    # Nothing was written or initialized.
    assert not (project / ".claude" / "settings.json").exists()
    assert not (mem / ".memattest").exists()
```

`write_settings` is already imported at the top of the test file (line 7-14 import block); if it is not in scope here, import it inside the test as the helper tests do.

- [ ] **Step 8: Run the block test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py::test_install_blocks_on_cross_scope_duplicate -v`
Expected: FAIL - with no conflict check, install proceeds past the choice prompt and then calls `input()` for the confirm step, raising `StopIteration` (only one answer was queued), so `rc` is not 2 and no "already registered" message appears.

- [ ] **Step 9: Add the conflict check to run_install**

In `src/memattest/integrations/claude_code/install.py`, in `run_install`, insert the check right after the target is chosen and before the template is loaded. The existing lines are:

```python
    name = "settings.json" if choice == "1" else "settings.local.json"
    target = project / ".claude" / name

    template = load_filled_template(bin_path, memory_dir)
```

Insert between `target = ...` and `template = ...`:

```python
    conflicts = other_scope_hook_conflicts(project, target)
    if conflicts:
        listed = ", ".join(p.as_posix() for p in conflicts)
        print(
            f"error: memattest hooks are already registered in {listed}. "
            "Claude Code merges hooks across settings files, so installing "
            "them here too would make each memattest hook fire more than once "
            "per event. Remove the memattest hooks from that file first, or "
            "re-run and target it to update in place, then install again.",
            file=sys.stderr,
        )
        return 2
```

This runs before the plan display, the typed confirmation, `init`, and the settings write, so a blocked install mutates nothing.

- [ ] **Step 10: Run the block test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py::test_install_blocks_on_cross_scope_duplicate -v`
Expected: PASS.

- [ ] **Step 11: Replace "ceremony" with plain wording in install.py**

In `src/memattest/integrations/claude_code/install.py`, replace each occurrence of "ceremony" (lines 3, 7, 10, 109, 155) with plain wording:

- Line 3: `One interactive, adopt-style ceremony performs the full onboarding: derive` -> `One interactive, adopt-style procedure performs the full onboarding: derive`
- Line 7: `configure the hooks — so the ceremony requires a TTY and typed` -> `configure the hooks, so the procedure requires a TTY and typed` (also drops the em-dash)
- Line 10: `Pure pieces first (unit-testable without a terminal); the ceremony driver` -> `Pure pieces first (unit-testable without a terminal); the procedure driver`
- Line 109: `"added" / "updated" / "unchanged" for the ceremony plan display.` -> `"added" / "updated" / "unchanged" for the install plan display.`
- Line 155: `"""The interactive ceremony. make_ma and print_report are injected from` -> `"""The interactive install procedure. make_ma and print_report are injected from`

Also in `tests/test_claude_install.py`, the section comment at line 162 reads `# --- ceremony (CLI-level, adopt-test style) -----------------------------------`; change `ceremony` to `install procedure`.

- [ ] **Step 12: Add the install-block note to the README**

In `README.md`, in the "Treat the hook configuration as part of the trust surface" hardening bullet, immediately after the sentence that ends `turns off every hook at the next session start.` (line 439), add a new sentence:

```
  The installer refuses to add memattest hooks to a settings file when they
  already exist in another scope, so it will not silently create the
  duplicate registration that makes each hook fire more than once per event.
```

- [ ] **Step 13: Run the full install-test file and the CLI tests**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py tests/test_cli.py -q`
Expected: all pass.

- [ ] **Step 14: Commit**

```bash
git add src/memattest/integrations/claude_code/install.py tests/test_claude_install.py README.md
git commit -m "Block the installer on a cross-scope duplicate hook

run_install now stops with exit 2 before writing anything when a memattest
hook already exists in another settings scope, so it cannot create a
duplicate registration that fires the hooks more than once per event."
```

---

### Task 3: Validation on this machine

**Files:** none (validation only).

**Interfaces:**
- Consumes: Tasks 1-2 merged into the working tree.
- Produces: evidence outside the suite.

- [ ] **Step 1: Full suite is green**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all tests pass. Report the count.

- [ ] **Step 2: Session start shows the OK line to the user**

Run: `.venv\Scripts\memattest hook session-start --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory`
Expected: the printed JSON has a top-level `systemMessage` containing `memattest: OK <n> entries verified`, and `hookSpecificOutput.additionalContext` contains the same line. Exit 0.

- [ ] **Step 3: Confirm the live log still verifies**

Run: `.venv\Scripts\memattest verify --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory`
Expected: `OK <n> entries verified`, exit 0. No commit (nothing changed).
