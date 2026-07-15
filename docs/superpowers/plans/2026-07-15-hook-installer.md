# Claude Code Hook Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `memattest install` performs the full Claude Code onboarding in one interactive, adopt-style ceremony: derive or accept the memory directory, run `init` when needed, merge the filled `settings-snippet.json` template into the chosen project settings file (idempotent), and finish with a closing `verify`.

**Architecture:** A new module `src/memattest/integrations/claude_code/install.py` holds the pure pieces (slug derivation, binary discovery, template fill, settings merge, settings I/O) and the ceremony driver `run_install(args, make_ma, print_report)`. `cli.py` adds a thin `cmd_install` plus parser wiring (lazy import) and an `_INSTALL_INVOCATION` deny pattern in the PreToolUse guard beside the adopt one. The shipped template stays the single source of truth.

**Tech Stack:** Python ≥ 3.12 (stdlib only: `json`, `re`, `importlib.resources`), pytest. Spec: `docs/superpowers/specs/2026-07-15-hook-installer-design.md`.

## Global Constraints

- **venv only** — every `pytest` and `memattest` invocation uses `.venv\Scripts\...` (Windows dev machine). Branch: `hook-installer`.
- No new dependencies. Code changes confined to `src/memattest/integrations/claude_code/install.py` (new), `src/memattest/cli.py`, `src/memattest/integrations/claude_code/settings-snippet.json`, `pyproject.toml` (package-data only), tests, and docs.
- The hot `hook pre-tool-use` path imports nothing heavy: `install.py` is imported only inside `cmd_install`; `tests/test_cli.py::test_cli_module_import_stays_lightweight` must keep passing.
- Ceremony gating mirrors adopt: interactive TTY required, full plan printed before any write, typed confirmation (`install`), EOF/interrupt → `aborted`, exit 2. No `--yes` flag may be added.
- Exit codes: `0` success · `1` closing verify found problems · `2` operational (non-TTY, abort, missing binary, underivable memory directory, unparseable settings, init failure).
- The installer never touches the user-level `~/.claude` settings file; only the project-level file chosen in the ceremony.
- Wording, everywhere (docs, help strings, messages, commits): plain phrasing over fancy vocabulary; "backend keystore", never bare "backend"; never "load-bearing"; never the informal term for testing a tool on its own repository; no contrastive-reframe constructions.
- Commit messages: subject + body only, **no attribution/Co-Authored-By lines**.
- **Guard phrase discipline:** shell commands and commit messages must never contain the literal two-word phrase `memattest adopt`, paths shaped like `.claude/settings*.json`, or the hook-disabling flag name; **and, from Task 3 onward, never the literal two-word phrase `memattest install` either** — the editable install makes the new deny pattern live immediately on this machine. Write "the install command" in commit messages. (File content written via Edit/Write tools may contain any of these; the guard inspects commands, not edited text.)

## File Structure

- `src/memattest/integrations/claude_code/install.py` — new: pure helpers + ceremony driver (Tasks 1-2).
- `pyproject.toml` — package-data declaration so the JSON template ships in wheels (Task 1).
- `src/memattest/cli.py` — `cmd_install`, parser wiring (Task 2); `_INSTALL_INVOCATION` guard pattern (Task 3).
- `src/memattest/integrations/claude_code/settings-snippet.json` — install deny globs + one comment sentence (Task 3).
- `tests/test_claude_install.py` — new: unit + ceremony tests (Tasks 1-2).
- `tests/test_cli.py` — guard tests (Task 3).
- `README.md` — quickstart reorganization (Task 4).

---

### Task 1: Pure installer pieces — slug, binary, template, merge, settings I/O

**Files:**
- Create: `src/memattest/integrations/claude_code/install.py`
- Modify: `pyproject.toml` (add package-data after `[tool.setuptools.packages.find]`)
- Test: `tests/test_claude_install.py` (new)

**Interfaces:**
- Consumes: `MemAttestError` from `memattest.errors`; the shipped `settings-snippet.json`.
- Produces (module `memattest.integrations.claude_code.install`):
  - `project_slug(resolved_project_dir) -> str` — accepts any `PurePath`/str; caller resolves first.
  - `derive_memory_dir(project_dir: Path) -> Path` — `~/.claude/projects/<slug>/memory` (resolves the project; does NOT existence-check — the ceremony does).
  - `find_memattest_bin() -> Path` — console script next to `sys.executable`; `MemAttestError` if absent.
  - `load_filled_template(bin_path: Path, memory_dir: Path) -> dict` — placeholders filled with forward-slash absolute paths, `"//"` key removed.
  - `plan_merge(existing: dict, template: dict) -> tuple[dict, dict[str, str]]` — merged settings + per-item action map (`"added"`/`"updated"`/`"unchanged"`, plus a `"deny rules"` entry).
  - `read_settings(path: Path) -> dict` — `{}` when absent; `MemAttestError` on unparseable/non-object.
  - `write_settings(path: Path, data: dict) -> None` — `indent=2`, trailing newline, parent dir created.
  - Task 2 builds `run_install` on all of these.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_claude_install.py`:

```python
import json
from pathlib import Path, PurePosixPath, PureWindowsPath

import pytest

from memattest.errors import MemAttestError
from memattest.integrations.claude_code.install import (
    derive_memory_dir,
    load_filled_template,
    plan_merge,
    project_slug,
    read_settings,
    write_settings,
)


# --- slug derivation (Claude Code convention: non [A-Za-z0-9-] -> dash) ------
# Pinned against the observed real slug on this machine:
# C:\source\agentmemoryvalidation -> C--source-agentmemoryvalidation


def test_project_slug_windows_drive_path():
    assert project_slug(PureWindowsPath(r"C:\source\agentmemoryvalidation")) == \
        "C--source-agentmemoryvalidation"


def test_project_slug_posix_path():
    assert project_slug(PurePosixPath("/home/user/proj")) == "-home-user-proj"


def test_project_slug_dots_and_underscores_become_dashes():
    assert project_slug(PureWindowsPath(r"C:\repos\my.app_v2")) == "C--repos-my-app-v2"


def test_derive_memory_dir_lands_under_claude_projects(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    project = tmp_path / "proj"
    project.mkdir()
    derived = derive_memory_dir(project)
    assert derived == tmp_path / ".claude" / "projects" / project_slug(project.resolve()) / "memory"


# --- template fill ------------------------------------------------------------


def test_load_filled_template_fills_and_strips_comment(tmp_path):
    data = load_filled_template(Path("C:/repo/.venv/Scripts/memattest.exe"),
                                Path("C:/users/me/.claude/projects/x/memory"))
    assert "//" not in data
    assert set(data["hooks"]) == {"SessionStart", "PreToolUse", "PostToolUse"}
    for groups in data["hooks"].values():
        command = groups[0]["hooks"][0]["command"]
        assert "C:/repo/.venv/Scripts/memattest.exe" in command
        assert "C:/users/me/.claude/projects/x/memory" in command
        assert "<" not in command  # no placeholder survived
    assert any("adopt" in rule for rule in data["permissions"]["deny"])


# --- merge semantics -----------------------------------------------------------


def _template():
    def cmd(sub):
        return {"type": "command",
                "command": f"C:/bin/memattest hook {sub} --memory-dir C:/mem"}
    return {
        "hooks": {
            "SessionStart": [{"hooks": [cmd("session-start")]}],
            "PreToolUse": [{"matcher": "Bash|PowerShell|Write|Edit",
                            "hooks": [cmd("pre-tool-use")]}],
            "PostToolUse": [{"matcher": "Write|Edit", "hooks": [cmd("post-tool-use")]}],
        },
        "permissions": {"deny": ["rule-a", "rule-b"]},
    }


def test_plan_merge_into_empty_settings_adds_everything():
    merged, actions = plan_merge({}, _template())
    assert merged["hooks"] == _template()["hooks"]
    assert merged["permissions"]["deny"] == ["rule-a", "rule-b"]
    assert actions["SessionStart"] == "added"
    assert actions["deny rules"] == "2 added"


def test_plan_merge_preserves_unrelated_entries():
    existing = {
        "hooks": {"SessionStart": [{"hooks": [
            {"type": "command", "command": "other-tool --greet"}]}]},
        "permissions": {"deny": ["Bash(rm -rf *)"], "allow": ["Bash(ls*)"]},
        "model": "opus",
    }
    merged, actions = plan_merge(existing, _template())
    session_cmds = [h["command"] for g in merged["hooks"]["SessionStart"] for h in g["hooks"]]
    assert "other-tool --greet" in session_cmds  # untouched
    assert any("session-start" in c for c in session_cmds)  # ours appended
    assert "Bash(rm -rf *)" in merged["permissions"]["deny"]
    assert merged["permissions"]["allow"] == ["Bash(ls*)"]
    assert merged["model"] == "opus"
    assert actions["SessionStart"] == "added"


def test_plan_merge_updates_stale_memattest_command_in_place():
    stale = _template()
    stale["hooks"]["SessionStart"][0]["hooks"][0]["command"] = \
        "D:/old-venv/Scripts/memattest hook session-start --memory-dir D:/old"
    merged, actions = plan_merge(stale, _template())
    cmds = [h["command"] for g in merged["hooks"]["SessionStart"] for h in g["hooks"]]
    assert cmds == ["C:/bin/memattest hook session-start --memory-dir C:/mem"]
    assert actions["SessionStart"] == "updated"


def test_plan_merge_is_idempotent():
    merged1, _ = plan_merge({}, _template())
    merged2, actions = plan_merge(merged1, _template())
    assert merged2 == merged1
    assert actions["SessionStart"] == "unchanged"
    assert actions["deny rules"] == "unchanged"


# --- settings I/O ---------------------------------------------------------------


def test_read_settings_absent_file_is_empty(tmp_path):
    assert read_settings(tmp_path / "settings.json") == {}


def test_read_settings_unparseable_is_operational_error(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text("{ not json", encoding="utf-8")
    with pytest.raises(MemAttestError, match="settings.json"):
        read_settings(f)


def test_read_settings_non_object_is_operational_error(tmp_path):
    f = tmp_path / "settings.json"
    f.write_text('["a list"]', encoding="utf-8")
    with pytest.raises(MemAttestError, match="JSON object"):
        read_settings(f)


def test_write_settings_roundtrip_creates_parent(tmp_path):
    f = tmp_path / ".claude" / "settings.json"
    write_settings(f, {"hooks": {}})
    assert json.loads(f.read_text(encoding="utf-8")) == {"hooks": {}}
    assert f.read_text(encoding="utf-8").endswith("\n")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v`
Expected: all ERROR with `ImportError` (module has no such names yet).

- [ ] **Step 3: Write the implementation**

Create `src/memattest/integrations/claude_code/install.py`:

```python
"""Claude Code hook installer (spec 2026-07-15).

One interactive, adopt-style ceremony performs the full onboarding: derive
or accept the memory directory, run init when needed, merge the filled
settings-snippet template into the chosen project settings file, and finish
with a closing verify. Trust-sensitive by nature — the settings files
configure the hooks — so the ceremony requires a TTY and typed
confirmation, and the PreToolUse guard denies agent-run invocations.

Pure pieces first (unit-testable without a terminal); the ceremony driver
run_install is at the bottom.
"""
from __future__ import annotations

import json
import re
import sys
from importlib import resources
from pathlib import Path

from ...errors import MemAttestError

TEMPLATE_NAME = "settings-snippet.json"


def project_slug(resolved_project_dir) -> str:
    """Claude Code's project-directory slug: every character outside
    [A-Za-z0-9-] becomes a dash. Internal Claude Code convention — callers
    must existence-check the derived path, never trust it."""
    return re.sub(r"[^A-Za-z0-9-]", "-", str(resolved_project_dir))


def derive_memory_dir(project_dir: Path) -> Path:
    slug = project_slug(Path(project_dir).resolve())
    return Path.home() / ".claude" / "projects" / slug / "memory"


def find_memattest_bin() -> Path:
    scripts = Path(sys.executable).parent
    for name in ("memattest.exe", "memattest"):
        candidate = scripts / name
        if candidate.exists():
            return candidate
    raise MemAttestError(
        f"no memattest console script found next to {sys.executable}; "
        "install memattest into this environment first"
    )


def load_filled_template(bin_path: Path, memory_dir: Path) -> dict:
    raw = (resources.files("memattest.integrations.claude_code")
           .joinpath(TEMPLATE_NAME).read_text(encoding="utf-8"))
    raw = raw.replace("<MEMATTEST_BIN>", Path(bin_path).as_posix())
    raw = raw.replace("<MEMORY_DIR>", Path(memory_dir).as_posix())
    data = json.loads(raw)
    data.pop("//", None)  # documents the template, not the user's settings
    return data


def _is_memattest_hook(hook: dict) -> bool:
    command = hook.get("command", "")
    return "memattest" in command and " hook " in command


def plan_merge(existing: dict, template: dict) -> tuple[dict, dict[str, str]]:
    """Merge the filled template into a settings dict.

    Hook entries whose command invokes a memattest 'hook' subcommand are
    updated in place; events with none get the template's matcher group
    appended. permissions.deny is a set-union. Everything else round-trips
    untouched. Returns (merged, actions) where actions maps each item to
    "added" / "updated" / "unchanged" for the ceremony plan display.
    """
    merged = json.loads(json.dumps(existing))  # deep copy
    actions: dict[str, str] = {}
    hooks = merged.setdefault("hooks", {})
    for event, template_groups in template.get("hooks", {}).items():
        template_group = template_groups[0]
        template_command = template_group["hooks"][0]["command"]
        groups = hooks.setdefault(event, [])
        ours = [h for g in groups for h in g.get("hooks", []) if _is_memattest_hook(h)]
        if ours:
            changed = any(h.get("command") != template_command for h in ours)
            for h in ours:
                h["command"] = template_command
                h["type"] = "command"
            actions[event] = "updated" if changed else "unchanged"
        else:
            groups.append(json.loads(json.dumps(template_group)))
            actions[event] = "added"
    deny = merged.setdefault("permissions", {}).setdefault("deny", [])
    new_rules = [r for r in template.get("permissions", {}).get("deny", [])
                 if r not in deny]
    deny.extend(new_rules)
    actions["deny rules"] = f"{len(new_rules)} added" if new_rules else "unchanged"
    return merged, actions


def read_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MemAttestError(f"cannot read settings file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise MemAttestError(f"settings file {path} is not a JSON object")
    return data


def write_settings(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
```

In `pyproject.toml`, after the `[tool.setuptools.packages.find]` table, append:

```toml
[tool.setuptools.package-data]
memattest = ["integrations/claude_code/*.json"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v`
Expected: 13 PASS.

- [ ] **Step 5: Run the full suite and commit**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

```bash
git add src/memattest/integrations/claude_code/install.py pyproject.toml tests/test_claude_install.py
git commit -m "Add the pure pieces of the Claude Code hook installer

Slug derivation (the Claude Code project-directory convention, pinned
against the observed slug on this machine), console-script discovery,
template fill with the documentation key stripped, idempotent settings
merge that preserves unrelated entries, and safe settings I/O that
refuses to overwrite what it cannot parse. The template JSON now ships
as package data."
```

---

### Task 2: Ceremony driver and CLI wiring

**Files:**
- Modify: `src/memattest/integrations/claude_code/install.py` (append `run_install`)
- Modify: `src/memattest/cli.py` (add `cmd_install` after `cmd_prove`; add parser block after the `prove` subparser)
- Test: `tests/test_claude_install.py`

**Interfaces:**
- Consumes: Task 1's helpers; `_make_ma(args)` and `_print_report(report, count)` from `cli.py`, injected as parameters.
- Produces: `run_install(args, make_ma, print_report) -> int`; CLI surface `memattest install [--project DIR] [--memory-dir DIR] [--keystore ...]`. Task 4 documents it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_claude_install.py`:

```python
# --- ceremony (CLI-level, adopt-test style) -----------------------------------

import io

from memattest import cli


def _tty_stdin(monkeypatch, answers):
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))


def _project_and_memory(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    mem = tmp_path / "memory"
    mem.mkdir()
    (mem / "MEMORY.md").write_text("index", encoding="utf-8")
    return project, mem


def test_install_refuses_without_tty(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    fake = io.StringIO()
    fake.isatty = lambda: False
    monkeypatch.setattr("sys.stdin", fake)
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 2
    assert "interactive terminal" in capsys.readouterr().err
    assert not (project / ".claude").exists()


def test_install_eof_at_choice_aborts_cleanly(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)  # input() raises EOFError
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 2
    assert "aborted" in capsys.readouterr().err
    assert not (project / ".claude").exists()


def test_install_full_drive_through(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["1", "install"])
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "initialized; adopted 1 pre-existing file(s)" in out
    assert "OK 1 entries verified" in out
    assert "next Claude Code session" in out
    settings = json.loads(
        (project / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert "//" not in settings
    cmds = [h["command"]
            for groups in settings["hooks"].values()
            for g in groups for h in g["hooks"]]
    assert len(cmds) == 3
    assert all(mem.resolve().as_posix() in c for c in cmds)
    assert any("session-start" in c for c in cmds)
    assert any("adopt" in r for r in settings["permissions"]["deny"])


def test_install_local_choice_writes_local_file(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["2", "install"])
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    assert rc == 0
    assert (project / ".claude" / "settings.local.json").exists()
    assert not (project / ".claude" / "settings.json").exists()


def test_install_rerun_is_idempotent(tmp_path, monkeypatch, capsys):
    project, mem = _project_and_memory(tmp_path)
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    _tty_stdin(monkeypatch, ["1", "install"])
    assert cli.main(["install", "--project", str(project),
                     "--memory-dir", str(mem), "--keystore", "file"]) == 0
    first = (project / ".claude" / "settings.json").read_text(encoding="utf-8")
    _tty_stdin(monkeypatch, ["1", "install"])
    capsys.readouterr()
    rc = cli.main(["install", "--project", str(project),
                   "--memory-dir", str(mem), "--keystore", "file"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "already initialized" in out
    assert (project / ".claude" / "settings.json").read_text(encoding="utf-8") == first


def test_install_derived_memory_dir_missing_is_operational_error(tmp_path, monkeypatch, capsys):
    project = tmp_path / "proj"
    project.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "fakehome"))
    fake = io.StringIO()
    fake.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake)

    def fail_if_prompted(prompt=""):
        raise AssertionError("no prompt may be reached when derivation fails")

    monkeypatch.setattr("builtins.input", fail_if_prompted)
    rc = cli.main(["install", "--project", str(project)])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--memory-dir" in err and "does not exist" in err
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v -k install_`
Expected: all FAIL — argparse rejects the unknown `install` subcommand (`SystemExit`).

- [ ] **Step 3: Write the implementation**

Append to `src/memattest/integrations/claude_code/install.py`:

```python
def run_install(args, make_ma, print_report) -> int:
    """The interactive ceremony. make_ma and print_report are injected from
    cli.py so this module never imports the CLI (or anything heavy)."""
    if not sys.stdin.isatty():
        print("error: install requires an interactive terminal", file=sys.stderr)
        return 2

    project = Path(args.project).resolve()
    bin_path = find_memattest_bin()

    if args.memory_dir is not None:
        memory_dir = Path(args.memory_dir).resolve()
        derivation = "given"
    else:
        memory_dir = derive_memory_dir(project)
        derivation = "derived from the project path"
        if not memory_dir.is_dir():
            raise MemAttestError(
                f"derived memory directory {memory_dir} does not exist; pass "
                "--memory-dir explicitly, or run one Claude Code session in "
                "the project first so the harness creates it"
            )

    args.memory_dir = str(memory_dir)
    ma = make_ma(args)
    init_needed = not ma.initialized

    print("Write the memattest hooks to which settings file?")
    print("  1. shared  .claude/settings.json   (recommended)")
    print("  2. local   .claude/settings.local.json")
    try:
        choice = input("Choose 1 or 2 [1]: ").strip() or "1"
    except (EOFError, KeyboardInterrupt):
        choice = ""
    if choice not in ("1", "2"):
        print("aborted", file=sys.stderr)
        return 2
    name = "settings.json" if choice == "1" else "settings.local.json"
    target = project / ".claude" / name

    template = load_filled_template(bin_path, memory_dir)
    existing = read_settings(target)
    merged, actions = plan_merge(existing, template)

    print("\nmemattest install plan:")
    print(f"  project:     {project.as_posix()}")
    print(f"  memory dir:  {memory_dir.as_posix()} ({derivation})")
    print(f"  memattest:   {bin_path.as_posix()}")
    print(f"  settings:    {target.as_posix()}")
    print(f"  init:        {'will run first (not yet initialized)' if init_needed else 'already initialized, skipped'}")
    for item, action in actions.items():
        print(f"  {item}: {action}")
    try:
        confirmed = input("Type 'install' to confirm: ").strip() == "install"
    except (EOFError, KeyboardInterrupt):
        confirmed = False
    if not confirmed:
        print("aborted", file=sys.stderr)
        return 2

    if init_needed:
        entries = ma.init()
        print(f"initialized; adopted {len(entries)} pre-existing file(s)")
    try:
        write_settings(target, merged)
    except OSError as exc:
        raise MemAttestError(
            f"cannot write {target}: {exc}; the memory directory is "
            "initialized, so re-running install completes the wiring"
        ) from exc
    print(f"wrote hooks and deny rules to {target.as_posix()}")

    report = ma.verify()
    print_report(report, ma.store.count())
    if not report.ok:
        return report.exit_code
    print("hooks take effect at the next Claude Code session "
          "(Claude Code snapshots hook configuration at session start)")
    return 0
```

In `src/memattest/cli.py`, add after `cmd_prove`:

```python
def cmd_install(args) -> int:
    from .integrations.claude_code.install import run_install
    return run_install(args, _make_ma, _print_report)
```

And in `main()`, after the `prove` subparser block:

```python
    p = sub.add_parser("install",
                       help="wire the Claude Code hooks for a project (interactive only)")
    p.add_argument("--project", default=".",
                   help="project root whose .claude settings get wired "
                            "(default: current directory)")
    p.add_argument("--memory-dir",
                   help="memory directory; derived from the project path when omitted")
    p.add_argument("--keystore", choices=["keyring", "file"], default=None,
                   help="backend keystore used if init runs; recorded in the "
                            "log's config.toml")
    p.set_defaults(fn=cmd_install)
```

(Deliberately not `_add_common`: its `--memory-dir` default of `"."` would defeat derivation.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_claude_install.py -v`
Expected: all PASS (19 tests).

- [ ] **Step 5: Run the full suite and commit**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass, including `test_cli_module_import_stays_lightweight` (install.py is imported only inside `cmd_install`).

```bash
git add src/memattest/integrations/claude_code/install.py src/memattest/cli.py tests/test_claude_install.py
git commit -m "Add the install ceremony and CLI wiring

One interactive run performs the full onboarding: TTY check, upfront
resolution of the binary and the memory directory (derived from the
project path and existence-checked when not given), the shared-or-
local settings question with shared recommended, a printed plan of
every write, typed confirmation, init when needed, the idempotent
settings merge, and a closing verify whose outcome is the exit code.
cli.py contributes a thin cmd_install that injects _make_ma and
_print_report, keeping the module free of CLI imports."
```

---

### Task 3: Guard extension and template deny globs

**Files:**
- Modify: `src/memattest/cli.py` (pattern beside `_ADOPT_INVOCATION`; new branch in `cmd_hook_pre_tool_use`)
- Modify: `src/memattest/integrations/claude_code/settings-snippet.json` (deny globs + comment sentence)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: existing `_deny`, quote normalization, `_ADOPT_INVOCATION` structure in `cmd_hook_pre_tool_use`.
- Produces: `_INSTALL_INVOCATION` regex; deny branch between the adopt and settings checks; template deny list grows two globs. **From this task onward, no shell command or commit message may contain the literal two-word install phrase** (editable install makes the guard live immediately).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
def _assert_denied_for_install(capsys):
    out = json.loads(capsys.readouterr().out)
    hso = out["hookSpecificOutput"]
    assert hso["hookEventName"] == "PreToolUse"
    assert hso["permissionDecision"] == "deny"
    assert "install" in hso["permissionDecisionReason"]


def test_hook_pre_tool_use_denies_bare_install(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash", "memattest install --project .")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied_for_install(capsys)


def test_hook_pre_tool_use_denies_quoted_exe_install(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "PowerShell",
                  '& "C:/repo/.venv/Scripts/memattest.exe" install')
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    _assert_denied_for_install(capsys)


def test_hook_pre_tool_use_allows_pip_install_memattest(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash", "pip install memattest")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    assert capsys.readouterr().out.strip() == ""


def test_hook_pre_tool_use_allows_init(memdir, capsys, monkeypatch):
    _pre_tool_use(monkeypatch, "Bash", "memattest init --memory-dir .")
    assert run("hook", "pre-tool-use", *base(memdir)) == 0
    assert capsys.readouterr().out.strip() == ""
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v -k "install or allows_init"`
Expected: the two deny tests FAIL (no decision emitted today); the two allow tests PASS already — regression locks.

- [ ] **Step 3: Write the implementation**

In `src/memattest/cli.py`, directly below `_ADOPT_INVOCATION`:

```python
# The installer rewrites the hook configuration itself — the same trust
# surface the settings guard protects — so agent-run invocations are denied
# like adopt. 'pip install memattest' does not match: memattest must
# immediately precede install.
_INSTALL_INVOCATION = re.compile(r"\bmemattest(\.exe)?\s+install\b", re.IGNORECASE)
```

In `cmd_hook_pre_tool_use`, between the adopt branch and the settings branch:

```python
    elif _INSTALL_INVOCATION.search(normalized):
        _deny("memattest install rewrites the Claude Code hook configuration "
              "and may only be run by a human at an interactive terminal, "
              "not by the agent")
```

In `src/memattest/integrations/claude_code/settings-snippet.json`, extend the deny list:

```json
    "deny": [
      "Bash(*memattest adopt*)",
      "PowerShell(*memattest adopt*)",
      "Bash(*memattest install*)",
      "PowerShell(*memattest install*)"
    ]
```

and append one sentence to the `"//"` comment (before its final sentence): `The 'memattest install' command consumes this template — filling the placeholders and merging it into a project's settings file — and PreToolUse denies agent-run 'memattest install' invocations, which would otherwise rewrite this trust surface.`

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py tests/test_claude_install.py -v`
Expected: all PASS (the template-fill test tolerates the two extra deny rules — it asserts membership, not count).

- [ ] **Step 5: Run the full suite and commit**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

```bash
git add src/memattest/cli.py src/memattest/integrations/claude_code/settings-snippet.json tests/test_cli.py
git commit -m "Deny agent-run invocations of the install command

The installer rewrites the hook configuration itself, so the
PreToolUse guard treats it like adopt: bare, quoted, path-prefixed,
and .exe spellings are denied with the only-a-human message, while
'pip install memattest' stays allowed. The template's permission deny
globs gain the matching pair, and its comment notes the installer
consumes the template."
```

---

### Task 4: README quickstart reorganization

**Files:**
- Modify: `README.md` (the wiring paragraph beginning "To wire memattest into Claude Code, copy the hooks…" at ~line 121, and the PreToolUse description bullet at ~line 146)

**Interfaces:**
- Consumes: the CLI surface shipped in Task 2 and guard behavior from Task 3.
- Produces: README documents the installer as the primary path; manual wiring stays as the alternative.

- [ ] **Step 1: Insert the installer as the primary path**

Replace the paragraph `To wire memattest into Claude Code, copy the hooks and permission rules from … substituting two placeholders:` with:

```markdown
To wire memattest into Claude Code, run the installer from your project
directory and follow its prompts:

```bash
cd <YOUR_PROJECT>
memattest install
```

One interactive run performs the whole onboarding: it locates the
project's Claude Code memory directory (shown in the printed plan for you
to confirm; pass `--memory-dir` for custom layouts), runs `init` if the
directory isn't initialized yet, merges the three hooks and the permission
deny rules into the settings file you choose (shared is recommended;
existing unrelated entries are preserved, and re-running updates the
memattest entries in place), and finishes with a `verify`. Like `adopt`,
it only runs from an interactive terminal, prints its full plan, and asks
for typed confirmation before writing anything — and the `PreToolUse`
guard denies agent-run `memattest install` invocations, since the command
rewrites the same trust surface the guard protects.

Prefer to wire things by hand, or using another harness? Copy the hooks
and permission rules from
[`src/memattest/integrations/claude_code/settings-snippet.json`](src/memattest/integrations/claude_code/settings-snippet.json)
into your project's `.claude/settings.json`, substituting two placeholders:
```

(The existing two placeholder bullets and everything after them stand unchanged.)

- [ ] **Step 2: Update the PreToolUse description**

In the PreToolUse bullet ("…denies two kinds of proposed tool call. First, any command that invokes `memattest adopt`…"), change "two kinds" to "three kinds" and insert after the adopt sentence:

```markdown
  Second, any command that invokes `memattest install` — the installer
  rewrites the hook configuration, so only a human at a terminal may run
  it.
```

and change the following "Second," to "Third,".

- [ ] **Step 3: Sanity pass and commit**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

```bash
git add README.md
git commit -m "Document the installer as the primary wiring path

The quickstart now leads with the one-command interactive onboarding
and keeps the manual template procedure as the alternative for other
harnesses and custom layouts; the PreToolUse description covers the
third denied category."
```

---

### Task 5: Validation on this machine

**Files:** none (validation only).

**Interfaces:**
- Consumes: the installed editable package with Tasks 1-4 merged.
- Produces: evidence outside pytest. The interactive ceremony itself cannot be driven here (TTY check, and the live guard now denies the invocation) — it belongs to the user's manual pass on their test project.

- [ ] **Step 1: Slug derivation against the real machine**

```powershell
.venv\Scripts\python -c "from pathlib import Path; from memattest.integrations.claude_code.install import derive_memory_dir; p = derive_memory_dir(Path('C:/source/agentmemoryvalidation')); print(p); print(p.exists())"
```

Expected: prints `C:\Users\jlatino\.claude\projects\C--source-agentmemoryvalidation\memory` (path separators may render either way) and `True` — the derived path is this project's real, existing memory directory.

- [ ] **Step 2: Template fill from the installed package**

```powershell
.venv\Scripts\python -c "from pathlib import Path; from memattest.integrations.claude_code.install import find_memattest_bin, load_filled_template; t = load_filled_template(find_memattest_bin(), Path('C:/x/memory')); print(len(t['hooks']), len(t['permissions']['deny']), '//' in t)"
```

Expected: `3 4 False` — three hook events, four deny globs (adopt + install pairs), comment stripped.

- [ ] **Step 3: Live-log regression and full suite**

```powershell
.venv\Scripts\memattest verify --memory-dir C:/Users/jlatino/.claude/projects/C--source-agentmemoryvalidation/memory
.venv\Scripts\python -m pytest -q
```

Expected: `OK <n> entries verified` exit 0; all tests pass. Report results; no commit (nothing changed).
