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


def _shape_error(where: str) -> MemAttestError:
    return MemAttestError(
        f"settings content has an unexpected shape at {where!r}; "
        "fix or remove the malformed entry by hand — the installer "
        "never rewrites content it cannot read"
    )


def _check_shape(existing: dict) -> None:
    """Validate the settings shapes plan_merge relies on before it touches
    anything, so a malformed-but-parseable settings file produces an
    operational error naming the offending key path instead of a raw
    AttributeError/TypeError escaping as an uncaught traceback."""
    if "hooks" in existing:
        hooks = existing["hooks"]
        if not isinstance(hooks, dict):
            raise _shape_error("hooks")
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                raise _shape_error(f"hooks.{event}")
            for group in groups:
                if not isinstance(group, dict):
                    raise _shape_error(f"hooks.{event}")
                if "hooks" in group:
                    group_hooks = group["hooks"]
                    if not isinstance(group_hooks, list) or not all(
                        isinstance(h, dict) for h in group_hooks
                    ):
                        raise _shape_error(f"hooks.{event}")
    if "permissions" in existing:
        permissions = existing["permissions"]
        if not isinstance(permissions, dict):
            raise _shape_error("permissions")
        if "deny" in permissions and not isinstance(permissions["deny"], list):
            raise _shape_error("permissions.deny")


def plan_merge(existing: dict, template: dict) -> tuple[dict, dict[str, str]]:
    """Merge the filled template into a settings dict.

    Hook entries whose command invokes a memattest 'hook' subcommand are
    updated in place; events with none get the template's matcher group
    appended. permissions.deny is a set-union. Everything else round-trips
    untouched. Returns (merged, actions) where actions maps each item to
    "added" / "updated" / "unchanged" for the ceremony plan display.
    """
    _check_shape(existing)
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


def run_install(args, make_ma, print_report) -> int:
    """The interactive ceremony. make_ma and print_report are injected from
    cli.py so this module never imports the CLI (or anything heavy)."""
    if not sys.stdin.isatty():
        print("error: install requires an interactive terminal", file=sys.stderr)
        return 2

    project = Path(args.project).resolve()
    if not project.is_dir():
        raise MemAttestError(f"project directory {project} does not exist")
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

    if args.memory_dir is not None and not memory_dir.is_dir():
        derivation = "given — does not exist yet; init will create it"

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
