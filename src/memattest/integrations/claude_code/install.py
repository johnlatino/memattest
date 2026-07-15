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
