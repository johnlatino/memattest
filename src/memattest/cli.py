from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from .errors import MemAttestError

if TYPE_CHECKING:
    from .core import MemAttest, VerifyReport

# The signing/verification machinery (core, identity, merkle) is imported
# lazily inside the functions that need it: 'hook pre-tool-use' runs on every
# shell command of a session and must not pay the cryptography import.


def _derive_memory_dir(paths: list[Path]) -> Path:
    from .core import STATE_DIR_NAME

    # Strictly the files' containing folder — deliberately no ancestor search,
    # so a typo can never silently land in some other guarded directory.
    parents = {p.resolve().parent for p in paths}
    if len(parents) != 1:
        raise MemAttestError("paths are in different directories; pass --memory-dir explicitly")
    (parent,) = parents
    if not (parent / STATE_DIR_NAME).is_dir():
        raise MemAttestError(
            f"{parent} is not an initialized memory directory. For a memory "
            "file, run init there first; for a watched external file, pass "
            "--memory-dir or --project."
        )
    return parent


def _memory_dir_from_flags(args) -> str | None:
    """Resolve --memory-dir / --project for adopt and unwatch.

    Returns the memory-dir string, or None when neither flag was given (the
    caller decides the fallback). Passing both is a usage error; a --project
    whose derived memory directory does not exist is an operational error.
    """
    project = getattr(args, "project", None)
    if project is not None and args.memory_dir is not None:
        raise MemAttestError("pass --memory-dir or --project, not both")
    if args.memory_dir is not None:
        return args.memory_dir
    if project is not None:
        from .integrations.claude_code.install import derive_memory_dir
        derived = derive_memory_dir(Path(project))
        if not derived.is_dir():
            raise MemAttestError(
                f"derived memory directory {derived} does not exist; pass "
                "--memory-dir explicitly, or run a Claude Code session in the "
                "project first so the directory exists"
            )
        return str(derived)
    return None


def _make_ma(args) -> MemAttest:
    # Lazily import the core components because the 'hook pre-tool-use' runs on every shell command.
    # Don't want to slow down command execution when it's not needed.    
    from .core import STATE_DIR_NAME, MemAttest
    from .identity import FileKeyStore, KeyringKeyStore
    from .per_log_config import load_config

    memory_dir = Path(args.memory_dir)
    state_dir = memory_dir / STATE_DIR_NAME
    config = load_config(state_dir)
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
        ks = FileKeyStore(state_dir / "key.sealed",
                          (passphrase or "").encode("utf-8"))
    else:
        ks = KeyringKeyStore()
    return MemAttest(memory_dir, keystore=ks)


def _report_lines(report: VerifyReport, entry_count: int) -> list[str]:
    if report.ok:
        return [f"OK {entry_count} entries verified"]
    lines = [
        f"PROBLEM kind={p['kind']} path={p['path']} detail={p['detail']} last_valid={p['last_valid_index']}"
        for p in report.problems
    ]
    lines.append(
        "Remediation: restore the affected files and re-run verify, or run "
        "'memattest adopt --path <file> --reason ...' (repeat --path per "
        "file) to accept the current state."
    )
    return lines


def _print_report(report: VerifyReport, entry_count: int) -> None:
    for line in _report_lines(report, entry_count):
        print(line)
    if not report.ok:
        # One concise alert on stderr: harnesses that surface only the stderr
        # of a failing hook (settings still running plain 'verify' at
        # SessionStart) get an untruncated pointer to the full stdout report.
        print(f"memattest: verification FAILED: {len(report.problems)} problem(s) found — "
              "run 'memattest verify' for the full report", file=sys.stderr)


def cmd_init(args) -> int:
    ma = _make_ma(args)
    entries = ma.init()
    print(f"initialized; adopted {len(entries)} pre-existing file(s)")
    return 0


def cmd_record(args) -> int:
    if args.memory_dir is None:
        args.memory_dir = _derive_memory_dir([Path(args.path)])
    ma = _make_ma(args)
    entry = ma.record(Path(args.path), op=args.op)
    print(f"recorded {entry['op']} of {entry['path']} at entry {entry['index']}")
    return 0


def cmd_verify(args) -> int:
    ma = _make_ma(args)
    report = ma.verify(key_check=not args.no_key_check)
    _print_report(report, ma.store.count())
    return report.exit_code


def cmd_adopt(args) -> int:
    if not sys.stdin.isatty():
        print("error: adopt requires an interactive terminal", file=sys.stderr)
        return 2
    resolved = _memory_dir_from_flags(args)
    if resolved is not None:
        args.memory_dir = resolved
    elif args.memory_dir is None:
        args.memory_dir = str(_derive_memory_dir([Path(p) for p in args.paths]))
    ma = _make_ma(args)
    if not ma.initialized:
        raise MemAttestError("not initialized; run init first")
    print(f"About to adopt {len(args.paths)} file(s) as trusted "
          f"in {Path(args.memory_dir).resolve()}. Reason: {args.reason}")
    try:
        confirmed = input("Type 'adopt' to confirm: ").strip() == "adopt"
    except (EOFError, KeyboardInterrupt):
        confirmed = False
    if not confirmed:
        print("aborted", file=sys.stderr)
        return 2
    ma.adopt([Path(p) for p in args.paths], reason=args.reason)
    print(f"adopted {len(args.paths)} file(s)")
    return 0


def cmd_unwatch(args) -> int:
    if not sys.stdin.isatty():
        print("error: unwatch requires an interactive terminal", file=sys.stderr)
        return 2
    resolved = _memory_dir_from_flags(args)
    if resolved is None:
        raise MemAttestError("pass --memory-dir or --project to say which log to unwatch from")
    args.memory_dir = resolved
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


def cmd_log(args) -> int:
    ma = _make_ma(args)
    for e in ma.store.load_all():
        print(json.dumps(e, sort_keys=True))
    return 0


def cmd_prove(args) -> int:
    from . import merkle

    ma = _make_ma(args)
    leaves = ma.store.leaf_bytes()
    if args.index is not None:
        if not (0 <= args.index < len(leaves)):
            raise MemAttestError(f"--index must be in [0, {len(leaves) - 1}]")
        proof = merkle.inclusion_proof(args.index, leaves)
    elif args.old_size is not None:
        if not (0 <= args.old_size <= len(leaves)):
            raise MemAttestError(f"--old-size must be in [0, {len(leaves)}]")
        proof = merkle.consistency_proof(args.old_size, leaves)
    else:
        raise MemAttestError("prove requires --index or --old-size")
    print(json.dumps([h.hex() for h in proof]))
    return 0


def cmd_install(args) -> int:
    from .integrations.claude_code.install import run_install
    return run_install(args, _make_ma, _print_report)


def _read_hook_payload() -> dict:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise MemAttestError(f"malformed hook payload on stdin: {exc}") from exc
    if not isinstance(payload, dict):
        raise MemAttestError("malformed hook payload on stdin: expected a JSON object")
    return payload


def cmd_hook_post_tool_use(args) -> int:
    payload = _read_hook_payload()
    file_path = (payload.get("tool_input") or {}).get("file_path")
    if not file_path:
        return 0
    target = Path(file_path).resolve()
    memory_dir = Path(args.memory_dir).resolve()
    try:
        rel = target.relative_to(memory_dir)
    except ValueError:
        return 0  # write outside the guarded directory: not our concern
    if ".memattest" in rel.parts or not target.exists():
        return 0
    _make_ma(args).record(target)
    return 0


def cmd_hook_session_start(args) -> int:
    # Claude Code injects a SessionStart hook's stdout into agent context only
    # on exit 0, so the outcome must be delivered as hook JSON, never as a
    # non-zero exit — including operational failures like a deleted
    # .memattest directory, which would otherwise leave the agent silently
    # trusting unguarded memory.
    try:
        ma = _make_ma(args)
        report = ma.verify()
        ok = report.ok
        text = "memattest: " + "\n".join(_report_lines(report, ma.store.count()))
    except MemAttestError as exc:
        ok = False
        text = f"memattest: verification could not run: {exc}"
    out: dict = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": text,
        }
    }
    if not ok:
        out["systemMessage"] = text
    print(json.dumps(out))
    return 0


# Matches an adopt invocation even when the executable is quoted, path-prefixed,
# or named memattest.exe. Quotes are stripped first so `"...\memattest" adopt`
# still matches. Renaming the binary defeats this; the hook is defense-in-depth.
_ADOPT_INVOCATION = re.compile(r"\bmemattest(\.exe)?\s+adopt\b", re.IGNORECASE)

# The installer rewrites the hook configuration itself — the same trust
# surface the settings guard protects — so agent-run invocations are denied
# like adopt. 'pip install memattest' does not match: memattest must
# immediately precede install.
_INSTALL_INVOCATION = re.compile(r"\bmemattest(\.exe)?\s+install\b", re.IGNORECASE)

# Deny unwatch from agent-run invocation because it removes tamper-detection coverage.
_UNWATCH_INVOCATION = re.compile(r"\bmemattest(\.exe)?\s+unwatch\b", re.IGNORECASE)

# The Claude Code settings files configure the memattest hooks themselves, and
# 'disableAllHooks' silences every hook from any settings scope — an agent
# that can touch either can un-hook memattest for its next session. Matched
# broadly (fail-closed), like the adopt guard.
_SETTINGS_TARGET = re.compile(r"\.claude[/\\]settings(\.local)?\.json|disableAllHooks",
                              re.IGNORECASE)


def _deny(reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))


def cmd_hook_pre_tool_use(args) -> int:
    payload = _read_hook_payload()
    tool_input = payload.get("tool_input") or {}

    file_path = tool_input.get("file_path")
    if file_path and _SETTINGS_TARGET.search(str(file_path)):
        _deny("the Claude Code settings files configure the memattest hooks "
              "and may only be edited by a human, not the agent")
        return 0

    command = tool_input.get("command")
    if not command:
        return 0
    normalized = command.replace('"', " ").replace("'", " ")
    if _ADOPT_INVOCATION.search(normalized):
        _deny("memattest adopt may only be run by a human at an "
              "interactive terminal, not by the agent")
    elif _INSTALL_INVOCATION.search(normalized):
        _deny("memattest install rewrites the Claude Code hook configuration "
              "and may only be run by a human at an interactive terminal, "
              "not by the agent")
    elif _UNWATCH_INVOCATION.search(normalized):
        _deny("memattest unwatch narrows tamper-detection coverage and may "
              "only be run by a human at an interactive terminal, not by "
              "the agent")
    elif _SETTINGS_TARGET.search(normalized):
        _deny("this command touches the Claude Code settings files (or the "
              "hook-disabling flag) that configure the memattest hooks; "
              "only a human may change them")
    return 0


def _add_common(p: argparse.ArgumentParser, *, memory_dir_default: str | None = ".") -> None:
    p.add_argument("--memory-dir", default=memory_dir_default,
                   help="the guarded memory directory (holds the .memattest "
                        "state); required unless derivable from the path")
    p.add_argument("--keystore", choices=["keyring", "file"], default=None,
                   help="backend keystore; recorded in the log's config.toml "
                        "at init, so it is only needed before init or for "
                        "pre-config logs")


class _HelpFormatter(argparse.HelpFormatter):
    """Wrap the description like the default formatter, but leave the epilog
    (our command-line examples, which start with "Example") unwrapped."""

    def _fill_text(self, text, width, indent):
        if text.lstrip().startswith("Example"):
            return "".join(indent + line for line in text.splitlines(keepends=True))
        return super()._fill_text(text, width, indent)


class _HintingParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        if message.startswith("unrecognized arguments:"):
            message += ("\nhint: the memory directory is passed as "
                        "'--memory-dir <path>' and files as '--path <file>', "
                        "not as positional arguments")
        super().error(message)


def main(argv: list[str] | None = None) -> int:
    parser = _HintingParser(prog="memattest",
                            description="Tamper-evident agent memory (append-only Merkle log)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="initialize and baseline existing memories",
                       description="Initialize a memory directory: generate the "
                       "signing key, seal it in the backend keystore, and adopt "
                       "the existing files as the trusted baseline.",
                       epilog="Example:\n  memattest init --memory-dir <MEMORY_DIR>",
                       formatter_class=_HelpFormatter)
    _add_common(p)
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("record", help="append one write/delete event",
                       description="Append a signed write or delete event for one "
                       "memory file (the PostToolUse hook calls this).",
                       epilog="Example:\n  memattest record --path <MEMORY_DIR>/notes.md",
                       formatter_class=_HelpFormatter)
    _add_common(p, memory_dir_default=None)  # derived from --path's folder when omitted
    p.add_argument("--path", required=True, help="the memory file that changed")
    p.add_argument("--op", choices=["write", "delete"], default="write",
                   help="whether the file was written or deleted (default: write)")
    p.set_defaults(fn=cmd_record)

    p = sub.add_parser("verify", help="run the integrity checks",
                       description="Recompute the Merkle tree, check the signed "
                       "tree heads and the signing-key cross-check, and compare "
                       "the derived state against the files on disk.",
                       epilog="Example:\n  memattest verify --memory-dir <MEMORY_DIR>",
                       formatter_class=_HelpFormatter)
    _add_common(p)
    p.add_argument("--no-key-check", action="store_true",
                   help="skip the signing-key cross-check against the backend "
                        "keystore (for auditing a copied log on a machine "
                        "without the key)")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("adopt", help="bless out-of-band changes (interactive only)",
                       description="Bless the current content of one or more files "
                       "as trusted, appending a signed adopt entry. A path outside "
                       "the memory directory is recorded as a watched file.",
                       epilog="Example:\n"
                       "  memattest adopt --path <MEMORY_DIR>/notes.md --reason \"manual edit\"\n"
                       "Example, to watch an external file:\n"
                       "  memattest adopt --path <PROJECT>/CLAUDE.md --project <PROJECT> --reason \"baseline\"",
                       formatter_class=_HelpFormatter)
    _add_common(p, memory_dir_default=None)  # derived from the paths' folder when omitted
    p.add_argument("--path", action="append", required=True, dest="paths",
                   help="file to adopt; repeat the flag for multiple files")
    p.add_argument("--project", default=None,
                   help="Claude Code project root; derives the memory directory "
                        "when --memory-dir is omitted")
    p.add_argument("--reason", required=True, help="why this state is being blessed (recorded in the entry)")
    p.set_defaults(fn=cmd_adopt)

    p = sub.add_parser("unwatch", help="stop watching an external file (interactive only)",
                       description="Stop watching an external file, appending a "
                       "signed delete entry. Also clears a missing finding for a "
                       "watched file you deliberately removed.",
                       epilog="Example:\n"
                       "  memattest unwatch --path <PROJECT>/CLAUDE.md --project <PROJECT> --reason \"no longer used\"",
                       formatter_class=_HelpFormatter)
    p.add_argument("--memory-dir", default=None,
                   help="the guarded memory directory; or use --project")
    p.add_argument("--project", default=None,
                   help="Claude Code project root; derives the memory directory "
                        "when --memory-dir is omitted")
    p.add_argument("--keystore", choices=["keyring", "file"], default=None,
                   help="backend keystore; only needed for pre-config logs")
    p.add_argument("--path", action="append", required=True, dest="paths",
                   help="watched file to stop watching; repeat the flag for multiple files")
    p.add_argument("--reason", required=True, help="why watching stops (recorded in the entry)")
    p.set_defaults(fn=cmd_unwatch)

    p = sub.add_parser("log", help="print entries as JSON lines",
                       description="Print every log entry as one JSON object per line.")
    _add_common(p)
    p.set_defaults(fn=cmd_log)

    p = sub.add_parser("prove", help="emit inclusion or consistency proof",
                       description="Emit an RFC 6962 inclusion proof for one entry, "
                       "or a consistency proof between two tree sizes, as JSON.",
                       epilog="Example:\n  memattest prove --memory-dir <MEMORY_DIR> --index 1",
                       formatter_class=_HelpFormatter)
    _add_common(p)
    p.add_argument("--index", type=int, help="entry index to prove inclusion for")
    p.add_argument("--old-size", type=int, help="earlier tree size to prove consistency from")
    p.set_defaults(fn=cmd_prove)

    p = sub.add_parser("install",
                       help="wire the Claude Code hooks for a project (interactive only)",
                       description="Wire the memattest hooks into a Claude Code "
                       "project: run init if needed, merge the hooks into the "
                       "chosen settings file, watch the shared settings file, and "
                       "verify.",
                       epilog="Example:\n  cd <PROJECT>\n  memattest install",
                       formatter_class=_HelpFormatter)
    p.add_argument("--project", default=".",
                   help="project root whose .claude settings get wired "
                        "(default: current directory)")
    p.add_argument("--memory-dir", default=None,
                   help="memory directory; derived from the project path when omitted")
    p.add_argument("--keystore", choices=["keyring", "file"], default=None,
                   help="backend keystore used if init runs; recorded in the "
                        "log's config.toml")
    p.set_defaults(fn=cmd_install)

    p = sub.add_parser("hook", help="harness hook entry points")
    hook_sub = p.add_subparsers(dest="hook_command", required=True)
    hp = hook_sub.add_parser("post-tool-use")
    _add_common(hp)
    hp.set_defaults(fn=cmd_hook_post_tool_use)
    hp = hook_sub.add_parser("session-start")
    _add_common(hp)
    hp.set_defaults(fn=cmd_hook_session_start)
    hp = hook_sub.add_parser("pre-tool-use")
    _add_common(hp)
    hp.set_defaults(fn=cmd_hook_pre_tool_use)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except MemAttestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: unexpected failure: {exc!r}", file=sys.stderr)
        return 2
