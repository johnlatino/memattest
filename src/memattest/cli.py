import argparse
import json
import os
import sys
from pathlib import Path

from . import merkle
from .core import MemAttest, VerifyReport
from .errors import MemAttestError
from .identity import FileKeyStore, KeyringKeyStore


def _make_ma(args) -> MemAttest:
    memory_dir = Path(args.memory_dir)
    if args.keystore == "file":
        passphrase = os.environ.get("MEMATTEST_PASSPHRASE")
        if not passphrase:
            raise MemAttestError("keystore 'file' requires MEMATTEST_PASSPHRASE to be set")
        ks = FileKeyStore(memory_dir / ".memattest" / "key.sealed", passphrase.encode("utf-8"))
    else:
        ks = KeyringKeyStore()
    return MemAttest(memory_dir, keystore=ks)


def _print_report(report: VerifyReport, entry_count: int) -> None:
    if report.ok:
        print(f"OK {entry_count} entries verified")
        return
    lines = [
        f"PROBLEM kind={p['kind']} path={p['path']} detail={p['detail']} last_valid={p['last_valid_index']}"
        for p in report.problems
    ]
    lines.append(
        "Remediation: restore the affected files and re-run verify, or run "
        "'memattest adopt <paths> --reason ...' to accept the current state."
    )
    for line in lines:
        print(line)
    for line in lines:
        print(line, file=sys.stderr)


def cmd_init(args) -> int:
    ma = _make_ma(args)
    entries = ma.init()
    print(f"initialized; adopted {len(entries)} pre-existing file(s)")
    return 0


def cmd_record(args) -> int:
    ma = _make_ma(args)
    ma.record(Path(args.path), op=args.op)
    return 0


def cmd_verify(args) -> int:
    ma = _make_ma(args)
    report = ma.verify()
    _print_report(report, ma.store.count())
    return report.exit_code


def cmd_adopt(args) -> int:
    if not sys.stdin.isatty():
        print("error: adopt requires an interactive terminal", file=sys.stderr)
        return 2
    ma = _make_ma(args)
    print(f"About to adopt {len(args.paths)} file(s) as trusted. Reason: {args.reason}")
    if input("Type 'adopt' to confirm: ").strip() != "adopt":
        print("aborted", file=sys.stderr)
        return 2
    ma.adopt([Path(p) for p in args.paths], reason=args.reason)
    print(f"adopted {len(args.paths)} file(s)")
    return 0


def cmd_log(args) -> int:
    ma = _make_ma(args)
    for e in ma.store.load_all():
        print(json.dumps(e, sort_keys=True))
    return 0


def cmd_prove(args) -> int:
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


def cmd_hook_post_tool_use(args) -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        raise MemAttestError(f"malformed hook payload on stdin: {exc}") from exc
    if not isinstance(payload, dict):
        raise MemAttestError("malformed hook payload on stdin: expected a JSON object")
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


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--memory-dir", default=".")
    p.add_argument("--keystore", choices=["keyring", "file"], default="keyring")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="memattest",
                                     description="Tamper-evident agent memory (append-only Merkle log)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="initialize and baseline existing memories")
    _add_common(p)
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("record", help="append one write/delete event")
    _add_common(p)
    p.add_argument("--path", required=True)
    p.add_argument("--op", choices=["write", "delete"], default="write")
    p.set_defaults(fn=cmd_record)

    p = sub.add_parser("verify", help="run the three integrity checks")
    _add_common(p)
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("adopt", help="bless out-of-band changes (interactive only)")
    _add_common(p)
    p.add_argument("paths", nargs="+")
    p.add_argument("--reason", required=True)
    p.set_defaults(fn=cmd_adopt)

    p = sub.add_parser("log", help="print entries as JSON lines")
    _add_common(p)
    p.set_defaults(fn=cmd_log)

    p = sub.add_parser("prove", help="emit inclusion or consistency proof")
    _add_common(p)
    p.add_argument("--index", type=int)
    p.add_argument("--old-size", type=int)
    p.set_defaults(fn=cmd_prove)

    p = sub.add_parser("hook", help="harness hook entry points")
    hook_sub = p.add_subparsers(dest="hook_command", required=True)
    hp = hook_sub.add_parser("post-tool-use")
    _add_common(hp)
    hp.set_defaults(fn=cmd_hook_post_tool_use)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except MemAttestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: unexpected failure: {exc!r}", file=sys.stderr)
        return 2
