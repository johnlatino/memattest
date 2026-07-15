# CLI Polish Round — Design

Date: 2026-07-15
Status: approved for planning
Scope: items 1–3 from the user's manual full-lifecycle test (2026-07-15).
Item 4 from that test (a hook installer) is deliberately excluded — it is
its own feature with its own trust-surface questions and gets a separate
design cycle (Round B).

## 1. Problems

1. `memattest record` prints nothing on success. Every other
   state-changing command reports what it did (`init`: "initialized;
   adopted N pre-existing file(s)"; `adopt`: "adopted N file(s)").
2. `record` takes its file as `--path <file>` while `adopt` takes bare
   positional paths — two shapes for "which files am I operating on".
3. `prove` is not documented in the README, so a user finding it in
   `--help` has no way to know when to use it.

## 2. Item 1 — `record` success line

`cmd_record` in `cli.py` keeps the entry dict `ma.record()` already
returns and prints:

```
recorded {op} of {path} at entry {index}
```

e.g. `recorded write of notes.md at entry 12`, or `recorded delete of
notes.md at entry 13` under `--op delete`. `path` is the log-relative
path from the entry (the same spelling `log` and tamper reports use).

CLI handler only: `hook post-tool-use` calls core's `ma.record()`
directly, not `cmd_record`, so hook invocations stay silent. Exit codes
unchanged.

Tests: one CLI test asserting the stdout shape for a write; one for
`--op delete`.

## 3. Item 2 — `adopt` takes repeatable `--path`

The positional `paths` argument (`nargs="+"`) is replaced by:

```python
p.add_argument("--path", action="append", required=True, dest="paths")
```

Multiple files repeat the flag: `--path a.md --path b.md`. `dest="paths"`
keeps `args.paths` a list, so the handler, memory-dir derivation, and the
interactive ceremony are untouched. This sets (rather than follows) the
project convention: every memattest flag takes exactly one value.

This is a breaking CLI change. Everything showing the old form moves in
the same round:

- **Verify remediation line** (`_report_lines`): "run 'memattest adopt
  <paths> --reason ...'" becomes the `--path` form, e.g. "run 'memattest
  adopt --path <file> --reason ...' (repeat --path per file)".
- **`_HintingParser` hint**: today it only explains `--memory-dir`, so a
  user typing the old positional adopt syntax would get "unrecognized
  arguments" plus a hint about the wrong flag. The hint text now covers
  both: the memory directory is passed as `--memory-dir <path>` and files
  as `--path <file>`, not as positional arguments.
- **Docs**: README adopt examples; `docs/manual-test-full-lifecycle.md`
  step C3.
- **Tests**: existing adopt tests switch to the new syntax; new tests for
  multi-file (`--path a --path b` adopts both) and for omitted `--path`
  (argparse usage error, exit 2).

Explicitly unaffected: the PreToolUse adopt guard and its tests — the
guard matches the invocation (`memattest adopt`), not the argument shape.
The ceremony, TTY check, `--reason` requirement, and no-`--yes` policy
are unchanged.

## 4. Item 3 — document `prove` in the README

New short README section, "Auditing with proofs", after the Keystores
section. Content:

- What the two modes emit: `--index N` prints the RFC 6962 inclusion
  proof for entry N (a JSON array of hex-encoded hashes — the audit
  path); `--old-size K` prints the consistency proof between the
  K-entry tree and the current tree.
- Honest positioning, in plain words: you never need `prove` for your own
  log — `verify` already recomputes the full tree and checks every entry
  directly. `prove` exists for *other* parties: an auditor holding a
  snapshot, or, once external root anchoring lands (roadmap), anyone
  checking that today's log is an append-only extension of a previously
  published tree head, which is what makes rollback detectable.
- A small worked example: a three-entry log, `memattest prove
  --memory-dir <dir> --index 1`, its actual JSON output, and one sentence
  on what an auditor does with it (hash the entry, combine it with the
  audit path, compare the result against the root in a signed tree head).

Docs only; no code changes.

## 5. What this round does not touch

Core, the log and STH formats, the hooks, the per-log config, the
keystore code, and all exit-code semantics are unchanged. The only code
edits are in `cli.py` (one print, one argparse line, two message strings)
plus tests; the rest is documentation.

## 6. Testing

- `tests/test_cli.py`: record success-line tests (write and delete);
  adopt syntax tests (single `--path`, repeated `--path`, omitted
  `--path` → usage error); updated hint-text assertion.
- `tests/test_adopt.py`: existing tests move to the new syntax
  (behavioral assertions unchanged — same ceremony, same entries).
- Full suite green before each commit; no new test files.
