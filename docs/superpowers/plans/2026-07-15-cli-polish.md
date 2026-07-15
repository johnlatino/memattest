# CLI Polish Round Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `record` prints a success line, `adopt` takes files via a repeatable `--path` flag (with the remediation line, parser hint, docs, and tests moved in the same round), and the README documents `prove` with a worked example.

**Architecture:** Pure CLI-surface and documentation changes. Code edits live entirely in `cli.py`: one print in `cmd_record`, one argparse line for adopt (`--path`, `action="append"`, `dest="paths"` so the handler is untouched), and two message strings (`_report_lines` remediation, `_HintingParser` hint). Core, hooks, log/STH formats, per-log config, keystores, and exit codes are unchanged.

**Tech Stack:** Python ≥ 3.12, argparse, pytest. Spec: `docs/superpowers/specs/2026-07-15-cli-polish-design.md`.

## Global Constraints

- **venv only** — every `pytest` and `memattest` invocation uses `.venv\Scripts\...` (Windows dev machine).
- No new dependencies; no changes outside `src/memattest/cli.py`, tests, and docs.
- The hot `hook pre-tool-use` path is untouched; `tests/test_cli.py::test_cli_module_import_stays_lightweight` must keep passing.
- The adopt ceremony semantics are unchanged: interactive TTY only, `--reason` required, typed confirmation, no `--yes` flag. The PreToolUse adopt guard and its tests are unaffected (it matches the invocation, not the argument shape).
- Wording, everywhere (docs, help strings, messages, commits): plain phrasing over fancy vocabulary; "backend keystore", never bare "backend"; the informal term for testing a tool on its own repository is banned in all variants (say "self-testing"); never the phrase "load-bearing"; no contrastive-reframe constructions ("X isn't just Y", "more than just", "goes beyond").
- Commit messages: subject + body only, **no attribution/Co-Authored-By lines**. Commit messages and shell commands must not contain the literal two-word phrase `memattest adopt`, paths shaped like `.claude/settings*.json`, or the hook-disabling flag name — the live PreToolUse guard on this machine denies them. (File *content* written via the Edit/Write tools may contain command examples; the guard inspects commands, not edited text.)

## File Structure

- `src/memattest/cli.py` — `cmd_record` print (Task 1); adopt parser line, remediation string, hint string (Task 2).
- `tests/test_cli.py` — record success-line tests (Task 1).
- `tests/test_adopt.py` — adopt syntax swaps + new `--path` tests (Task 2).
- `README.md`, `docs/manual-test-full-lifecycle.md` — adopt examples, record expectations, new "Auditing with proofs" section (Task 3).

---

### Task 1: `record` success line

**Files:**
- Modify: `src/memattest/cli.py:105-110` (`cmd_record`)
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `ma.record(path, op=...)` already returns the appended entry dict with keys `op`, `path` (log-relative), `index`.
- Produces: `cmd_record` prints exactly `recorded {op} of {path} at entry {index}` on success. Task 3 updates the manual-test doc to expect this line.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_cli.py`:

```python
# --- record success line (CLI polish round, spec 2026-07-15) -----------------
# The hook path (hook post-tool-use) calls core's ma.record() directly and
# stays silent; only the CLI handler prints.


def test_record_prints_success_line(memdir, capsys):
    run("init", *base(memdir))
    f = memdir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    capsys.readouterr()
    assert run("record", *base(memdir), "--path", str(f)) == 0
    assert capsys.readouterr().out.strip() == "recorded write of notes.md at entry 1"


def test_record_delete_prints_success_line(memdir, capsys):
    run("init", *base(memdir))
    f = memdir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    run("record", *base(memdir), "--path", str(f))
    f.unlink()
    capsys.readouterr()
    assert run("record", *base(memdir), "--path", str(f), "--op", "delete") == 0
    assert capsys.readouterr().out.strip() == "recorded delete of notes.md at entry 2"
```

(The `memdir` fixture's init adopts `MEMORY.md` as entry 0, so the first record is entry 1.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v -k success_line`
Expected: both FAIL — stdout is empty today (`'' == 'recorded write of ...'` assertion error).

- [ ] **Step 3: Write the implementation**

In `src/memattest/cli.py`, replace `cmd_record`:

```python
def cmd_record(args) -> int:
    if args.memory_dir is None:
        args.memory_dir = _derive_memory_dir([Path(args.path)])
    ma = _make_ma(args)
    entry = ma.record(Path(args.path), op=args.op)
    print(f"recorded {entry['op']} of {entry['path']} at entry {entry['index']}")
    return 0
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v -k success_line`
Expected: 2 PASS.

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass (no existing test asserts record's stdout is empty; the hook-path test drives `hook post-tool-use`, which does not go through `cmd_record`).

- [ ] **Step 6: Commit**

```bash
git add src/memattest/cli.py tests/test_cli.py
git commit -m "Print a success line from record

record was the one state-changing command that reported nothing on
success. It now prints the operation, the log-relative path, and the
entry index (recorded write of notes.md at entry 12), matching what
log and tamper reports show. The post-tool-use hook calls the core
API directly and stays silent."
```

---

### Task 2: `adopt` takes a repeatable `--path` flag

**Files:**
- Modify: `src/memattest/cli.py:80-83` (`_report_lines` remediation string), `:277-282` (`_HintingParser`), `:308-312` (adopt parser)
- Test: `tests/test_adopt.py`

**Interfaces:**
- Consumes: `cmd_adopt` reads `args.paths` (a list) — unchanged.
- Produces: adopt CLI syntax `--path <file>` repeated per file (`action="append"`, `required=True`, `dest="paths"`); new remediation and hint strings quoted below. Task 3 updates the docs to the new syntax.

- [ ] **Step 1: Update existing tests to the new syntax and add the new ones**

In `tests/test_adopt.py`, every `cli.main([...])` adopt invocation currently passes file paths positionally. Insert `"--path"` before each file argument (8 call sites, in: `test_cli_adopt_refuses_without_tty`, `test_cli_adopt_derives_memory_dir_from_file_parent`, `test_cli_adopt_without_memory_dir_does_not_walk_up`, `test_cli_adopt_paths_in_different_directories_require_explicit_flag`, `test_cli_adopt_uninitialized_fails_before_prompting`, `test_cli_adopt_eof_at_confirmation_aborts_cleanly`, `test_cli_adopt_interrupt_at_confirmation_aborts_cleanly`, `test_cli_adopt_requires_typed_confirmation`). Examples of the transformation:

```python
# before
rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
# after
rc = cli.main(["adopt", "--path", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])

# the two-directory test passes two files; each gets its own flag:
rc = cli.main(["adopt", "--path", str(dirs[0]), "--path", str(dirs[1]), "--reason", "r", "--keystore", "file"])
```

Then append the new tests:

```python
# --- repeatable --path (CLI polish round, spec 2026-07-15) -------------------


def test_cli_adopt_multiple_paths_adopts_all(tmp_path, monkeypatch, capsys):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    a, b = d / "a.md", d / "b.md"
    a.write_text("x", encoding="utf-8")
    b.write_text("y", encoding="utf-8")
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)
    monkeypatch.setattr("builtins.input", lambda prompt="": "adopt")
    rc = cli.main(["adopt", "--path", str(a), "--path", str(b),
                   "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    assert rc == 0
    assert "adopted 2 file(s)" in capsys.readouterr().out
    assert cli.main(["verify", "--memory-dir", str(d), "--keystore", "file"]) == 0


def test_cli_adopt_old_positional_syntax_names_the_missing_flag(tmp_path, monkeypatch, capsys):
    # Old syntax: file passed positionally, no --path. argparse reports the
    # missing required flag by name, which is the migration message.
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(["adopt", str(f), "--reason", "r",
                  "--memory-dir", str(d), "--keystore", "file"])
    assert exc.value.code == 2
    assert "--path" in capsys.readouterr().err


def test_cli_adopt_stray_positional_hints_at_path_flag(tmp_path, monkeypatch, capsys):
    # --path satisfied but an extra bare token remains: the unrecognized-
    # arguments hint must now mention --path alongside --memory-dir.
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    capsys.readouterr()
    with pytest.raises(SystemExit) as exc:
        cli.main(["adopt", "--path", str(f), "stray.md", "--reason", "r",
                  "--memory-dir", str(d), "--keystore", "file"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "unrecognized arguments" in err
    assert "'--path <file>'" in err and "'--memory-dir <path>'" in err
```

- [ ] **Step 2: Run tests to verify current state**

Run: `.venv\Scripts\python -m pytest tests/test_adopt.py -v`
Expected: every updated existing test FAILS (argparse: `unrecognized arguments: --path ...` under the old parser) and all three new tests FAIL. This is the RED state for the syntax change.

- [ ] **Step 3: Write the implementation**

In `src/memattest/cli.py`, replace the adopt parser lines:

```python
    p = sub.add_parser("adopt", help="bless out-of-band changes (interactive only)")
    _add_common(p, memory_dir_default=None)  # derived from the paths' folder when omitted
    p.add_argument("--path", action="append", required=True, dest="paths",
                   help="file to adopt; repeat the flag for multiple files")
    p.add_argument("--reason", required=True)
    p.set_defaults(fn=cmd_adopt)
```

Replace the remediation append in `_report_lines`:

```python
    lines.append(
        "Remediation: restore the affected files and re-run verify, or run "
        "'memattest adopt --path <file> --reason ...' (repeat --path per "
        "file) to accept the current state."
    )
```

Replace the hint in `_HintingParser.error`:

```python
class _HintingParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        if message.startswith("unrecognized arguments:"):
            message += ("\nhint: the memory directory is passed as "
                        "'--memory-dir <path>' and files as '--path <file>', "
                        "not as positional arguments")
        super().error(message)
```

(`cmd_adopt` itself is untouched — `dest="paths"` keeps `args.paths` a list, so the TTY check, memory-dir derivation, ceremony, and core call all read exactly as before.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv\Scripts\python -m pytest tests/test_adopt.py tests/test_cli.py -v`
Expected: all PASS, including the untouched guard tests and `test_verify_positional_path_hints_at_memory_dir_flag` (the new hint still contains `--memory-dir`).

- [ ] **Step 5: Run the full suite**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

- [ ] **Step 6: Commit**

```bash
git add src/memattest/cli.py tests/test_adopt.py
git commit -m "Adopt files via a repeatable --path flag

adopt took bare positional paths while record took --path; adopt now
takes --path per file (action=append, dest=paths, so the handler and
ceremony are unchanged), making every flag single-valued and the two
commands consistent. The verify remediation line and the unrecognized-
arguments hint teach the new form; old positional syntax gets argparse
naming the missing --path flag."
```

---

### Task 3: Documentation — adopt syntax, record expectation, prove section

**Files:**
- Modify: `README.md:190-202` (adopt examples), `README.md:278` (insert new section before `## Hardening your installation`)
- Modify: `docs/manual-test-full-lifecycle.md` (steps B1 and C3)

**Interfaces:**
- Consumes: behavior shipped in Tasks 1-2 (`recorded {op} of {path} at entry {index}`; `--path` per file).
- Produces: documentation consistent with shipped behavior.

- [ ] **Step 1: README — adopt examples**

Replace the two command lines (README.md:191 and :201):

```bash
memattest adopt --path <MEMORY_DIR>/notes.md --reason "manual correction of stale project name"
```

```bash
memattest adopt --path <MEMORY_DIR>/subfolder/notes.md --memory-dir <MEMORY_DIR> --reason "manual correction of stale project name"
```

- [ ] **Step 2: README — "Auditing with proofs" section**

Insert immediately before `## Hardening your installation` (currently line 279):

````markdown
## Auditing with proofs

`memattest prove` emits the RFC 6962 proofs that let someone else check
your log without trusting your machine:

- `--index N` prints the inclusion proof for entry N — the audit path, a
  JSON array of hex-encoded hashes.
- `--old-size K` prints the consistency proof between the K-entry tree
  and the current tree — evidence that the log grew append-only, with
  nothing rewritten or reordered.

You never need `prove` for your own log: `verify` already recomputes the
full tree and checks every entry directly. `prove` exists for *other*
parties — an auditor holding a snapshot you handed them, or, once
external root anchoring lands (see the roadmap), anyone checking that
today's log is an append-only extension of a previously published tree
head, which is what makes rollback detectable.

A small example. With three entries in the log:

```bash
$ memattest prove --memory-dir <MEMORY_DIR> --index 1
["a7f3c2…", "5d90ee…"]
```

(hashes shortened here). An auditor holding entry 1's bytes, this audit
path, and a signed tree head recomputes the root — hash the entry, then
combine it pairwise with each hash in the path — and compares the result
against the root in the tree head. A match proves the entry is in the
tree that head commits to; they never need the rest of the log.
````

- [ ] **Step 3: Manual-test doc — record and adopt expectations**

In `docs/manual-test-full-lifecycle.md`:

Step B1's expected text currently says record is silent. Replace:

```markdown
Expected: `record` prints `recorded write of lifecycle-note.md at entry N`,
exit `0` — note `--memory-dir` was omitted and derived from the file's
containing folder. Verify shows the entry count grew by one, exit `0`.
```

Step C3's adopt invocation becomes:

```powershell
.venv\Scripts\memattest adopt --path "$mem\lifecycle-note.md" --path "$mem\planted.md" --reason "manual lifecycle test reconcile"
```

- [ ] **Step 4: Sanity pass and commit**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass.

```bash
git add README.md docs/manual-test-full-lifecycle.md
git commit -m "Document prove and the polished CLI surface

Add the Auditing with proofs README section with a worked inclusion-
proof example, move the adopt examples to the repeatable --path form,
and update the manual-test doc for the record success line and the new
adopt syntax."
```

---

### Task 4: End-to-end validation on this machine

**Files:** none (validation only; scratch state under `%TEMP%`).

**Interfaces:**
- Consumes: the installed editable package (`.venv\Scripts\memattest`) with Tasks 1-3 merged; the real Windows Credential Manager.
- Produces: evidence outside pytest. (The interactive adopt ceremony itself cannot be driven here — it requires a human typing at a TTY — and is left to the user's own manual pass.)

- [ ] **Step 1: Scratch checks**

```powershell
$scratch = "$env:TEMP\memattest-polish-e2e"
New-Item -ItemType Directory -Force $scratch | Out-Null
Set-Content -Encoding utf8 "$scratch\note.md" "hello"
.venv\Scripts\memattest init --memory-dir $scratch
Set-Content -Encoding utf8 "$scratch\second.md" "world"
.venv\Scripts\memattest record --path "$scratch\second.md"
.venv\Scripts\memattest prove --memory-dir $scratch --index 1
```

Expected: init adopts 1 file; `record` prints `recorded write of second.md at entry 1` (exit 0); `prove` prints a JSON array of hex hashes (exit 0).

(No adopt invocation here: the live PreToolUse guard on this machine denies
agent-issued adopt commands — working as designed. The old-syntax error path
is locked by `test_cli_adopt_old_positional_syntax_names_the_missing_flag`,
and the interactive ceremony belongs to the user's own manual pass.)

- [ ] **Step 2: Clean up**

```powershell
.venv\Scripts\python -c "import keyring, pathlib, os; keyring.delete_password('memattest', str((pathlib.Path(os.environ['TEMP']) / 'memattest-polish-e2e').resolve()))"
Remove-Item -Recurse -Force $scratch
```

Expected: both succeed silently.

- [ ] **Step 3: Full suite, final**

Run: `.venv\Scripts\python -m pytest -q`
Expected: all pass. Report results; no commit (nothing changed).
