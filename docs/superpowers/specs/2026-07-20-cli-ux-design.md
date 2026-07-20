# CLI UX Round - Design

Date: 2026-07-20
Status: approved for planning
Scope: four usability fixes found while manually testing the watch list.
A separate append-concurrency robustness bug is tracked outside this round.

## 1. Problems

1. Adopting a watched (external) file with `--memory-dir` omitted fails with
   "run init there first", which wrongly suggests running `init` on a
   `.claude` folder. The message predates watch adopts.
2. Adopting or unwatching an external file forces the user to type the long
   profile memory-directory path, even though `install` already derives it
   from the project via the Claude Code slug convention.
3. `install` auto-watches whichever settings file it wrote. When that is
   `settings.local.json`, the file churns - Claude Code writes permission
   decisions into it - so verify reports those routine writes as tampering.
4. Per-command help is uneven: several flags have blank help text, no
   command has a description sentence, and there are no example command
   lines.

## 2. Item 2: the `--project` flag (and precedence)

`adopt` and `unwatch` gain an optional `--project <dir>`. The memory
directory resolves by this precedence:

1. `--memory-dir` given -> use it.
2. else `--project` given -> derive `~/.claude/projects/<slug>/memory` via
   `derive_memory_dir` (reused from the installer module, lazy-imported),
   then existence-check it. A derived path that does not exist is an
   operational error naming both remedies: pass `--memory-dir`, or run a
   Claude Code session in the project first so the directory exists.
3. else -> today's behavior. For `adopt`, the file-parent derivation (right
   for memory files). For `unwatch`, which only operates on external files,
   one of `--memory-dir`/`--project` is required; omitting both is a clear
   error.

Passing both `--memory-dir` and `--project` is a usage error (they specify
the same thing two ways). From inside a project,
`memattest adopt --path .claude/settings.json --project . --reason "..."`
needs no long path. No walk-up, no inference - consistent with memattest's
existing strict no-walk-up rule.

Coupling note: `derive_memory_dir`/`project_slug` stay in the
`integrations/claude_code` module (the slug convention is Claude Code
specific); `cli.py` lazy-imports `derive_memory_dir` for `--project`, as it
already imports that module for `install`.

## 3. Item 1: the derivation error message

`_derive_memory_dir` (used by `record` and `adopt`) currently raises "run
init there first, or pass --memory-dir explicitly". It changes to cover both
cases without implying you should `init` a settings folder, roughly:

"{parent} is not an initialized memory directory. For a memory file, run
init there first; for a watched external file, pass --memory-dir or
--project."

## 4. Item 3: install watches the shared settings file only

`run_install` adopt-watches the settings file it wrote only when that file
is the shared `settings.json`:

- Shared chosen -> adopt-watch it, as today; the plan still discloses the
  watch before confirmation.
- Local chosen (`settings.local.json`) -> skip the watch and print a plain
  note in place of the watch line: Claude Code writes permission decisions
  into `settings.local.json`, so watching it whole would report those
  routine writes as tampering; the hook configuration there is left
  unwatched for now, and a hooks-only watch is the planned way to cover it.

This leaves an accepted, visible gap: a local-only install gets no watch on
its hook configuration until the projection feature exists. The note makes
that explicit rather than silent.

## 5. Item 4: help polish

No new machinery, just complete help text via argparse:

- Fill in missing flag help on every command (`--memory-dir`, `--path`,
  `--op`, `--project`, `--reason`, and any other blank ones), so `-h` is
  self-describing.
- A one-sentence `description=` per subcommand, shown at the top of its
  `-h`.
- One example command line per command via `epilog`, focused on the
  commands where it helps most (`adopt`, `unwatch`, `install`, `verify`,
  `record`). Example text lives in source strings, so the live PreToolUse
  guard (which inspects executed shell commands, not source) does not
  interfere even where an example contains `memattest adopt`.

Because the guard denies `memattest adopt -h` / `memattest install -h` /
`memattest unwatch -h` as shell commands on this machine, help for those
commands is exercised in tests through `cli.main([...])` (argparse raises
`SystemExit(0)` for `-h`), never by running the guarded phrase in a shell.

## 6. Testing

- CLI (`tests/test_adopt.py`, `tests/test_cli.py`): `adopt`/`unwatch` with
  `--project .` derive the correct memory directory and create/drop a watch
  entry; `--project` at a project with no memory directory -> operational
  error naming both remedies; both `--memory-dir` and `--project` -> usage
  error; the improved derivation message appears for an external adopt with
  no directory flag.
- Install (`tests/test_claude_install.py`): the shared-settings drive-
  through still watches its file (existing test holds); a new local-settings
  drive-through asserts the settings file is not in `derived_watch_state`
  and the skip note is printed.
- Help (`tests/test_cli.py`): `cli.main(["adopt", "-h"])` (and the other
  commands) raises `SystemExit(0)`; a smoke check that the new help strings
  are present in captured output for a representative command.

## 7. Out of scope

- Projection-based (hooks-only) watch of `settings.local.json` - hash just
  the `hooks` block and the memattest `permissions.deny` rules, ignoring
  `permissions.allow` - so a churny local settings file can be watched
  without false alarms. Recorded here as the planned way to close item 3's
  gap; cross-referenced from the watch-list spec.
- The append-concurrency robustness bug (concurrent post-tool-use hooks race
  on the non-atomic `count() -> check -> write` append). Tracked separately.
- Auto-inferring the project from a watched file's path (rejected: it breaks
  the no-walk-up rule).
