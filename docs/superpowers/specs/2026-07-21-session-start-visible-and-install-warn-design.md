# Visible Session-Start Success and Install Duplicate-Hook Block - Design

Date: 2026-07-21
Status: approved for planning
Scope: backlog items "visible session-start success" and the install-warn
refinement (now an install block). Two small, independent changes bundled in
one round because both touch the Claude Code hook lifecycle and neither alters
the log format, exit codes, or the hot hook paths.

## 1. Problem

Two gaps found while self-testing the tool on its own repository:

- **Session start is silent to the human on success.**
  `cmd_hook_session_start` delivers the verify result two ways: it always sets
  `additionalContext` (which Claude Code injects into the agent's context) and
  it sets `systemMessage` (which Claude Code shows in the user's console) only
  on failure. So a clean session shows the user nothing, and a session where
  the hook was removed also shows nothing: the two are indistinguishable. The
  README already tells the user that the last-resort signal for total hook
  removal is noticing the missing `OK N entries verified` line, but the code
  never sends that line to the user, so the documented backstop is vacuous for
  the human (it is real only for the agent).

- **Install can silently create a duplicate hook registration.**
  `run_install` writes the memattest hooks into the one settings file the user
  picks, and `plan_merge` only ever inspects that target file. Claude Code
  merges hooks across all settings scopes additively, so if a memattest hook
  already exists in another scope (the other project settings file, or the
  user-level `~/.claude/settings.json`), installing into a second scope makes
  every memattest hook fire more than once per event. That duplicate firing was
  the most reliable real-world trigger of the append race that the append-lock
  round fixed; even with the lock it is wasteful and confusing.

## 2. Component 1: visible success at session start

In `cmd_hook_session_start`, set `systemMessage` unconditionally instead of
only when the report is not ok. The success text is already a single line
(`_report_lines` returns `["OK N entries verified"]`), so the same assignment
covers both cases: a clean session shows `memattest: OK N entries verified` in
the user's console, and a failing or errored session shows the full report,
exactly as today. `additionalContext` is unchanged, so the agent still receives
the complete report on every session start.

The message is always on, with no flag to suppress it. A one-line per-session
confirmation is the point of the feature: it keeps the "notice the silence"
rule unambiguous, since silence then always means the hook did not run, never
"the user turned the message off."

## 3. Component 2: block install on a cross-scope duplicate

After the user chooses the target settings file, `run_install` scans the
settings scopes other than the target for an existing memattest hook:

- `<project>/.claude/settings.json`
- `<project>/.claude/settings.local.json`
- `~/.claude/settings.json`

The scan reuses the existing `_is_memattest_hook` detector through a small,
defensive walk that tolerates malformed shapes and never raises: an unreadable
or malformed scope is skipped rather than aborting the install for an unrelated
reason. If any other scope already holds a memattest hook, install prints a
message naming the conflicting file(s), explains that Claude Code merges hooks
across settings scopes so each memattest hook would fire more than once per
event, tells the user to remove the memattest hooks from the other scope(s)
(or to re-run install targeting that scope to update it in place), and stops
with exit 2.

The check runs after the target is known and before any state change: before
the plan is rendered, before the typed confirmation, and before `init` or the
settings write. A blocked install therefore leaves zero partial state. Because
the conflict set excludes the target itself, re-running install against the
same file that already holds the hooks is an in-place update, not a conflict,
so idempotent re-installs still succeed; only a genuine cross-scope duplicate
blocks.

Two new pure helpers carry the logic, unit-testable without a terminal:

- `_has_memattest_hook(settings: dict) -> bool` - defensive walk of a settings
  dict's `hooks`, returning whether any hook is a memattest hook.
- `other_scope_hook_conflicts(project: Path, target: Path) -> list[Path]` -
  reads each candidate scope (skipping the target and any scope it cannot
  read), returning the paths that contain a memattest hook.

## 4. Documentation corrections

- README hook description: it currently says `systemMessage` shows the report
  to the user "on failure". Correct it to state that the result is shown on
  every session start (a one-line `OK` on success, the full report on a
  problem).
- README LIMITATION 1 and the hardening bullet already describe watching for
  the missing `memattest: OK` line; they become accurate once Component 1
  lands and need only light tightening for consistency.
- Note the new install behavior where the installer's steps are documented: a
  cross-scope duplicate registration blocks the install.

## 5. Testing

- **Component 1:** flip the existing clean-session test
  (`test_hook_session_start_clean_emits_context_json`) from asserting
  `systemMessage` is absent to asserting `OK 1 entries verified` is in
  `systemMessage`. The existing failure and operational-error session-start
  tests already assert `systemMessage` and stay green.
- **Component 2:** `_has_memattest_hook` positive and negative cases;
  `other_scope_hook_conflicts` finds a hook in the non-target project file and
  in the user-level file, ignores the target itself, and tolerates a missing
  or malformed scope without raising; and an integration test that a conflict
  in another scope makes `run_install` return 2 while leaving the target
  settings unwritten and the log uninitialized.
- The full existing suite stays green.

## 6. Out of scope

- The projection-based (hooks-only) watch for `settings.local.json` - a
  separate backlog item.
- Any change to how Claude Code merges or fires hooks - Component 2 only
  detects and reports a duplicate, it does not change hook merging.
- External root anchoring and the append concurrency work - separately tracked
  or already shipped.

## 7. Minor wording tidy

`install.py` still describes its flow as a "ceremony" in the module docstring
and comments, which conflicts with the project's plain-wording preference
("procedure", not metaphorical jargon). Since this round edits `install.py`,
replace those occurrences with plain wording as a small fold-in.
