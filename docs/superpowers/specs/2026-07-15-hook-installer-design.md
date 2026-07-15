# Claude Code Hook Installer — Design

Date: 2026-07-15
Status: approved for planning
Scope: Round B from the 2026-07-15 manual-test feedback (item 4: wiring the
hooks by hand is cumbersome). Rounds are independent; Round A (CLI polish)
already merged.

## 1. Problem

Wiring memattest into a Claude Code project today takes five manual steps:
init the memory directory, open `settings-snippet.json`, hand-merge it into
the project's `.claude` settings file, substitute `<MEMATTEST_BIN>` and
`<MEMORY_DIR>` with absolute paths (forward slashes on Windows), and
restart the session. Each step has a failure mode (wrong path notation,
clobbered existing hooks, forgotten init), and the user who requested this
feature hit the friction directly.

The installer is trust-sensitive by nature: the settings files configure
the hooks, and the PreToolUse guard exists precisely to keep agents away
from them. An installer command is an innocent-looking invocation that
rewrites that trust surface, so it must be gated the way `adopt` is.

## 2. Design summary

`memattest install` performs the full onboarding in one interactive,
adopt-style ceremony: derive or accept the memory directory, run `init` if
needed, merge the filled hook template into the chosen project settings
file, and finish with a closing `verify`. Re-runs are idempotent (existing
memattest entries updated in place, nothing duplicated). No uninstall mode
in this round; unwiring stays a manual README procedure. The PreToolUse
guard gains an install deny pattern beside the adopt one.

Alternatives rejected: a standalone script (security-equivalent, worse
discoverability); a generate-only mode that prints filled JSON for manual
pasting (keeps the hand-merge step, which is the complaint).

## 3. Command surface and ceremony

`memattest install [--memory-dir <dir>] [--project <dir>] [--keystore ...]`

- `--project` names the project root whose `.claude` settings get wired;
  default is the current directory.
- `--memory-dir` is optional. When omitted, the installer derives it from
  the project directory via the Claude Code convention
  `~/.claude/projects/<slug>/memory`, where `<slug>` is the project's
  absolute path with the drive colon and every path separator replaced by
  dashes (`C:\source\agentmemoryvalidation` →
  `C--source-agentmemoryvalidation`). The convention is internal to Claude
  Code, so the installer derives and confirms, never trusts: the candidate
  must exist on disk, and the resolved path is displayed in the ceremony
  plan for the human to check. If the derived directory does not exist,
  the installer stops (exit 2) stating both options: pass `--memory-dir`
  explicitly, or run one Claude Code session in the project first so the
  harness creates its own directory. An explicit `--memory-dir` is used
  as-is — the escape hatch for custom layouts and other setups.
  (Implementation must verify the slug convention's edge characters, e.g.
  dotted folder names, and pin the verified behavior in unit tests.)
- `--keystore` is passed through to `init` when init is needed (default
  keyring, recorded in the per-log config as usual).

The ceremony, in order:

1. Refuse without an interactive TTY (same best-effort check as `adopt`);
   non-interactive → exit 2.
2. Resolve everything up front: the memattest binary path derived from the
   running interpreter (the console script next to `sys.executable`;
   operational error if absent), the resolved memory directory, whether
   init is needed, the candidate settings files.
3. Ask the one interactive question: shared settings file or local, with
   shared presented as the recommended choice.
4. Print the full plan before touching anything: target file path, both
   resolved paths that will be written, whether each of the three hooks
   and the deny rules will be added or updated, and whether init runs
   first.
5. Typed confirmation — the word `install` — with EOF/interrupt aborting
   cleanly (`aborted`, exit 2), exactly like adopt.
6. Execute: init if needed, merge-write the settings, closing verify,
   final summary including the reminder that Claude Code snapshots hook
   configuration at session start, so the hooks take effect next session.

## 4. Settings merge semantics

The shipped `settings-snippet.json` is the single source of truth: the
installer loads it from the package (`importlib.resources`), fills the two
placeholders, and merges into the chosen file.

- **Absent file** → created with only the memattest hooks and deny rules,
  pretty-printed JSON (`indent=2`). The template's `"//"` documentation
  key is not copied — it documents the template; the README carries that
  material for installed users.
- **Existing file** → parsed as JSON; unparseable → operational error
  naming the file. The installer never overwrites or repairs content it
  cannot read.
- **Identifying memattest entries:** a hook entry is memattest's when its
  command string invokes a memattest binary with one of the three `hook`
  subcommands. On re-run each such entry is updated in place (fresh binary
  path and memory dir — the venv-moved case); when absent it is appended
  to the matching event's matcher group, creating the group with the
  template's matcher when the event has none. Hooks belonging to anything
  else are never touched or reordered beyond what a JSON round-trip
  implies.
- **Deny rules:** set-union — the memattest globs are added to
  `permissions.deny` when missing; unrelated deny entries are preserved.
- **Scope boundary:** only the project-level file chosen in the ceremony
  (shared or local) is written. The user-level `~/.claude` settings file
  is never touched.
- All paths written into the file use absolute, forward-slash notation
  (`C:/...` on Windows), per existing README guidance.
- Consequence, made visible rather than hidden: identification keys on the
  command string, so a hand-customized memattest hook command is reported
  in the plan as "will be updated" before the re-run replaces it.

## 5. Onboarding flow and error handling

Order after confirmation, each failure leaving a clean, stated position:

1. **Init, when needed.** Reports the adopted-file count; an initialized
   log skips this (stated in the plan). Init failure aborts before any
   settings edit: exit 2, nothing written.
2. **Settings merge-write.** Failure after a successful init states the
   exact position: the memory directory is initialized, the hooks are not
   wired, and re-running the idempotent installer completes the job. No
   rollback of the init — it produced a valid baseline.
3. **Closing verify** (cross-check included) is the installer's outcome:
   clean → success summary, exit 0; problems → the standard report prints
   and the installer exits 1 with the wiring intact — a tamper finding at
   install time is exactly what the hooks exist to surface, and the human
   is at the terminal to act on it. Only reachable for a pre-existing log;
   a fresh init verifies clean by construction.

Exit codes: `0` success · `1` closing verify found problems · `2`
operational (non-TTY, aborted ceremony, missing binary, underivable memory
directory, unparseable settings, init failure).

## 6. Guard extension

`cmd_hook_pre_tool_use` gains an `_INSTALL_INVOCATION` pattern beside the
adopt one — `\bmemattest(\.exe)?\s+install\b` after the existing quote
normalization, so quoted, path-prefixed, and `.exe` spellings are caught —
with a deny message of the same shape: the installer may only be run by a
human at an interactive terminal. The existing broad-match policy applies
(a command merely mentioning the phrase is denied; rephrase and rerun).
`pip install memattest` does not match: the pattern requires `memattest`
immediately before `install`.

The template's permission-deny globs gain `Bash(*memattest install*)` and
the PowerShell twin for second-layer symmetry, and the snippet's `"//"`
comment gains one sentence noting the installer consumes this template.

## 7. Code placement

New module `src/memattest/integrations/claude_code/install.py`, next to
the template it consumes: the pure, unit-testable pieces (slug derivation,
template fill, settings merge) plus the ceremony driver. `cli.py` gets a
thin `cmd_install` and parser wiring, importing the module lazily, keeping
the hot pre-tool-use path light.

## 8. Testing

- **Unit** (`tests/test_claude_install.py`): slug derivation (Windows
  drive paths, Linux paths, dotted folder names per the verified
  convention); merge semantics — fresh file; unrelated hooks and deny
  entries preserved through round-trip; idempotent re-run updates paths
  without duplicating; deny union; unparseable JSON → operational error;
  the `"//"` key never copied.
- **Ceremony (CLI-level, adopt-test style):** non-TTY refusal;
  EOF/interrupt abort; a full drive-through with monkeypatched stdin
  answering both prompts (target choice, typed `install`) against a tmp
  project and tmp memory dir on the file backend keystore, asserting init
  ran, settings landed, and verify passed.
- **Guard** (`tests/test_cli.py`): deny bare, quoted, and `.exe` install
  invocations; allow `pip install memattest` and `memattest init`.
- **End-to-end:** the real interactive ceremony cannot be driven by an
  agent (TTY check plus, once live, the guard itself); pytest covers the
  flow, and the user's manual pass on their test project is the true
  end-to-end.

## 9. Documentation

- **README quickstart** reorganizes around `memattest install` as the
  primary path; the manual template procedure remains as the alternative
  for non-Claude-Code harnesses and custom layouts.
- **settings-snippet.json** `"//"` comment: one sentence on the installer,
  plus the new deny globs (§6).
- Hardening and Security limitations sections: unchanged except where they
  reference the manual wiring as the only path.

## 10. Out of scope

- Uninstall/unwire mode (manual README procedure stands).
- A generate-only/print mode.
- Other harnesses (Codex etc.) — the module layout under
  `integrations/claude_code/` leaves room without committing to anything.
- User-level settings, hook customization options, non-default matchers.
