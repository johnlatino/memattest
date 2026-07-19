# Watch List — Design

Date: 2026-07-17
Status: approved for planning
Scope: roadmap item 3. The standalone config-sealing sub-project considered
first was dropped — see §8.

## 1. Problem

memattest guards files inside the memory directory. The hook configuration
that makes it run — the Claude Code settings file, and instruction files
like `CLAUDE.md` — lives outside that directory and is unguarded. An
out-of-band edit to the settings file (adding a malicious hook, changing a
matcher) or to `CLAUDE.md` (injected instructions) is invisible to
memattest today. The watch list extends coverage to designated external
files so such edits are reported at the next session start.

## 2. Design summary

A watched file is recorded as an ordinary log entry, distinguished by a new
`scope` field. Because watch data lives in the signed, append-only log, the
existing Merkle tree and signed-tree-head checks protect it with no new
integrity mechanism — deleting a mid-log watch entry is the same log
tampering the tree and consistency checks already catch (suffix truncation
is the log's existing rollback limitation — see §7). Verify hashes each watched file
at its recorded absolute path and reports divergence like memory tampering.
Reconciliation reuses `adopt`; removal is a new guarded `unwatch` command.

The scheme stays `"v1"` — the entry format is extended, not versioned.
Since there are no external adopters, this repo's own log is
re-initialized once so every entry carries the new field explicitly.

## 3. Entry model

Every entry carries `scope`:

- `scope: "memory"` — a file inside the memory directory. `path` is
  memory-directory-relative (today's behavior). This is written explicitly
  on all entries going forward.
- `scope: "watch"` — a designated external file. `path` is the file's
  absolute, resolved path (`Path(p).resolve().as_posix()`).

Watched files use the same ops as memory files except `write`: `adopt`
establishes or re-establishes a baseline hash, `delete` (via `unwatch`)
stops watching. There is no `write` for watched files — nothing hooks their
edits; memattest baselines them with `adopt` and detects out-of-band changes
at verify. Replay is uniform: `adopt` sets a watched file's expected hash,
`delete` drops it from coverage, exactly like memory's derived state.

Reader code reads `entry.get("scope", "memory")` so any entry lacking the
field is treated as memory, but every entry this feature writes includes it.

## 4. Verify

The state-conformance check partitions replayed state by scope:

- **Memory** (`scope: "memory"`): checked against the files in the memory
  directory, including the `unlogged` check for un-recorded files appearing
  there — unchanged from today.
- **Watch** (`scope: "watch"`): for each watched file, hash the file at its
  recorded absolute path and compare to the baseline.

Watch findings:

- `modified` — the file exists but its hash differs from the baseline.
- `missing` — the file was recorded as watched but is absent on disk.
- No `unlogged` for watch: the watch list is an explicit set of named files,
  not a directory swept for extras.

Edge cases: a watched file that is absent → `missing` (exit 1). A watched
file that exists but cannot be read (permission error) → operational error
(exit 2); verify refuses rather than guessing. Each watch finding carries
the absolute `path` (visually distinct from memory's relative paths) and
`scope` so machine consumers can tell them apart.

No hook change is needed: the session-start hook already runs verify, which
replays every entry including watch entries, so an out-of-band edit surfaces
at the next session start automatically.

## 5. Commands

Every operation on a watched file is a trust operation and gets the same
protections `adopt` has (interactive terminal, typed confirmation,
provenance, required `--reason`, agent-blocking guard).

- **Start watching / re-bless** → `adopt`, extended to accept a path
  outside the memory directory. Scope is inferred from location: a path
  under the memory directory is a memory adopt; a path outside it is a watch
  adopt. The first adopt of an external file sets its baseline; a later
  adopt of the same file re-blesses it after a legitimate edit. `--memory-dir`
  is required for watch adopts, since an external path cannot indicate which
  log should watch it. Adopt's path handling branches on scope: memory paths
  are validated as under the directory (as today); watch paths are stored
  absolute and are deliberately not required to be under it. No new guard
  surface — agents already cannot run `adopt`.
- **Stop watching** → new `unwatch` command. Removing coverage is the
  dangerous direction, so `unwatch` gets adopt-level protection (TTY, typed
  confirmation, `--reason`, `--memory-dir`) plus its own `PreToolUse` deny
  pattern beside `adopt` and `install`. It appends a `scope: "watch"`,
  `op: "delete"` entry, dropping the file from derived watch state. It also
  clears the `missing` finding for a watched file you legitimately deleted.

## 6. Onboarding and reconciliation

**Onboarding via install.** The installer writes the settings file worth
watching, so after merging the hooks its plan gains one line: adopt-watch
the settings file it just wrote. That file rarely changes, so it is a
low-noise default, and it means memattest watches its own hook configuration
out of the box. `CLAUDE.md` and other files are opt-in via `adopt`, since
they change often and watching them is a cost the user should choose.

**Reconciliation without rubber-stamping.** Watched files change more often
than memories, so re-blessing must not become reflexive. Two parts, no new
mechanism: keep the default watch set to rarely-changing files (the settings
file), and reuse adopt's existing friction for re-blessing — typed
confirmation, a required reason, and a permanent provenance-stamped entry.
Every re-bless is a deliberate, recorded act. Alarm fatigue is managed by
not watching churny files by default, not by weakening the confirmation.

## 7. Security posture

The watch list catches out-of-band edits to the trust surface by in-scope
actors — a sync client, another local account with write access, a human
editing between sessions — and surfaces them at the next session start. It
is the detection complement to the PreToolUse guard's prevention.

Two honest boundaries:

- **Total hook removal is not caught by the watch list.** If an attacker
  removes the memattest hook from the settings file, verify never runs, so
  the watch check on that file never runs — the tampering disables its own
  detector. The remaining signal is a human noticing memattest went silent:
  the expected `memattest: OK N entries verified` line is absent at session
  start. This is not an automated check and cannot be one within v1; the v2
  validator, running under a separate account, closes it.
- **Suffix truncation needs only file access.** An attacker who can write the
  state directory can delete the newest entries together with their covering
  tree heads; the surviving tree heads still verify and the latest still
  matches the truncated length, so `verify` does not detect it — no signing
  key required. This is the log's existing rollback limitation, and it bites
  watch coverage harder than memory: a watched file on disk with no entry is
  indistinguishable from one never watched, so a dropped watch entry leaves no
  disk-side trace. Mid-log deletion of a watch entry is still caught by the
  tree and consistency checks. The v2 validator, and an external anchor for
  the latest tree head, close the rollback gap; same-user malware (which can
  also re-sign) remains the validator's domain too.

## 8. Why standalone config sealing was dropped

An earlier plan split this work into config sealing first, then the watch
list. Two findings collapsed that split:

- The current config holds one value (`keystore`), and every lie a
  file-write-only attacker can tell about it is already fail-noisy without
  sealing (per the per-log-config spec §6). So standalone sealing protected
  nothing that exists — its only purpose was to protect watch-list content.
- Choosing to store watch data in the log (rather than a config table) means
  the log's signatures protect it directly. No config sealing is needed at
  all.

This also corrects the per-log-config spec, which named "config sealing" as
the closer for the exported-passphrase config-redirect attack. That was
wrong: the redirect requires knowing an exported `MEMATTEST_PASSPHRASE`,
which requires same-user access, which also lets the attacker delete the
keyring entry any contradiction-check would rely on. The redirect is
same-user malware and is closed by the v2 validator, not by sealing.

## 9. Testing

- **Unit:** `scope` round-trips through entry build and replay; derived
  state partitions by scope; existing memory-entry tests unaffected by the
  added field.
- **Verify:** a watched file modified → `modified`; deleted → `missing`;
  unreadable → operational error; no `unlogged` for watch; memory checks
  unchanged.
- **Commands:** `adopt` of an external path creates a `scope: "watch"` entry
  and requires `--memory-dir`; `unwatch` drops it and clears a `missing`
  finding; both refuse without a TTY and are denied to agents by the
  `PreToolUse` guard (bare, quoted, path-prefixed, `.exe` spellings).
- **End-to-end on this machine:** re-initialize the live log, adopt-watch
  its settings file, edit that file, confirm session-start verify reports
  the change; unwatch it and confirm the report clears.

## 10. Out of scope

- Real-time watching and same-user-proof checking (v2 validator).
- Suppressing watch findings during a copied-log audit on another machine
  (watched paths are local; a foreign machine reports them `missing`, which
  is expected and documented). A `--skip-watch` flag is a possible future
  addition, not built now.
- Watching directories or globs — only individually named files.
- Any config-table or config-sealing mechanism (§8).
- Sealing the latest tree size/head in the backend keystore so verify can
  detect suffix truncation without the separate-account validator is a
  possible v1.x hardening, not built here.
