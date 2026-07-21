# Append Concurrency Lock - Design

Date: 2026-07-21
Status: approved for planning
Scope: backlog item 1 (append concurrency robustness). The related
install-warn refinement, the visible-session-start-success fix, and
external anchoring are tracked separately and out of scope here.

## 1. Problem

`MemAttest.record`/`adopt`/`init` perform a read-all-then-append sequence
with no mutual exclusion: count the entries, append entry index N,
recompute the Merkle root over all leaves, append a signed tree head, write
the config. Concurrent memattest processes racing through this corrupt the
log two ways:

- **Entry index collision (common, benign today).** Two processes pick the
  same next index; the loser hits the index check and aborts before writing
  anything, so the log stays consistent but the write is dropped and an
  `entry index N != next index N+1` error surfaces.
- **Tree-head ordering (rare, corrupting).** Two processes interleave so
  that the highest-numbered tree-head file ends up covering fewer leaves
  than exist. Verify's "the latest tree head must cover all leaves" check
  then reports `root-mismatch` - a false tamper alarm on a genuine log.

Concurrency arises without any misconfiguration: two Claude Code sessions
running against the same project share one memory directory and both fire
the PostToolUse hook, and (harness-dependent) a single session issuing
parallel file edits can fire overlapping hooks. Duplicate hook registration
across settings scopes is the most reliable trigger but not the only one.

Making just the entry-file write atomic does not fix the tree-head ordering;
the seal step reads a leaf count at one moment and writes its tree-head file
at a later moment, and another process can slip an append-plus-seal in
between. The whole append-and-seal sequence must be serialized.

## 2. The lock

Add `filelock` (>=3) to the runtime dependencies (pure Python, no transitive
dependencies). Its default `FileLock` uses OS advisory locks, so a process
killed mid-append releases the lock instantly - no stale lock file can wedge
the log.

A helper `MemAttest._append_lock()` returns
`FileLock(str(self.state_dir / "append.lock"), timeout=T)` with a default
`T` of 10 seconds. The lock file lives inside `.memattest/`, which is
already excluded from guarding (so verify never flags it as `unlogged`) and
is not matched by the `entries/*.json` or `sth/*.json` globs that count
files. `filelock` leaves an empty lock file behind on release; there it is
harmless.

`record`, `adopt`, and `init` each wrap their entire body in the lock:

```
self.state_dir.mkdir(parents=True, exist_ok=True)   # lock file needs a home
with self._append_lock():
    ...precondition checks, _append, _seal_current_tree, _write_config_if_named...
```

Two ordering points:

- The `mkdir` runs before acquiring so the lock file has a home even on a
  fresh `init` (the memory directory always exists; `.memattest` may not).
- The precondition checks (e.g. `init`'s "already initialized", `record`'s
  "not initialized") move inside the lock, so two concurrent `init`s
  serialize: one initializes, the other acquires next, re-checks, and fails
  cleanly with "already initialized" instead of racing.

On timeout the `FileLock` raises; translate it to `MemAttestError` -> exit 2
("could not acquire the append lock"). Under normal contention the wait is
milliseconds; a timeout only fires if something is genuinely wedged, where
erroring beats hanging the hook forever.

## 3. Verify: consistent snapshot, minimal hold

`verify` acquires the same lock only around the reads of the log - loading
the entries and the tree heads into memory - then releases before the
cryptographic and file-state checks run on that in-memory snapshot.

This closes the remaining false-alarm window: without it, a session-start
verify landing mid-append could read N+1 entries but a latest tree head
covering only N and report a spurious `root-mismatch`.

The lock is held only for the file reads, not the compute, deliberately.
Verify's tree-head loop is O(entries squared) (a pre-existing inefficiency
tracked separately), so on a large log the crypto phase can reach hundreds
of milliseconds to seconds; holding the lock through it would block appends
for that whole time, right at session start. Releasing after the snapshot
read decouples verify's compute time from append latency - appends only ever
wait for the quick read.

Holding through the full verify would add no robustness: the entry-vs-tree-
head consistency that the lock secures is fully captured the instant the
snapshot is read, and verify's file-hashing phase cannot be protected by
this lock in either design. The reason is architectural, not fundamental:
in this hook-driven design memattest runs only *after* the agent's write,
via a separate short-lived PostToolUse process, and holds no process across
the write itself, so the append lock can never overlap it. (A mediated-store
design, where memattest performs the write and appends under one held lock -
the roadmap's "MCP tool as the only write path" direction - could guard the
write and eliminate the transient; it is out of scope here.) So a file
edited around verify time can produce a transient `modified` regardless;
that is benign (verify is advisory and the next run, after the append lands,
is clean) and is a separate concern from append serialization.

## 4. Testing

- **Cross-process contention (core test):** launch N processes (via
  `multiprocessing`) that each run a `record` against the same initialized
  log, released together, then assert (a) exactly N new entries landed - no
  lost writes, no exceptions - and (b) `verify` is clean, proving the
  tree-head chain stayed consistent. A single-process threaded test does not
  suffice: `filelock` is reentrant within a process, so only separate
  processes exercise the real serialization. Mildly probabilistic, but N
  racing processes reliably force contention.
- **Timeout maps to an operational error:** hold the lock in one place and
  assert a second `record` raises `MemAttestError` / exits 2 with the
  "could not acquire" message rather than hanging.
- **Lock placement:** assert the lock file is created at
  `.memattest/append.lock`, and that verify still passes with it present (it
  is neither counted as an entry nor flagged `unlogged`).
- The full existing suite stays green: the lock is transparent to all
  current single-threaded tests.

## 5. Out of scope

- **install-warn** for duplicate hook registration across settings scopes
  (prevention for the most common trigger) - its own follow-up.
- The **O(entries squared) verify recomputation** - a pre-existing
  inefficiency; this design only avoids holding the lock across it.
- Visible-session-start-success fix and external root anchoring - separately
  tracked.
