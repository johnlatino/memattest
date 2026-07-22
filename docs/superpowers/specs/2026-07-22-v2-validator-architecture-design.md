# memattest v2 Resident Validator - Architecture and Decomposition

Date: 2026-07-22
Status: approved for decomposition (parent spec)
Scope: the overall v2 validator effort. This is the umbrella spec. Each
sub-project (SP1-SP4) gets its own design spec, implementation plan, and build
cycle that references this document. No single sub-project ships the whole
security guarantee on its own; see the build order and security boundary below.

## 1. Goal

Close two v1 gaps that a session-bound, same-account check cannot close:

- **Same-user (non-admin) malware that re-signs history.** An attacker running
  as the user can unseal or replace the signing key in the backend keystore,
  rewrite the log, re-sign every tree head, and swap the on-disk
  `pubkey.ed25519`. A `verify` run by the same user cross-checks the on-disk
  pubkey against the keystore-derived key, but both are now attacker-controlled,
  so it passes.
- **Rollback / suffix truncation.** Deleting a suffix of entries together with
  their covering tree heads reverts the log to an earlier, fully valid sealed
  state. This needs only file access, no signing key, and the surviving tree
  heads still verify, so `verify` does not detect it.

The v2 validator is a resident service under a separate OS account that watches
guarded logs out of band and detects both, reporting findings back to the user
and the agent.

## 2. Threat model

**In scope:** same-user, non-admin malware or processes (including the re-sign
and rollback attacks above), other unprivileged users, and offline theft
(already covered by the v1 backend keystores).

**Out of scope, by design:**

- **Admin / SYSTEM (root) attackers.** An attacker at that privilege can
  rewrite the validator, its storage, the memattest binary, or the OS itself,
  so a purely local defense against them is futile without a hardware root of
  trust and bypassable even then. memattest does not invest in defenses whose
  only benefit is against admin/SYSTEM attackers.
- **Off-machine anchoring** (RFC 3161 timestamping / transparency log). This is
  the only defense against the admin-level rollback case and is therefore
  deferred post-v2 and possibly permanently, per the decision above.

## 3. Trust model

The validator's power comes from one thing the separate OS account buys:
**state the user account cannot write.** Per enrolled log, the validator keeps
two pinned facts in storage only the service account can modify:

- A **pinned public key**, captured at enrollment. Every tree head must verify
  against this key. This defeats the re-sign attack: the validator never trusts
  the on-disk `pubkey.ed25519` or the backend keystore, so swapping them does
  not help the attacker; forged history signed with any other key fails as a
  bad signature.
- A **high-water mark**: the greatest `tree_size` seen and its `root_hash`. The
  validator advances it only when the current log is a valid append-only
  extension of the anchored state, signed by the pinned key. This defeats
  rollback: a log that shrank below the high-water mark, or whose root at the
  anchored size changed, is a truncation or a rewrite.

If the user account could write that store, malware would roll the anchor back
too. So the account isolation is the security, not an add-on to it. The real
security guarantee therefore lands only when the isolation lands (SP3).

## 4. Scoping decisions

- **Windows-first.** The privilege separation and service machinery are
  OS-specific and are the riskiest part of the work, so v1 targets Windows 11
  (the primary and development environment). The platform-agnostic detection
  core is shared, so Linux (systemd) and, if ever targeted, macOS (launchd)
  become focused fast-follows that add only the per-platform service-install
  and service-state-query adapters. macOS is not a currently stated memattest
  platform (the CI matrix is Windows + Linux).
- **Registry-shaped, one log in v1.** The anchor store and enrollment are
  designed around a registry of many enrolled logs, each with its own pinned
  key and high-water mark, because a machine accumulates one log per project.
  The first working validator only needs one log enrolled and watched;
  designing the model registry-shaped now avoids a painful retrofit later.
- **Sticky detections.** The validator cannot distinguish a legitimate change
  from an attack when the pinned facts break (a deliberate re-init looks
  identical to a malicious re-sign). So a tripped log stays reported until a
  human runs an explicit re-enrollment (re-pinning the current state as the new
  believed-good baseline). It does not auto-clear on a later return to
  consistency, since auto-clear would let a transient attack erase its own
  evidence.
- **Enrollment is trust-on-first-use.** The validator pins whatever state the
  log is in at enrollment, so enrollment must be run when the log is believed
  good. No anchor escapes this.
- **Reporting is console-only in v1.** See SP4.

## 5. Liveness

A stopped or crashed validator must not read as "all clear," the same "notice
the silence" problem the session-start work addressed. The mechanism is to ask
the OS service manager for the daemon's run state, not to trust a self-reported
heartbeat file:

- The user-account SessionStart hook queries the service manager (SCM on
  Windows via `QueryServiceStatus`; `systemctl is-active`/`is-failed` on Linux;
  `launchctl` on macOS). If the validator service is not running, the hook
  emits an advisory console line: the validator is not running and rollback /
  re-sign protection is not currently active.
- This is advisory, not a tamper alarm. Querying service state needs no
  elevation for the user account, and a non-admin cannot lie to the service
  manager about a service's state or stop a service owned by another account
  (SP3 withholds stop and config rights, not query rights). So the signal is
  trustworthy without depending on the verdict file.
- The one failure this does not catch is "running but wedged" (alive per the
  service manager but hung and not re-checking). A heartbeat would catch that;
  it is deferred (a hung service is a rarer failure than a stopped one, and it
  can be added later if hangs prove real).

An informational "last checked at HH:MM" from the verdict file may be displayed
for context, but it is not a staleness threshold alarm.

## 6. Sub-projects

**SP1 - Detection core and anchor model** (platform-agnostic, pure logic).
The registry data model (per-log record: log id, pinned pubkey, high-water
`tree_size` and `root_hash`, status), an *enroll* function (capture the pinned
key and initial high-water from a believed-good log's current state), and a
*step* function (given an anchor record and a current log snapshot, return a
verdict and the new anchor). Reuses the existing `merkle`, `seal`, and
`verify_sth` primitives. Fully unit-testable with no OS specifics and no
daemon. Verdicts: advance (legitimate extension), rollback (shrank below or
covered size below the high-water), rewrite/fork (root changed at or below the
anchored size), bad-signature/key-swap (a tree head not signed by the pinned
key), and unreadable/incomplete (a transient mid-append or corrupt snapshot).

**SP2 - Resident watcher** (platform-agnostic process).
The long-running loop: per enrolled log, notice changes (file-event watching or
polling), read the current snapshot, call SP1's *step*, persist the advanced
anchor, and emit detection events. Handles append bursts (debounce), transient
mid-append reads (re-check, the same benign transient `verify` sees), and
catch-up on startup. Runs as the same account for development and testing, with
no security claim until SP3 isolates it.

**SP3 - Windows privilege separation and enrollment procedure**
(Windows-specific; the security-defining piece).
A dedicated low-privilege service account; ACLs so the anchor store is writable
only by that account and the memory directories are readable, not writable, by
it; registration as an auto-start Windows Service running as that account; and a
human-run, elevated enrollment procedure that sets all this up and pins a log's
current state as the believed-good baseline. This turns SP1's store from
user-writable and defeatable into trusted. The chartered security gaps close
only once SP3 lands.

**SP4 - Reporting path across the account boundary** (console-only in v1).
The validator runs as another account and cannot touch the user's console, so
it writes a verdict/status file into a location it owns but the user can read.
The existing SessionStart hook reads that file and folds any validator finding
into the console output (`systemMessage` and `additionalContext`) alongside the
local verify result, and performs the liveness query (section 5). A `memattest` CLI
status subcommand reads the same file on demand. Windows toast notifications and
the Windows Event Log are deferred; between-session detections surface at the
next session start or the next manual status check.

## 7. Build order and the security boundary

Dependencies: SP2 and SP4 both consume SP1; SP3 secures SP1's store and wraps
the rest in account isolation. Suggested order: **SP1 -> SP2 -> SP4 -> SP3.**

SP1 + SP2 + SP4 produce a working same-account resident validator: continuous
watching, rollback and rewrite detection against accidental corruption, and
console reporting. It does not close the same-user-malware gap until SP3 puts
the anchor store behind the separate account. This backloading is inherent to
the design and is named here so it does not surprise anyone at the ship line.
The public "v2 validator closes the gaps" claim is only true after SP3.

## 8. Implementation notes

- The validator is a **Python process that reuses the existing memattest
  package** (its `merkle`, `seal`, `verify_sth`, `store`, and canonical-JSON
  primitives), run as a Windows Service under the separate account. It is not a
  rewrite in another language.
- The validator code lives in **this same repository**, as a new subpackage
  (for example `memattest.validator`), following the existing module and test
  conventions.
- Each sub-project follows the established workflow: its own brainstorm ->
  design spec -> implementation plan -> subagent-driven build, on its own
  branch, referencing this umbrella spec.

## 9. Out of scope (for the whole v2 effort)

- Admin / SYSTEM defenses and off-machine anchoring (section 2).
- Mediated-store mode (writes flowing through a memattest-owned tool);
  enforcement rather than detection, tracked separately.
- Windows toast notifications and Event Log reporting (SP4 defers these).
- Heartbeat-based "running but wedged" liveness (section 5 defers this).
- Key rotation without re-enrollment; a legitimate re-key is handled by the
  human re-enrollment procedure, since it is indistinguishable from an attack.
- Non-systemd Linux init systems and macOS as a committed platform.
