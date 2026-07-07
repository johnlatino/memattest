# memattest — Design Specification

**Date:** 2026-07-06
**Status:** Draft for review
**Deliverable:** Python prototype (library + CLI) with a Claude Code integration

## 1. Problem statement

AI agents accumulate persistent memories (files, notes, learned context) that shape their future behavior. Today there is no standard way to detect that a stored memory has been tampered with, reordered, deleted, or forged after the fact. An attacker — or a compromised agent itself — can rewrite an agent's past, and nothing flags it. OWASP identifies this as **ASI06: Memory Poisoning** in the Top 10 for Agentic Applications.

`memattest` makes an agent's memory store **tamper-evident**: every memory write becomes a signed, provenance-stamped entry in an append-only cryptographic log, and any out-of-band modification, reordering, or history rewrite is detected and reported precisely.

### What memattest does NOT claim

memattest proves **integrity and provenance** — that a memory is unaltered since it was recorded, was recorded by a specific installation, and sits at a specific position in the sequence. It does **not** prove the memory's content is *true* or *safe*: a prompt-injected agent writing a poisoned memory through the legitimate path produces a perfectly valid, fully attested entry. Content screening is the province of complementary tools (e.g., OWASP Agent Memory Guard); memattest is intended to be the integrity/sequence layer beneath them.

## 2. Threat model

Data flow and adversary positions ([A1], [A2] are the two in-scope adversaries):

```
                     ┌─────────────────────────────┐
                     │    Agent harness session    │
                     │     (e.g., Claude Code)     │
                     └───────┬─────────────┬───────┘
                             │             │
                  1. agent writes      2. hooks invoke CLI
                     memory file          SessionStart → verify
                             │            PostToolUse  → append
                             ▼             ▼
                     ┌───────────────┐   ┌──────────────────────┐
  [A1] out-of-band   │  Memory dir   │◀─▶│    memattest CLI     │
  file tampering ┄┄▶ │  (guarded     │   │ append / verify /    │
  detected by state  │   files)      │   │ adopt (human-only)   │
  conformance check  └───────────────┘   └──────┬────────┬──────┘
                                                │        │
                             append entries and │        │ unseal signing key;
                             signed tree heads  │        │ verify with pubkey
                                                ▼        ▼
  [A2] history rewrite     ┌──────────────────────┐   ┌─────────────────┐
  (alter / reorder /  ┄┄▶  │ .memattest/          │   │ OS keystore     │
  truncate the log)        │ entries/ sth/ pubkey │   │ (sealed Ed25519 │
  detected by consistency  └──────────────────────┘   │  signing key)   │
  proofs between STHs                                 └─────────────────┘
```

### In scope (v1)

| Adversary | Attack | Defense |
|---|---|---|
| Unprivileged process or other user | Edits, adds, or deletes memory files on disk out-of-band | Verification diffs actual files against log-derived expected state; root key sealed in OS keystore |
| Compromised / prompt-injected agent | Alters, deletes, or reorders *past* memories through legitimate channels | Append-only log semantics; consistency proofs between successive signed tree heads; agent denied access to `adopt` |

### Out of scope (v1, documented limitations)

- **Same-user malware.** Code running as the same OS user can unseal the signing key (keystore backends protect against *other* users and offline theft, not the owner's own session). This will be mitigated in v2 by a resident validator service under a separate account. Even in v1, same-user tampering that goes through `adopt` leaves a permanent signed record (see §8).
- **Admin/SYSTEM-level attackers.** Requires TPM sealing or external root anchoring; deferred.
- **Remote/synced memory stores.** Key distribution and multi-device identity deferred.
- **Content poisoning through legitimate writes ("front-door" poisoning).** A compromised or prompt-injected agent recording a malicious memory through the normal write path, which produces a validly attested entry. By design out of scope (see §1).
- **Trust anchor.** v1 verification trusts the public key file stored in `.memattest/`; an attacker with write access to the memory directory can replace it, rewrite history, and re-sign with their own key undetected. Mitigations: keystore-sealed pubkey cross-check (fast-follow), external root anchoring (v2).
- **Rollback.** Deleting a suffix of entries together with their covering tree heads and created files reverts the log to an earlier, fully valid sealed state undetected. Requires an external anchor for the latest tree head (v2).

## 3. Goals and non-goals

**Goals**

1. Detect any out-of-band modification, addition, or deletion of guarded memory files, reporting *which file* and *since which entry*.
2. Detect any rewrite, reorder, or truncation of memory history via consistency proofs.
3. Record extensible provenance (process, machine, session, custom plugins) with every write.
4. Cross-platform: Windows and Linux from v1 (macOS expected to work via the same abstractions).
5. Harness-agnostic core library; adapter implementation provided to support Claude Code. Adapters can be easily created to support Codex, Gemini CLI and others.
6. Survive agent/harness upgrades without rehashing history (per-entry scheme versioning).

**Non-goals (v1)**

- Content analysis (injection/PII detection) — compose with OWASP Agent Memory Guard instead.
- Enforcement (blocking writes) — v1 detects and reports; enforcement arrives with the v2 mediated paths.

## 4. Prior art and differentiators

| Project | What it does | Gap memattest fills |
|---|---|---|
| [OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/) (Incubator, 2026; ASI06 reference impl.) | Runtime read/write screening: flat SHA-256 baselines, injection/PII/size detectors, YAML policy | No hierarchical or sequential validation; no signatures; no provenance; fixed detector set |
| [memledger](https://pypi.org/project/memledger/) (alpha) | Attribution/provenance/confidence scoring atop vector memory stores | No cryptographic tamper-evidence or sequence proofs |
| Portable Agent Memory (arXiv 2605.11032) | Provenance-verified memory *transfer* between agents | Research protocol, not a guarding tool for a live store |
| ECDH-keyed Merkle chains (arXiv 2506.13246); Right to History (arXiv 2602.20214) | Academic frameworks for immutable agent memory / verifiable execution | No production implementation or harness integration |

**Differentiators:** (a) sequential integrity via a real transparency-log construction, not flat hashes; (b) an extensible provenance-provider plugin interface; (c) signed roots with an explicit trust anchor; (d) a no-rehash upgrade policy that preserves historical tamper-evidence; (e) practical implementation tested with Claude Code harness.

## 5. Architecture

**v1 shape: hook-driven CLI.** No resident process. A Python package `memattest` exposes a library API and a CLI. Agent-harness hooks invoke the CLI at well-defined moments (session start → verify; post-write → append). All state lives in a directory next to the guarded memory directory. The signing key is sealed in an OS keystore.

Rejected alternatives, revisitable later: a resident validator service under a separate account (v2 — real privilege separation, near-real-time detection) and a fully mediated store where writes flow through a memattest-owned MCP tool (enforcement rather than detection, but harness-invasive).

### Components

```
memattest/
├── log/         # RFC 6962 append-only Merkle log: append, inclusion proofs,
│                # consistency proofs. Leaf = SHA-256(0x00 ‖ entry);
│                # interior = SHA-256(0x01 ‖ left ‖ right).
├── provenance/  # Provider plugin interface (entry-point group
│                # "memattest.providers"). Each provider returns a named dict
│                # of claims. Built-ins: agent, process, machine, session.
├── identity/    # Per-installation Ed25519 keypair behind a KeyStore
│                # abstraction: seal(bytes) / unseal() -> bytes.
│                # Backends: keyring (default; DPAPI / Secret Service /
│                # Keychain), encrypted file (headless fallback, 0600).
│                # Future: systemd-creds (TPM), Vault, cloud KMS.
├── seal/        # Signed Tree Heads (STH): {tree_size, root_hash, timestamp,
│                # signature}. STHs form their own append-only chain; each new
│                # STH must carry a consistency proof against its predecessor.
├── cli/         # memattest init | record | verify | adopt | log | prove
└── integrations/claude_code/   # hook scripts + settings snippets
```

The canonical example of a **third-party provenance provider** is a git workspace provider (repo, branch, HEAD commit at write time). It would tie each memory to the code state that the agent was working with. Built-in providers use `psutil`/stdlib only.

## 6. Data model

Memory files are mutable (MEMORY.md changes constantly), so the log records immutable *write events*; current expected state is derived as the latest event per path.

Each leaf is a canonical-JSON (UTF-8, no insignificant whitespace) record:

```json
{
  "scheme": "v1",
  "index": 42,
  "timestamp": "2026-07-06T14:03:22Z",
  "op": "write | delete | adopt",
  "path": "memory/project-goals.md",
  "content_hash": "sha256:...",
  "reason": "(required for adopt, absent otherwise)",
  "provenance": {
    "agent":   { "harness": "claude-code", "version": "..." },
    "process": { "pid": 1234, "exe": "..." , "parent_chain": ["..."] },
    "machine": { "hostname": "...", "machine_id": "..." },
    "session": { "id": "...", "user": "...", "interactive_tty": false }
  }
}
```

**Storage layout** (itself excluded from guarding):

```
<memory-dir>/.memattest/
├── entries/000000.json …    # one canonical-JSON file per leaf
├── sth/000000.json …        # append-only chain of signed tree heads
└── pubkey.ed25519           # public key, stored in the clear
```

Entries are plain JSON on disk deliberately: the log is inspectable and reconstructable by a human with no tooling.

**Identity:** the per-installation Ed25519 keypair is the identity. Environmental properties (PID, machine ID, IP) are *claims recorded inside entries* — useful provenance, but never treated as identity, since they are spoofable and recycled.

## 7. Operations

**Record** (post-write hook, CLI `memattest record`): hash the written file → gather claims from all registered providers → build canonical entry → append leaf → compute new root → sign STH with consistency proof against the previous STH → append STH to chain.

**Verify** (session-start hook, or on demand). Three independent checks, all must pass:
1. **Tree integrity:** recompute the Merkle tree from entries; root must match the latest STH, whose signature must verify against the public key.
2. **History consistency:** every successive STH pair must satisfy an RFC 6962 consistency proof (today's log is an append-only extension of yesterday's — no rewrite, reorder, or truncation).
3. **State conformance:** derive expected current state (latest event per path); diff against actual files. Divergence = out-of-band tampering, reported as *file X, expected hash H₁, found H₂, last valid at entry N (timestamp T)*.

Verification of tree structure and file state requires only the **public** key; the sealed private key is needed only to append/seal. Exit codes distinguish: 0 clean · 1 tamper detected · 2 operational error · 3 unknown scheme version.

**Inspect** (`memattest log`, `memattest prove`): `log` prints entries human-readably; `prove` emits an RFC 6962 inclusion proof for a given entry or a consistency proof between two tree sizes, as JSON, so third parties holding only the public key and an STH can independently verify a memory's presence and position.

**Adopt** — the only way to allow out-of-band edits. Appends a signed `adopt` event recording the current content hash of named files with full provenance and a required `--reason`. Three uses: (1) initial baseline (`memattest init` runs an adopt over pre-existing memories); (2) legitimate out-of-band edits (human hand-edits a memory file between sessions); (3) post-tamper acceptance. **Adopt appends; it never rewrites.** The divergence it forgives remains permanently visible in history: an auditor sees writes through entry N, then an adopt at N+1 whose hash contradicts entry N's prediction, with timestamp, provenance, and reason.

## 8. Adopt protections

Adopt is the most dangerous command (the one way to make untracked changes trusted), and the v1 threat model includes a compromised agent. Therefore:

1. **Interactive-only:** `adopt` refuses to run without a TTY and requires typed confirmation; there is no `--yes`/`--auto-adopt` flag by design.
2. **Denied to the agent:** the shipped Claude Code configuration adds a permission deny rule for `memattest adopt`.
3. **Audited regardless:** the adopt entry's provenance records the parent-process chain and `interactive_tty` flag, so an adoption invoked from an agent or script — even if (1) and (2) were bypassed — is distinguishable from one typed by a human in a shell.

`verify` failure output lists remediation options (restore-and-reverify, or adopt) but never performs adoption itself.

## 9. Versioning and upgrade policy

Every entry carries a `scheme` field. Verifiers dispatch per entry and must support all historical schemes (backward-compatibility layer). **Old entries are never rehashed or migrated:** rehashing would launder any pre-migration tampering into validly signed history and make the migration tool itself a prime attack target. When a scheme or key rotates, the new configuration **countersigns** the old log: it verifies the existing chain, then records a `checkpoint` STH — an ordinary STH plus a `type: "checkpoint"` marker and the countersigning key's ID — signed by the new key over the old root. In this way, history accumulates signatures and is never rewritten. Entries with a scheme newer than the verifier are reported as unverifiable.

## 10. Claude Code integration

Configured in `.claude/settings.json`:

- **SessionStart hook** → `memattest verify <memory-dir>`. Clean pass emits one line at most. Failure emits a structured report into session context so both the user and the agent know the memory is suspect before trusting it; hook config chooses warn-vs-block via exit code.
- **PostToolUse hook** (Write|Edit matching the memory directory) → `memattest hook post-tool-use`, which records the write, reading the hook JSON payload from stdin.
- **Permission deny rule** for `memattest adopt` (§8).

Failure of a hook to fire (crash between file write and append) is handled as follows: The next verify reports the file as diverged. A human then needs to review and can reconcile via adopt. This approach intentionally requires a human in the loop for verification.

The integration layer is deliberately thin; LangChain/mem0-style middleware adapters can follow the Memory Guard integration pattern in later versions without touching the core.

## 11. Error handling

Exit codes per §7: 0 clean · 1 tamper detected · 2 operational error · 3 unknown scheme version.

| Condition | Behavior |
|---|---|
| Tamper detected | Report precisely (file, hashes, last-valid entry); never auto-repair; exit 1 |
| KeyStore unavailable (locked keyring, headless without Secret Service) | Verify still runs (public-key only). Appends fail **closed**: refuse to record unverifiable entries and tell the agent memory recording is paused; exit 2 |
| Unknown `scheme` version | Refuse to validate those entries, state why; exit 3 |
| Log/STH corruption | Entries are plain JSON — reconstructable by inspection; worst case re-baseline via adopt (loud, signed, permanent) |
| Hook missed a write | Next verify flags divergence; reconcile via adopt |

## 12. Testing strategy

1. **Unit:** RFC 6962 hashing validated against the RFC's published test vectors; inclusion and consistency proofs property-tested (Hypothesis: any log prefix proves consistent with any extension of itself; any mutation fails).
2. **Attack simulations — one test per threat-model claim:** bit-flip a guarded file; reorder two entries; truncate the log; replace an entry wholesale; forge an STH without the key; back-date a timestamp; delete a guarded file; add an unlogged file. Each must be detected AND the report must name the correct file/entry.
3. **Adopt semantics:** adopt-then-verify passes; history before the adopt still shows the divergence; adopt without TTY refuses.
4. **Integration:** drive the real CLI against a temp memory dir with simulated hook payloads, on a Windows + Linux CI matrix; `KeyStore` faked in tests, `keyring` smoke-tested per platform.
5. **Dogfood:** install the hooks in this repository's own `.claude/settings.json`, guarding the memory directory of the sessions used to build memattest.

## 13. Future work (explicitly out of v1)

- v2 resident validator service under a separate OS account (closes the same-user-malware gap; near-real-time watching).
- TPM-backed keystore backends (`systemd-creds`, Windows TPM APIs); external root anchoring (transparency log / RFC 3161 timestamping) against admin-level attackers.
- Mediated-store mode (MCP tool as the only write path — enforcement, not just detection).
- Middleware adapters for LangChain / mem0 / AutoGen; possible positioning as a complement or contribution to OWASP Agent Memory Guard.
- Remote/synced store support (key distribution, multi-device identity).
- Per-log `config.toml` in `.memattest/` recording the keystore backend chosen at init (plus provider config and guard globs). Today the backend is a per-invocation `--keystore` flag; verifying with a different backend than the log was initialized with produces a confusing key-not-found error instead of a clear "this log uses the file backend" message. Dropped from v1 scope during planning.
