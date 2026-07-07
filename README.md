# memattest

memattest makes an AI agent's persistent memory **tamper-evident**. Every write
to a guarded memory file becomes a signed, provenance-stamped leaf in an
append-only RFC 6962 Merkle log, and every leaf is periodically sealed under a
signed tree head (STH) — an Ed25519 signature over the current root hash,
chained to the previous STH by a consistency proof. Verification recomputes
the tree from the entries on disk, checks that every STH in the chain is both
correctly signed and a consistent extension of the one before it, and diffs
the log's derived expected state against the actual files in the memory
directory. Any out-of-band edit, deletion, or addition to a guarded file is
detected and reported by name — *which file*, what hash was expected, what
hash was found, and at which log entry the file was last known-good. Any
attempt to reorder, truncate, or rewrite history is likewise caught by the
consistency-proof check, because the log format makes silently editing the
past mathematically distinguishable from validly extending it.

## What memattest does NOT do

memattest proves **integrity and provenance** — that a memory is unaltered
since it was recorded, that it was recorded by a specific installation, and
that it sits at a specific, unforgeable position in the write history. It
does **not** prove that a memory's *content* is true, safe, or free of
manipulation. If an agent is prompt-injected or otherwise compromised and
writes a poisoned memory through the normal, legitimate write path, memattest
records that write faithfully: hash, timestamp, provenance, and signature all
check out, because nothing about the write was out-of-band. This is
sometimes called "front-door" poisoning, and it is deliberately out of scope
for memattest — the integrity layer cannot also be the content-screening
layer without conflating two very different guarantees. For screening memory
*content* (prompt injection, PII, policy violations, and similar), pair
memattest with a complementary tool such as
[OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/);
memattest is designed to sit beneath such tools as the tamper-evidence and
sequencing layer, not to replace them.

## Quickstart

memattest requires Python 3.12 or newer. Install it into a virtual
environment — never into your system Python:

```bash
python -m venv .venv
.venv\Scripts\activate    # Windows; use `source .venv/bin/activate` on Linux/macOS
pip install -e .
```

Initialize a memory directory. This generates a per-installation Ed25519
signing key, seals it in the OS keystore, and adopts any pre-existing files
in the directory as the trusted baseline:

```bash
memattest init --memory-dir <MEMORY_DIR>
```

To wire memattest into Claude Code, copy the hooks and permission rule from
[`src/memattest/integrations/claude_code/settings-snippet.json`](src/memattest/integrations/claude_code/settings-snippet.json)
into your `.claude/settings.json`, substituting your real memory directory for
`<MEMORY_DIR>`. The template configures a `SessionStart` hook that runs
`memattest verify` before the session trusts its memory, a `PostToolUse` hook
(matching `Write|Edit`) that runs `memattest hook post-tool-use` to append an
entry after every memory write, and a permission `deny` rule for
`memattest adopt` so the agent itself can never bless its own out-of-band
changes.

Run verification at any time, not just from a hook:

```bash
memattest verify --memory-dir <MEMORY_DIR>
```

A clean log prints a single `OK <n> entries verified` line and exits 0. A
compromised log prints one `PROBLEM` line per finding — kind, path, detail,
and the last entry index known to be good — and exits 1 (or 3 if entries use an unknown scheme version — see Exit codes below).

If you edit a guarded memory file by hand between sessions (a legitimate
out-of-band change, not tampering), verification will correctly report it as
a divergence. Reconcile it with `adopt`, which appends a new signed entry
recording the file's current hash together with a required justification:

```bash
memattest adopt <MEMORY_DIR>/notes.md --reason "manual correction of stale project name" --memory-dir <MEMORY_DIR>
```

`adopt` only runs from an interactive terminal and asks for typed
confirmation; there is no non-interactive or `--yes` flag, by design (see
Security limitations below).

One Windows-specific note for anyone testing the `hook post-tool-use`
subcommand by hand: piping JSON into `memattest.exe` from Windows PowerShell
5.1 does not reliably deliver the payload on stdin, and PowerShell can also
prepend a byte-order mark that breaks JSON parsing. Use Git Bash (or WSL) for
manual hook testing; Claude Code's own hook invocation does not go through
PowerShell and is unaffected.

## Keystores

The Ed25519 signing key never touches disk unencrypted; it is always sealed
behind a `KeyStore` backend, selected with `--keystore`.

- **`--keystore keyring`** (the default) uses the OS-native credential store
  via the `keyring` package: DPAPI on Windows, Secret Service (or the
  matching desktop keyring) on Linux, and Keychain on macOS. This is the
  right choice for any interactive desktop session.
- **`--keystore file`** encrypts the key in a file (scrypt-derived AES-256-GCM,
  written with `0600` permissions) for headless hosts where no OS keyring is
  available — CI runners, containers, servers without a logged-in desktop
  session. It requires the `MEMATTEST_PASSPHRASE` environment variable to be
  set on every invocation; there is no default or embedded passphrase.

```bash
MEMATTEST_PASSPHRASE="correct horse battery staple" \
  memattest init --memory-dir <MEMORY_DIR> --keystore file
```

Use the same `--keystore` choice consistently for a given memory directory —
each backend seals the key under a name derived from the memory directory's
resolved path, so switching backends after `init` means memattest can no
longer unseal the original key.

## Extending provenance

Every recorded entry carries a `provenance` block built by collecting claims
from a set of providers. memattest ships built-in providers for the agent
harness, the writing process (pid, executable, parent-process chain), the
machine (hostname, a stable machine id), and the session (user, session id,
whether the write happened at an interactive TTY). Third parties can add
their own claims without touching memattest's source by registering a Python
entry point in the `memattest.providers` group. A provider is any zero-argument
callable that returns a JSON-serializable dict; its return value is recorded
under the entry point's name in every subsequent entry.

The canonical example is a **git workspace provider** — useful because it
ties a memory write to the exact code state the agent was working against:

```python
# in your package
def git_workspace_claims() -> dict:
    import subprocess
    def _git(*args):
        return subprocess.check_output(["git", *args], text=True).strip()
    return {
        "repo": _git("rev-parse", "--show-toplevel"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "head": _git("rev-parse", "HEAD"),
    }
```

```toml
# in your package's pyproject.toml
[project.entry-points."memattest.providers"]
git_workspace = "your_package.providers:git_workspace_claims"
```

Once installed, every memattest entry recorded in that environment will carry
a `git_workspace` claim alongside the built-ins. A provider that raises an
exception cannot abort the write or take down the other providers: memattest
isolates each provider call and records `{"error": "..."}` for the failing
one instead, so a broken plugin degrades provenance richness rather than
availability.

## Security limitations

memattest v1's threat model is deliberately scoped. It protects against an
unprivileged process or a different OS user tampering with memory files on
disk out-of-band, and against a compromised or prompt-injected agent trying
to alter, delete, or reorder its own past memories through the log itself.
It does **not** protect against a fully privileged attacker running as the
same user memattest itself runs as:

**Malware running as your own OS user can unseal the signing key and forge
history. memattest v1 protects against other users' processes and against
agents rewriting their own history — not against same-user malware. A v2
resident validator service under a separate account is the planned
mitigation.**

A few related boundaries are worth stating plainly:

- **Admin/SYSTEM-level attackers are out of scope.** Defending against an
  attacker with administrative privileges would require TPM-backed key
  sealing or an external root of trust; v1 has neither.
- **Remote or synced memory stores are out of scope.** Key distribution and
  multi-device identity are unsolved in this version; memattest assumes a
  single local installation with a single signing identity.
- **Same-user tampering routed through `adopt` cannot be silent.** Even if
  same-user malware unseals the key and calls `adopt` to launder a bad state
  into the log, it still leaves a permanent, signed `adopt` entry — including
  the parent-process chain and whether the call came from an interactive TTY
  — so the event remains visible to anyone who later inspects the log with
  `memattest log`, even though it was not blocked.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean — no tampering or inconsistency detected |
| 1 | Tamper detected — see the printed `PROBLEM` lines for file, hashes, and last-valid entry |
| 2 | Operational error — e.g. not initialized, keystore unavailable, malformed hook payload; appends fail closed rather than record an unverifiable entry |
| 3 | Unknown scheme version — an entry was written by a newer scheme than this verifier understands, and is refused rather than guessed at |
