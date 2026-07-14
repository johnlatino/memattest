# memattest

memattest provides AI agent memory attestation. It makes an AI agent's persistent memory **tamper-evident**.

Agent memory is the information an AI agent carries between sessions- notes,
learned preferences, project context, and decisions, typically stored as
plain files that the agent reads back into context each time it starts. It 
shapes everything the agent does next, but it's vulnerable: 
anyone or anything that can write to those files can rewrite the agent's
past, and the agent will trust the result.

Making memory tamper-evident addresses this vulnerability. The agent (and the human dev running it) can
detect that a memory was altered, planted, deleted, or reordered after the
fact- before acting on it. Tampering isn't prevented, but it can no longer
succeed *silently*, so you and the agent will know that the memory was tampered with.

memattest delivers this as a small library and CLI that guard a memory
directory: hooks record every legitimate memory write into a cryptographic
log, and a verification pass at session start compares what's on disk against
what the log says should be there, reporting any divergence.

The gory details: every write to a guarded memory file becomes a signed,
provenance-stamped leaf in an
append-only [Merkle](https://en.wikipedia.org/wiki/Merkle_tree) log,
and every leaf is sealed under a
signed tree head (STH)- an [Ed25519](https://en.wikipedia.org/wiki/EdDSA#Ed25519)
signature over the current root hash,
chained to the previous STH by a consistency proof. Verification recomputes
the tree from the entries on disk, checks that every STH in the chain is both
correctly signed and a consistent extension of the one before it, and diffs
the log's derived expected state against the actual files in the memory
directory. Any out-of-band modification to a guarded file is
detected and reported with name and details: *which file*, what hash was expected, what
hash was found, and at which log entry the file was last known-good. Any
attempt to reorder, truncate, or rewrite history is likewise caught by the
consistency-proof check, because the log format makes silently editing the
past mathematically distinguishable from validly extending it. Note that rollback 
detection will be implemented in v2; see the
[rollback limitation](#security-limitations) below.

memattest proves **integrity and provenance**: that a memory is unaltered
since it was recorded, that it was recorded by a specific installation, and
that it sits at a specific, unforgeable position in the write history.

## What memattest does NOT do

memattest does **not** prove that a memory's *content* is true, safe, or free of
manipulation. If a compromised agent 
writes a poisoned memory through the normal, legitimate write path, memattest
will record that write faithfully. The hash, timestamp, provenance, and signature 
will all be valid, because nothing about the write was out-of-band. 
**memattest does not classify or validate the memory content.**
That's deliberately out of scope. For screening memory
*content* (prompt injection, PII, policy violations, and similar), pair
memattest with a complementary tool such as
[OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/);
memattest is designed to sit beneath such tools as the tamper-evidence and
sequencing layer, not to replace them.

## Quickstart

memattest requires Python 3.12 or newer. It is not yet published to PyPI, so
install it from a local clone of this repository. Run the following from the
**repository root** (the directory containing `pyproject.toml`).

```bash
cd <path-to-memattest-repo>
python -m venv .venv
.venv\Scripts\activate    # Windows; use `source .venv/bin/activate` on Linux/macOS
pip install -e .
```

One Windows note for the block above: if your shell is Git Bash, the activation path is
the Windows layout with POSIX syntax: `source .venv/Scripts/activate`.

Next you need the path to the memory directory you want to guard- the
`<MEMORY_DIR>` placeholder. memattest works with
any directory of files so it can support any agent or agent harness, 
and their memory folder paths will differ from each other.
As a concrete example, Claude Code keeps each
project's persistent memory under the user profile at:

```
<home>/.claude/projects/<my-project>/memory/
```

where `<my-project>` is derived from the project's working directory with
separators replaced by dashes. For example, the project `C:\source\myproject` maps
to `C--source-myproject`, giving
`C:/Users/<you>/.claude/projects/C--source-myproject/memory`. Inside, the
directory named `memory` typically holds `MEMORY.md` (an index the agent
loads every session) plus one Markdown file per remembered fact. Point
memattest at the `memory` directory itself, not the `<my-project>` directory
above it; that parent also holds session data that changes constantly and
would drown verification in false alarms. 

[!IMPORTANT]
Just a reminder- this example is for Claude Code. The memory directory will differ 
with other agents and agent harnesses. For example, in Codex it's `~/.codex/memories/`

Initialize the memory directory. This generates a per-installation Ed25519
signing key, seals it in the OS keystore, and adopts any pre-existing files
in the directory as the trusted baseline:

```bash
memattest init --memory-dir <MEMORY_DIR>
```

Double-check the path you pass: `init` guards whatever directory you point
it at, recursively, and cannot know your intent. It reports how many
pre-existing files it adopted — if that count surprises you, you initialized
the wrong directory. To undo an init (or to uninstall memattest's state for
a directory): delete the `<MEMORY_DIR>/.memattest` directory, then remove
the sealed signing key, which is stored under the directory's resolved
absolute path:

```bash
python -c "import keyring; keyring.delete_password('memattest', r'C:\full\resolved\path\to\MEMORY_DIR')"
```

To wire memattest into Claude Code, copy the hooks and permission rules from
[`src/memattest/integrations/claude_code/settings-snippet.json`](src/memattest/integrations/claude_code/settings-snippet.json)
into your project's `.claude/settings.json`, substituting two placeholders:

- `<MEMATTEST_BIN>` — the **absolute path** to the venv's console script
  (e.g. `C:/path/to/repo/.venv/Scripts/memattest`). Hooks run in a fresh
  shell without your venv activated, so a bare `memattest` will not resolve;
  an absolute path also defeats `PATH` hijacking (see
  [Hardening](#hardening-your-installation)).
- `<MEMORY_DIR>` — your memory directory as an absolute path. On Windows use
  drive notation with forward slashes (`C:/Users/you/...`), not Git Bash
  notation (`/c/Users/...`), which other shells and Python misinterpret.

The template configures three hooks and two permission rules:

- A `SessionStart` hook runs `memattest hook session-start`, which verifies
  the log and delivers the result as hook JSON: `additionalContext` places
  the report in the agent's context, and on failure `systemMessage` shows
  the same report to you, untruncated. The subcommand always exits 0 by
  design, because Claude Code discards a SessionStart hook's stdout on a
  non-zero exit — wiring plain `memattest verify` here alerts the user but
  leaves the agent, the party about to act on the memory, uninformed.
- A `PostToolUse` hook (matching `Write|Edit`) runs
  `memattest hook post-tool-use` to append a log entry after every memory
  write.
- A `PreToolUse` hook (matching `Bash|PowerShell|Write|Edit`) runs
  `memattest hook pre-tool-use`, which denies two kinds of proposed tool
  call. First, any command that invokes `memattest adopt`, including quoted
  or path-prefixed spellings such as `& "C:/.../memattest" adopt` that
  permission glob rules cannot match. Second, any agent edit of the trust
  surface itself: `Write`/`Edit` calls targeting a Claude Code settings
  file (`.claude/settings.json`, `.claude/settings.local.json`, or the
  user-level one), and shell commands that reference those files or the
  `disableAllHooks` flag — the routes by which an agent could un-hook
  memattest for its next session. Humans editing settings in their own
  editor are unaffected.

  [!IMPORTANT]
  both matches are deliberately broad (fail-closed), so a command that merely 
  *mentions* the phrases, such as a commit message, is denied too.
  
  [!IMPORTANT]
  An agent that can execute arbitrary Python can still reach the adopt API
  directly, which no command filter can catch; the signed,
  provenance-stamped `adopt` entry is what keeps that path from being
  silent (see [Security limitations](#security-limitations)).

- Permission `deny` rules (`Bash(*memattest adopt*)` and its `PowerShell`
  twin) remain as a second layer, but in my testing the `PreToolUse` hook
  is the layer that actually catches real invocations.

Claude Code snapshots hook configuration at session start, so the hooks take
effect in the **next** session, not the one where you edit the settings.

Run verification at any time, not just from a hook:

```bash
memattest verify --memory-dir <MEMORY_DIR>
```

A clean log prints a single `OK <n> entries verified` line and exits 0. A
compromised log prints one `PROBLEM` line per finding (kind, path, detail, last known good entry) 
and exits 1 (or 3 if entries use an unknown scheme version— see Exit codes below).

If you edit a guarded memory file by hand between sessions (a legitimate
out-of-band change, not tampering), verification will correctly report it as
a divergence. Reconcile it with `adopt`, which appends a new signed entry
recording the file's current hash together with a required justification:

```bash
memattest adopt <MEMORY_DIR>/notes.md --reason "manual correction of stale project name"
```

`adopt` and `record` locate the guarded directory from the file path itself:
the file's containing folder must hold the `.memattest` state directory.
In scenarios where it doesn't, like when the memory file is in a subdirectory of
the memory directory, or when the containing folder is not the guarded root,
pass `--memory-dir` to explicitly specify the memory directory. Example:

```bash
memattest adopt <MEMORY_DIR>/subfolder/notes.md --memory-dir <MEMORY_DIR> --reason "manual correction of stale project name"
```

The confirmation prompt always names the directory being adopted
into, so check it before typing `adopt`.

`adopt` only runs from an interactive terminal and asks for typed
confirmation; there is no non-interactive or `--yes` flag, by design. The
terminal check is best-effort, which is why the Claude Code template also
blocks `adopt` at the hook layer (see
[Security limitations](#security-limitations) below).

[!IMPORTANT]
The `adopt` command is designed to be run manually and interactively. It's security-critical and should not be automated.

One Windows-specific note for anyone testing the stdin-reading hook
subcommands (`hook post-tool-use`, `hook pre-tool-use`) by hand: piping JSON
into `memattest.exe` from Windows PowerShell
5.1 does not reliably deliver the payload on stdin, and PowerShell can also
prepend a byte-order mark that breaks JSON parsing. Use Git Bash (or WSL) for
manual hook testing; Claude Code's own hook invocation does not go through
PowerShell and is unaffected.

## Keystores

The Ed25519 signing key never touches disk unencrypted; it is always sealed
behind a `KeyStore` backend, selected with `--keystore`.

- **`--keystore keyring`** (the default) uses the OS-native credential store
  via the `keyring` package: DPAPI on Windows, Secret Service (or the
  matching desktop keyring) on Linux, and Keychain on macOS. These require a user 
  session, and Secret Service actually needs an active desktop session.
- **`--keystore file`** encrypts the key in a file (scrypt-derived AES-256-GCM,
  written with `0600` permissions) for headless hosts where no OS keyring is
  available — CI runners, containers, servers without a logged-in desktop
  session. Of course, it can also be used in a desktop session, as an alternative 
  to the keyring approach. It requires the `MEMATTEST_PASSPHRASE` environment variable to be
  set on every invocation; there is no default or embedded passphrase.

```bash
MEMATTEST_PASSPHRASE="correct horse battery staple" \
  memattest init --memory-dir <MEMORY_DIR> --keystore file
```

The choice is recorded in the log's `.memattest/config.toml` at `init`, and
the config is authoritative from then on: later commands need no
`--keystore` flag, and passing one that contradicts the config is an
operational error rather than a lookup in the wrong backend keystore (which
used to end in a false `key-missing` alarm). Logs initialized before this
feature record their config automatically on their next successful append.
Each backend keystore seals the key under a name derived from the memory
directory's resolved path, so there is no way to move a key between backend
keystores after `init`; the manual escape hatch, should the config ever be
wrong, is editing `config.toml` by hand. The config file ships unsigned —
every lie it can tell ends in a loud failure at the next session start, and
cryptographic sealing is planned together with the watch list.

Every `verify` — including the session-start hook — cross-checks
`pubkey.ed25519` on disk against the public key re-derived from the signing
seed in the backend keystore. To audit a *copied* log on a machine that never
had the key — a restored backup before re-initializing, incident response on
a clean machine, a third-party or CI audit — pass `--no-key-check`:

```bash
memattest verify --memory-dir <COPY_OF_MEMORY_DIR> --no-key-check
```

This skips only the backend-keystore cross-check; signatures, tree
consistency, and file state are still fully verified against the pubkey file
that travels with the log. After restoring a backup onto a new machine,
verify with `--no-key-check` first and re-init only once the report is clean
and you have reviewed the memory contents — re-init adopts whatever is on
disk.

## Hardening your installation

memattest detects tampering; it does not prevent it. Filesystem access
control is critical to prevent things like malicious removal of the memattest hook.

[!IMPORTANT]
**Before relying on memattest, secure the memory and installation folders!**

In rough priority order:

- **Restrict write access to the memory directory.** The primary 
  adversary is an unprivileged process or another user writing to your
  memory files out-of-band. Fewer possible writers means both less exposure
  and fewer false alarms. Keep `<MEMORY_DIR>` (including `.memattest/`)
  inside your own user profile with default private permissions — `0700` on
  Linux/Mac and the standard user-profile ACLs on Windows. Never use a
  world-writable or group-shared location.
- **Protect the memattest installation itself.** The hooks execute memattest
  at every session start, so whoever can modify the installed code can
  disable or subvert verification. Apply the same access
  restrictions to your synced memattest repo and its `.venv` that you apply to the memory
  directory.
- **The backend keystore is the trust anchor.** `verify` re-derives the
  public key from the keystore-held signing seed and cross-checks the disk
  copy, so your OS credential store (or the `MEMATTEST_PASSPHRASE` for the
  file backend keystore) is part of the trust surface. A `key-missing`
  finding at session start means the keystore entry is gone and the log's
  authorship can no longer be established locally — treat the memory
  contents as untrusted and review them manually before re-initializing.
- **Invoke the hook commands by absolute path.** The settings template's
  `<MEMATTEST_BIN>` placeholder exists for exactly this reason: a bare
  `memattest` resolves through `PATH`, and a writable directory earlier on
  `PATH` is a classic hijack point. Fill the placeholder with the absolute
  path to the venv's console script (e.g.
  `C:/path/to/repo/.venv/Scripts/memattest` or
  `/path/to/repo/.venv/bin/memattest`) and don't replace it with a bare
  command name.
- **Treat the hook configuration as part of the trust surface.** An attacker
  who can edit the settings file can remove the verify hook or the `adopt`
  guard. The template's `PreToolUse` guard blocks the *agent's* routes to
  those files (file tools and shell alike), but an attacker outside the
  session is not so constrained. Prefer the shared `.claude/settings.json` for the
  memattest hooks where practical— it normally lives in the repository, so
  edits leave a visible trail. Hooks defined there can't be selectively
  overridden from another settings file, but they can be globally silenced: `"disableAllHooks": true` in
  any scope — including the gitignored `settings.local.json` or the
  user-level `~/.claude/settings.json`, both outside the repository's
  visibility — turns off every hook at the next session start.
  Also keep in mind that memattest only emits messages 
  when a hook invokes it, so removal of the hook will be observed as *silence*, not a report. 
  So, if you don't see any message from memattest (e.g., `memattest: OK`) when starting your agent,
  treat the session as suspect. Instruct the agent (in `CLAUDE.md` or `AGENTS.md`) to 
  be suspicious if it doesn't see a memattest status when it starts as well.
- **Keep the memory directory out of cloud-synced folders.** Sync services
  (OneDrive, Dropbox, iCloud) rewrite files out-of-band by design, so
  sync conflicts or restores become indistinguishable from tampering.
- **Handle `MEMATTEST_PASSPHRASE` like the secret it is** (file backend
  only). Don't hardcode it in shell profiles or scripts that get committed;
  inject it at invocation time from a secret manager or the environment of a
  protected service account.
- **Keep a backup of the memory directory** (including `.memattest/`). If the memories are somehow tampered,
  you'll at least have a known-good copy to restore.

## Extending provenance

Every recorded entry carries a `provenance` block built by collecting claims
from a set of providers. memattest has built-in providers for the agent
harness, the writing process (pid, executable, parent-process chain), the
machine (hostname, a stable machine id), and the session (user, session id,
whether the write happened at an interactive TTY). Third parties can add
their own claims without touching memattest's source by registering a Python
entry point in the `memattest.providers` group. A provider is any zero-argument
callable that returns a JSON-serializable dict; its return value is recorded
under the entry point's name in every subsequent entry.

The canonical example is a **git workspace provider**, which
ties a memory write to the exact code state the agent was working in:

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

A few related boundaries are worth calling out:

- **Admin/SYSTEM-level attackers are out of scope.** Defending against an
  attacker with administrative privileges would require TPM-backed key
  sealing or an external root of trust; v1 has neither.
- **Remote or synced memory stores are out of scope.** Key distribution and
  multi-device identity are unsolved in this version; memattest assumes a
  single local installation with a single signing identity.
- **Same-user tampering routed through `adopt` cannot be silent.** Even if
  same-user malware unseals the key and calls `adopt` to launder a bad state
  into the log, it still leaves a permanent, signed `adopt` entry, including
  the parent-process chain and whether the call came from an interactive TTY.
  The event remains visible to anyone who later inspects the log with
  `memattest log`, even though it wasn't blocked.
- **The `adopt` terminal check can be circumvented.** `adopt` refuses to run when
  stdin reports itself as non-interactive, but Python's `isatty()` can
  return true in environments that are not meaningfully interactive 
  (like an agent's Git Bash shell tool on Windows) and a pty
  wrapper such as `script`, `winpty`, or `expect` can satisfy the check
  deliberately. It's more of a limited protection against accidental scripting. 
  You should rely on the harness-level `PreToolUse` guard to keep agents away from
  `adopt`; the signed `adopt` entry (previous bullet) is what keeps even a
  successful bypass from being silent.
- **Trust anchor.** `verify` re-derives the public key from the signing seed
  in the backend keystore and cross-checks `pubkey.ed25519` on disk, so an
  attacker with write access to the memory directory who swaps the pubkey
  and re-signs history is reported (`key-mismatch`, plus `bad-signature` on
  the forged tree heads), and a deleted keystore entry is reported
  (`key-missing`) at the next session start instead of surfacing later as a
  failed append. A `key-missing` log's authorship cannot be established —
  accidental key loss and a hostile rewrite that also deleted the keystore
  entry are indistinguishable — so review memory contents manually before
  re-adopting them under a new key. Same-user malware can rewrite the
  keystore entry itself and defeat the cross-check; that gap remains until
  the v2 validator service, as does rollback (next bullet). External root
  anchoring (v2) hardens this further.
- **Rollback.** Because every append seals a valid tree head, an attacker who
  deletes a suffix of entries together with their covering tree heads and the
  created files reverts the log to an earlier, fully valid sealed state
  undetected. Detecting rollback requires an external anchor for the latest
  tree head (v2).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean — no tampering or inconsistency detected |
| 1 | Tamper detected — see the printed `PROBLEM` lines for file, hashes, and last-valid entry; includes `key-mismatch` and `key-missing` from the signing-key cross-check |
| 2 | Operational error — e.g. not initialized, backend keystore unreachable for the signing-key cross-check (`--no-key-check` skips it when auditing a copied log), malformed hook payload; appends fail closed rather than record an unverifiable entry |
| 3 | Unknown scheme version — an entry was written by a newer scheme than this verifier understands, and is refused rather than guessed at |

`memattest hook session-start` is a deliberate exception: it exits 0 for
clean, tampered, and operational-error outcomes alike, delivering each
through hook JSON, because Claude Code discards a SessionStart hook's stdout
on any non-zero exit. A failing `verify` also prints a one-line
`verification FAILED` alert to stderr, so a harness that surfaces only the
stderr of a failed hook still says something useful.

## License

MIT — see [LICENSE](LICENSE).
