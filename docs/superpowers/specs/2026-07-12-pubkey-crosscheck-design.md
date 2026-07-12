# Keystore-Sealed Public-Key Cross-Check — Design

Date: 2026-07-12
Status: approved for planning
Scope: roadmap item 1 from the implementation plan's "Next steps (post-v1)"
(fast-follow named in the v1 spec §2 "Trust anchor" limitation).

## 1. Problem

v1 verification trusts `.memattest/pubkey.ed25519` — a plain file inside the
guarded memory directory. An attacker with write access to that directory can:

1. generate their own Ed25519 keypair,
2. rewrite the log entries and re-sign every STH with their key,
3. replace `pubkey.ed25519` with their public key.

`memattest verify` then passes cleanly. The trust anchor is a file the
adversary can write.

A second, operational gap surfaced in practice (2026-07-10 incident on this
repository's own installation): the signing key was deleted from the OS
keystore, yet `verify` kept passing — it never consults the keystore — and the
loss stayed invisible until the next append failed. Key loss should be an
explicit verify finding, not a latent append error.

## 2. Design summary

At verify time, load the private signing key the way appends already do
(`Identity.load(keystore, key_name)`), derive its public key, and compare the
derived bytes against `.memattest/pubkey.ed25519`. The keystore-held seed —
sealed at init by `Identity.generate`, outside the memory directory and outside
the attacker's write reach — becomes the root of trust; the disk file is only
ever the thing being checked.

Nothing new is sealed and no new state is persisted. Every initialized log
already has its seed in a keystore, so existing installations get the
cross-check immediately on upgrade with no migration.

### Alternatives rejected

- **Seal a separate copy of the public key at init.** Requires a migration
  ceremony for pre-existing logs, and the only candidate content to seal for
  them is the current disk file — blessing an already-swapped key
  (trust-on-first-use circularity). Also fails the motivating incident: with
  the sealed public-key copy intact but the private key deleted, verify would
  pass and the loss would stay silent.
- **Both of the above plus a private-key presence check.** The derive-from-seed
  guarantee re-implemented at twice the code and the same migration burden.

### Relationship to v2

The v2 resident validator (separate OS account) will hold its own trusted copy
of the public key under its own account — an integrity problem solvable with
account-owned files and ACLs; it does not need to unseal anything of the
user's. This cross-check persists no new state, so v2 layers on top with
nothing to migrate. The two checks are complementary: session-side verify
anchors to the user's keystore; the validator anchors to storage same-user
malware cannot write.

## 3. Verify flow

`MemAttest.verify()` gains a keyword parameter `key_check: bool = True`.

When `key_check` is true, immediately after the disk pubkey loads
(and before scheme dispatch):

1. `Identity.load(self.keystore, self.key_name)` — the exact load path appends
   use; its `public_key_bytes` is the derived public key.
2. Compare derived bytes to the disk file's bytes.

Outcomes:

| Cross-check outcome | Report | Exit |
| --- | --- | --- |
| Derived key == disk pubkey | no finding | — |
| Derived key != disk pubkey | `key-mismatch` problem; detail shows both key hexes (disk vs. derived) | 1 |
| `KeyNotFoundError` — backend keystore reachable, no entry for this log | `key-missing` problem; detail names the backend keystore and key name, states appends will also fail, and points at re-init after manual review | 1 |
| Other `KeyStoreError` — backend keystore unreachable (locked keyring, missing/wrong passphrase, unreadable key file) | raise `MemAttestError("keystore unavailable for signing-key cross-check: <cause>; pass --no-key-check to verify without it")` | 2 |

Both problem kinds carry `path: None`, like `bad-signature`.

**Verification key selection.** When the cross-check runs and succeeds in
deriving a key, the derived key — not the disk file — is used for the STH
signature checks that follow. Consequences:

- Pubkey file swapped, history *not* re-signed: genuine STH signatures still
  verify against the derived (true) key → the report is exactly one
  `key-mismatch`, with no false `bad-signature` noise.
- Full rewrite attack (swap + re-sign): `key-mismatch` plus `bad-signature`
  on every forged STH — both the swapped anchor and the forged history are
  visible.

When the cross-check is skipped (`key_check=False`) or the key is missing
(`key-missing`), the remaining checks fall back to the disk pubkey, as today.

**`key-missing` semantics.** `key-missing` means the log's authorship can no
longer be established locally: verify cannot distinguish accidental key loss
from a hostile rewrite in which the attacker also deleted the keystore entry,
re-signed the log with their own key, and replaced the disk pubkey (the
fallback checks then pass against the attacker's key). Memory contents must
therefore be treated as untrusted and manually reviewed by a human before
re-init re-adopts them; the `key-missing` detail text says so.

**Placement and precedence.** The cross-check runs before unknown-scheme
dispatch, so its problems are included in the early exit-3 return. Exit-code
precedence is unchanged: unknown scheme → 3; otherwise any problem → 1;
clean → 0. `key-mismatch` and `key-missing` are new problem kinds under the
existing exit-1 umbrella (joining `modified`, `missing`, `unlogged`,
`bad-signature`, `root-mismatch`, `log-truncated`); the exit-code table gains
no rows.

## 4. Error taxonomy

New exception: `KeyNotFoundError(KeyStoreError)` in `errors.py`, meaning "the
backend keystore answered the lookup, and the answer was: nothing stored under
that name." This is a statement about the key (evidence-grade); plain
`KeyStoreError` remains a statement about the environment (operational).

Backend keystore changes in `identity.py`:

- `KeyringKeyStore.unseal`: raise `KeyNotFoundError` when
  `keyring.get_password` returns `None`. Exceptions from the `keyring` call
  stay plain `KeyStoreError`.
- `FileKeyStore.unseal`: raise `KeyNotFoundError` when the key file is absent
  or the name is not among its blobs. Unreadable/corrupted file and
  wrong-passphrase (`InvalidTag`) stay plain `KeyStoreError`.

Because `KeyNotFoundError` subclasses `KeyStoreError`, every existing
`except KeyStoreError` handler — including append's fail-closed path — is
provably unchanged.

## 5. CLI surface

All changes in `cli.py`:

- `memattest verify` gains `--no-key-check` (store-true), mapping to
  `ma.verify(key_check=False)`. Help text: "skip the signing-key cross-check
  against the backend keystore (for auditing a copied log on a machine
  without the key)". No other subcommand gets the flag: `init`/`record`/
  `adopt` need the private key to sign anyway, and the hooks must never skip
  the check.
- `hook session-start` and `hook post-tool-use` pass nothing new; the
  cross-check is on by default. Exit-1 problems already flow into the agent
  context and `systemMessage`; the exit-2 operational error already becomes
  "memattest: verification could not run: …".
- `_report_lines` renders problem kinds generically, so the new kinds appear
  with no formatter changes. Detail strings carry the remediation seed.
- The lazy-import discipline is untouched: the cross-check lives in
  `core.verify`; the hot `hook pre-tool-use` path imports none of it.

**Skip semantics.** The cross-check is mandatory by default and skippable only
by the explicit flag — never implicitly. Supported reasons to skip:

1. Machine rebuild / backup restore: keystore entries (e.g. DPAPI) are bound
   to machine + user account; verify the restored files against the restored
   log *before* re-initializing, since re-init blesses whatever is on disk.
2. Incident response: audit a copied memory directory on a clean machine.
3. Third-party / CI audit of a snapshot: the log is self-contained for
   signature, tree-consistency, and file-state checks.

On a foreign machine the backend keystore is usually reachable but has no
entry, which would report `key-missing` — a false tamper finding for an
auditor. The flag exists to keep such audits both possible and honest.

## 6. Documentation updates

- **v1 spec** (`2026-07-06-memattest-design.md`): rewrite the §2 "Trust
  anchor" out-of-scope bullet — the pubkey-file-swap attack is now detected;
  what remains out of scope narrows to same-user malware (which can rewrite
  the keystore too) and rollback. Add the cross-check to §7 verify as a fourth
  check with the outcome table. Drop the item from §13 future work.
- **README**: update the "Security limitations" trust-anchor bullet the same
  way; note in "Hardening your installation" that verify now anchors to the
  backend keystore; note the two new problem kinds in Exit codes; add a short
  paragraph on `--no-key-check` and the restore/audit workflow (verify the
  copied log first, then re-init).
- **Plan roadmap**: mark "Next steps" item 1 done, pointing at this spec.

## 7. Testing

All new code lands red-green (TDD skill); the plan orders these as
failing-test-first tasks.

Error-typing units (`tests/test_identity.py`):

- `KeyringKeyStore.unseal` → `KeyNotFoundError` on a `None` lookup result
  (keyring faked).
- `FileKeyStore.unseal` → `KeyNotFoundError` for a missing key file and for a
  name absent from the blobs; wrong passphrase stays plain `KeyStoreError`.
- `KeyNotFoundError` is-a `KeyStoreError`.

Verify semantics (`tests/test_verify.py`, mirroring the existing attack
simulations):

1. Clean log, key present → ok; cross-check adds nothing to the report.
2. Keystore entry deleted after init → `key-missing`, exit 1; disk-based
   checks still run and report.
3. Pubkey file swapped, history not re-signed → exactly one `key-mismatch`,
   zero `bad-signature`.
4. Full rewrite attack (swap pubkey + re-sign with attacker key) →
   `key-mismatch` plus `bad-signature` per forged STH. (The attack verify
   passes cleanly today.)
5. Backend keystore unreachable (stub raising `KeyStoreError`) →
   `MemAttestError` mentioning `--no-key-check`; same log with
   `key_check=False` verifies as today.
6. `key_check=False` never touches the keystore (stub fails the test if
   called).
7. Unknown-scheme entry + deleted key → early exit-3 return still includes
   the `key-missing` problem.

CLI (`tests/test_cli.py`): `--no-key-check` plumbs through; session-start
hook with a deleted key emits `key-missing` in `additionalContext` +
`systemMessage`, exit 0; unreachable backend keystore → exit 2 with the hint
on stderr.

Post-implementation, on this machine: end-to-end pass on a scratch directory
with the real Windows Credential Manager — init, verify OK, delete the
credential, verify reports `key-missing`, clean up — plus a plain
`memattest verify` against the live memory directory to confirm the upgrade
is seamless (its key is already sealed). No destructive testing against the
live log.

## 8. Out of scope

- Key rotation / recovery beyond re-init (unchanged from v1).
- Same-user malware (can unseal or rewrite the user's keystore; v2 validator).
- Rollback of a sealed suffix (external root anchoring, roadmap item 4).
- Watch list, per-log config (roadmap items 2–3).
