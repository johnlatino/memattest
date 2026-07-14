# Per-Log Config — Design

Date: 2026-07-13
Status: approved for planning
Scope: roadmap item 2 from the implementation plan's "Next steps (post-v1)".

## 1. Problem

The backend keystore is chosen per invocation (`--keystore`, default
`keyring`), but the signing key exists in exactly one backend keystore per
log. Addressing the wrong one has always failed confusingly, and since the
signing-key cross-check (spec 2026-07-12) it fails *alarmingly*: a log
initialized with the keyring backend keystore, verified with
`--keystore file`, looks in the wrong place, finds nothing, and reports
`key-missing` — a false tamper alarm reachable by a typo.

The log should record which backend keystore it uses, once, at the moment
that choice is made.

## 2. Design summary

`init` writes `.memattest/config.toml` recording the backend keystore. The
config is **authoritative**: after init, commands need no `--keystore` flag,
and an explicit flag that contradicts the config is an operational error.
Pre-feature logs migrate themselves on their next successful append. The
file ships without cryptographic protection in this item; §6 carries the
analysis of why that is sound today and when it stops being sound (the
watch list, roadmap item 3).

## 3. File format and module

`.memattest/config.toml`:

```toml
# memattest per-log configuration
config_version = 1
keystore = "keyring"   # or "file"
```

- `config_version` follows the same refuse-to-guess policy as the entry
  scheme: an unknown version is an operational error ("config written by a
  newer memattest"), never a shrug. Future additions (the watch list would
  become a table) evolve through this field.
- Reading uses stdlib `tomllib` (Python ≥ 3.12 is already required; the
  runtime dependency list is unchanged). Writing is a template string — the
  file is two keys; no TOML serializer is needed or added.
- New module `src/memattest/per_log_config.py`:
  - `load_config(state_dir: Path) -> dict | None` — `None` when the file is
    absent; `MemAttestError` naming the file and the defect on unparseable
    TOML, missing or unknown keys, an unknown `keystore` value, or an
    unknown `config_version`.
  - `write_config(state_dir: Path, keystore: str) -> None`.
  - Imports nothing heavy; safe for the CLI's lazy-import discipline (the
    hot `hook pre-tool-use` path still imports no cryptography).

## 4. CLI resolution semantics

`--keystore` changes its argparse default from `"keyring"` to `None`
(unspecified). `_make_ma` — the single funnel every subcommand uses —
resolves the backend keystore:

1. **Config present:** omitted flag → config decides. Flag equal to the
   config → proceed. Flag contradicting the config → operational error
   (exit 2): "this log's config records backend keystore '<name>'; omit
   --keystore, or edit .memattest/config.toml if the config is wrong". The
   wrong-flag false `key-missing` alarm becomes unreachable.
2. **Config absent** (pre-feature or older-install copied log): exactly the
   pre-feature behavior — omitted flag → `keyring`; explicit flag → obeyed.
3. **`init`** (nothing to read yet): omitted flag → `keyring`, as today;
   init records whichever backend keystore it used.

Unchanged and orthogonal:

- The `MEMATTEST_PASSPHRASE` gate and its `--no-key-check` relaxation apply
  after resolution, whenever the resolved backend keystore is `file`.
  Copied-log audits with `--no-key-check` work with or without a config.
- Hook invocations that pass no `--keystore` (the shipped template and the
  live installation) behave identically before and after migration.
- The `--keystore` help text now says the choice is recorded at init and is
  only needed before init or for pre-config logs.

## 5. Error handling

Every config problem is an **operational error (exit 2), never a tamper
finding**:

| Condition | Behavior |
| --- | --- |
| Config absent | Not an error — legacy resolution (§4 case 2) |
| Unparseable TOML; missing or unknown keys; unknown `keystore` value | Exit 2, message naming the file and the defect |
| Unknown `config_version` | Exit 2, "config written by a newer memattest" |
| Explicit flag contradicts config | Exit 2, message naming the recorded backend keystore |

The session-start hook already wraps any `MemAttestError` as "verification
could not run: …" in both `additionalContext` and `systemMessage`, so a
corrupted or rewritten config announces itself at the next session start
with no new hook code.

## 6. Security analysis (why unprotected is sound today)

Claim: **no lie the config can tell produces a clean verify over forged
history.** The signing-key cross-check anchors trust in the backend
keystore's *contents*, which a memory-directory attacker cannot forge: they
cannot write the user's OS keyring at all, and a planted `key.sealed`
cannot decrypt under a passphrase they do not know (`InvalidTag`).
Exhaustively, for an attacker who can rewrite `config.toml`:

- Redirect `keyring` → `file`: verify fails on the missing
  `MEMATTEST_PASSPHRASE` or on `InvalidTag` — operational error, loud at
  session start.
- Redirect `file` → `keyring`: the keyring has no entry for this log —
  `key-missing`, loud.
- Delete the config: legacy resolution resumes; for a keyring log this
  changes nothing, for a file-backend log whose hook omits the flag it
  false-alarms loudly.
- Corrupt the config: exit 2, loud at session start.

Every outcome is fail-noisy; none is fail-silent. Config tampering can harass
(false alarms, blocked verifies) but cannot certify forged history.

**Deferral, stated precisely:** this argument holds only while the config's
sole content is routing that the cross-check double-checks. The watch list
(roadmap item 3) breaks it — deleting a watch-list line would silently
narrow coverage, with no backend-keystore failure to announce it. Item 3
must therefore add cryptographic sealing of the config (e.g. a digest
sealed in the backend keystore) together with the human reconciliation
ceremony that legitimate config edits then require. Designing that ceremony
once, next to the feature that needs it, is why it is not built here.

Boundary note: `config.toml` lives in `.memattest/`, which is excluded from
guarding, so it is intentionally outside the Merkle log — the same standing
as `pubkey.ed25519`, covered by the same session-start loudness argument.

## 7. Migration (auto-create on next append)

- `MemAttest.init()` writes the config immediately after `pubkey.ed25519`.
- For existing logs, the first successful **append** (`record` or `adopt`)
  writes it — at that moment the backend keystore has demonstrably unsealed
  the signing key, so the recorded value is proven, not guessed. `verify`
  stays strictly read-only (the no-stray-state guarantee already under
  test).
- Core learns the canonical name via a class attribute on the `KeyStore`
  ABC: `config_name: str | None = None`; `KeyringKeyStore.config_name =
  "keyring"`, `FileKeyStore.config_name = "file"`. Auto-create fires only
  when `config_name` is set, so in-memory test doubles (left at `None`)
  never write a config claiming a backend keystore the CLI cannot resolve,
  and third-party `KeyStore` implementers opt in by naming themselves.

## 8. Documentation updates

- **README**: Keystores section — replace "Use the same `--keystore` choice
  consistently…" with the config story (recorded at init, flag unnecessary
  afterwards, contradiction is an error, auto-migration on first append);
  add `config.toml` to every place the README enumerates the state
  directory's contents.
- **v1 spec** (`2026-07-06-memattest-design.md`): §13 future-work bullet on
  per-log `config.toml` marked done with a pointer to this spec.
- **Plan roadmap** (`2026-07-06-memattest.md` "Next steps"): item 2 marked
  done pointing at this spec and its plan.

## 9. Testing

- `tests/test_per_log_config.py` — module units: write→load roundtrip;
  absent file → `None`; unparseable TOML, missing key, unknown key, unknown
  `keystore` value, unknown `config_version` → `MemAttestError` naming the
  file.
- `tests/test_cli.py` — behavior matrix: init writes the config; post-init
  commands work with no flag (both backend keystores); contradicting flag →
  exit 2 naming the recorded backend keystore (regression lock for the
  false `key-missing` scenario); config-absent legacy behavior preserved;
  session-start hook surfaces a corrupted config as "could not run".
- `tests/test_core.py` — first append auto-creates the config for a named
  keystore; test-double keystore never auto-creates; verify on a config-less
  log writes nothing.
- Post-implementation, on this machine: verify the live log with no flag
  (config absent → legacy path, still clean); one real append to trigger
  auto-create; verify again and inspect the written file.

## 10. Out of scope

- Cryptographic sealing of the config and the reconciliation ceremony for
  legitimate edits (arrives with the watch list, roadmap item 3).
- Watch list, provider config, guard globs — future tables gated by
  `config_version`.
- Key rotation / changing a log's backend keystore after init (no rotation
  exists in v1; the manual escape hatch is editing the config by hand).
