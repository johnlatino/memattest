# Manual self-test: signing-key cross-check

Run everything from the repo root (`C:\source\agentmemoryvalidation`) in
PowerShell. `$LASTEXITCODE` after each `memattest` call is part of the
evidence — the expected exit code is listed for every step.

Part A uses a disposable scratch directory and the real Windows Credential
Manager; nothing it does can affect the live installation. Part B exercises
the live installation end-to-end (session-start delivery in your console)
and is fully reversible. Part C is optional and destructive — read its
warning first.

---

## Part A — scratch directory (safe, disposable)

### A1. Init and clean verify

```powershell
$scratch = "$env:TEMP\memattest-manual"
New-Item -ItemType Directory -Force $scratch | Out-Null
Set-Content -Encoding utf8 "$scratch\note.md" "hello"
.venv\Scripts\memattest init --memory-dir $scratch
.venv\Scripts\memattest verify --memory-dir $scratch; $LASTEXITCODE
```

Expected: `initialized; adopted 1 pre-existing file(s)`, then
`OK 1 entries verified`, exit `0`. The clean verify already ran the
cross-check silently against the Credential Manager entry it just created.

### A2. Swapped pubkey → `key-mismatch`

```powershell
Copy-Item "$scratch\.memattest\pubkey.ed25519" "$scratch\.memattest\pubkey.bak"
Set-Content -Encoding ascii "$scratch\.memattest\pubkey.ed25519" ("0" * 64)
.venv\Scripts\memattest verify --memory-dir $scratch; $LASTEXITCODE
```

Expected: exit `1`, one problem line
`PROBLEM kind=key-mismatch path=None detail=pubkey.ed25519 contains 0000…
but the key derived from the backend keystore is <64 hex chars>; the
on-disk pubkey was replaced`, plus the `Remediation:` line and a one-line
`verification FAILED` alert on stderr. Note there is **no** `bad-signature`
noise — the genuine tree heads still verify against the derived (true) key.

Restore and confirm clean:

```powershell
Copy-Item "$scratch\.memattest\pubkey.bak" "$scratch\.memattest\pubkey.ed25519" -Force
.venv\Scripts\memattest verify --memory-dir $scratch; $LASTEXITCODE
```

Expected: `OK 1 entries verified`, exit `0` — the log itself was never
touched, so restoring the file fully restores the clean state.

### A3. Deleted keystore entry → `key-missing`

```powershell
.venv\Scripts\python -c "import keyring, pathlib, os; keyring.delete_password('memattest', str((pathlib.Path(os.environ['TEMP']) / 'memattest-manual').resolve()))"
.venv\Scripts\memattest verify --memory-dir $scratch; $LASTEXITCODE
```

Expected: exit `1`,
`PROBLEM kind=key-missing path=None detail=backend keystore has no signing
key for '<scratch path>'; the log's authorship cannot be established
(accidental key loss and a hostile rewrite are indistinguishable) and
appends will fail — manually review memory contents before re-initializing`.
This is your 2026-07-10 incident, now caught at verify time instead of at
the next append.

### A4. The opt-out

```powershell
.venv\Scripts\memattest verify --memory-dir $scratch --no-key-check; $LASTEXITCODE
```

Expected: `OK 1 entries verified`, exit `0` — the copied-log-audit posture:
signatures, tree consistency, and file state still fully checked against
the pubkey that travels with the log; only the keystore cross-check skipped.

### A5. Clean up

```powershell
Remove-Item -Recurse -Force $scratch
```

The Credential Manager entry was already deleted in A3; nothing else remains.

---

## Part B — live installation (reversible)

Live memory dir: `C:\Users\jlatino\.claude\projects\C--source-agentmemoryvalidation\memory`

### B1. Baseline

```powershell
$live = "C:\Users\jlatino\.claude\projects\C--source-agentmemoryvalidation\memory"
.venv\Scripts\memattest verify --memory-dir $live; $LASTEXITCODE
```

Expected: `OK <n> entries verified`, exit `0`. This proves the upgrade is
seamless for a pre-feature log: the seed was already sealed at init, so the
cross-check passes with no migration. Note `<n>` for B3.

### B2. Hook-level check without restarting a session

```powershell
echo '{}' | .venv\Scripts\memattest hook session-start --memory-dir $live; $LASTEXITCODE
```

Expected: exit `0`, one JSON line whose
`hookSpecificOutput.additionalContext` contains `OK <n> entries verified`,
and **no** `systemMessage` key (quiet on success).

### B3. Live `key-mismatch`, delivered at real session start

```powershell
Copy-Item "$live\.memattest\pubkey.ed25519" "$live\.memattest\pubkey.bak"
Set-Content -Encoding ascii "$live\.memattest\pubkey.ed25519" ("a" * 64)
```

Now exit Claude Code and start/resume a session. Expected in your console:
the SessionStart systemMessage containing `PROBLEM kind=key-mismatch` with
both key hexes (the planted `aaaa…` and the genuine derived key). The agent
receives the same report as context. The `.memattest\` directory is excluded
from guarding, so the swap and backup themselves trigger nothing else.

Cautions while in the mismatched state: don't run `adopt`, and treat it as a
look-don't-touch state — the log is untouched, so restoring the file is a
complete recovery.

### B4. Restore and confirm

```powershell
Copy-Item "$live\.memattest\pubkey.bak" "$live\.memattest\pubkey.ed25519" -Force
Remove-Item "$live\.memattest\pubkey.bak"
.venv\Scripts\memattest verify --memory-dir $live; $LASTEXITCODE
```

Expected: `OK <n> entries verified`, exit `0` (same `<n>` as B1 unless the
session in between wrote memories). Restart once more and the session should
open with the normal quiet context and no warning banner.

---

## Part C — live `key-missing` (OPTIONAL — destructive, recommend skipping)

Deleting the **live** Credential Manager entry recreates the incident
end-to-end, but recovery requires deleting `.memattest\` and re-running
`init`, which re-baselines the log — the attestation history accumulated so
far is lost. A3 already exercises the identical code path on the scratch
directory, and you have lived the real incident once. Skip unless you
specifically want to rehearse the recovery ceremony again.

---

## Result checklist

- [ ] A1 clean init + verify (exit 0)
- [ ] A2 key-mismatch detected, no bad-signature noise, restore returns clean
- [ ] A3 key-missing detected with manual-review remediation text
- [ ] A4 --no-key-check verifies the same log (exit 0)
- [ ] A5 scratch removed
- [ ] B1 live log verifies clean, no migration
- [ ] B2 hook JSON quiet-on-success shape
- [ ] B3 key-mismatch systemMessage appears at real session start
- [ ] B4 restore returns the live installation to clean
