# Manual test: full lifecycle on a test project

Guard a test project's memory directory end to end: init, sign writes,
detect tampering, reconcile, exercise the per-log config, and exercise the
signing-key cross-check. Run everything from the repo root
(`C:\source\agentmemoryvalidation`) in PowerShell. `$LASTEXITCODE` after
each `memattest` call is part of the evidence — the expected exit code is
listed for every step, and several steps are *supposed* to fail.

Order matters: Parts A–D are non-destructive to the test log; Part E ends
with a one-way key deletion (no rotation exists), so it doubles as the
start of cleanup. Part F is optional hook wiring for a real Claude Code
project.

Set the target once. For a real Claude Code project this is
`C:\Users\jlatino\.claude\projects\<project-slug>\memory`; a scratch folder
works the same:

```powershell
$mem = "<absolute path to the test project's memory directory>"
```

---

## Part A — setup and baseline

### A1. Ensure there is something to guard

```powershell
New-Item -ItemType Directory -Force $mem | Out-Null
if (-not (Test-Path "$mem\MEMORY.md")) { Set-Content -Encoding utf8 "$mem\MEMORY.md" "# Memory Index" }
```

### A2. Init

```powershell
.venv\Scripts\memattest init --memory-dir $mem; $LASTEXITCODE
```

Expected: `initialized; adopted N pre-existing file(s)` (N = files already
in the directory), exit `0`. No `--keystore` flag: the keyring backend
keystore is the default, and the choice is now recorded per log.

### A3. Inspect what init produced

```powershell
Get-Content "$mem\.memattest\config.toml"
Get-Content "$mem\.memattest\pubkey.ed25519"
.venv\Scripts\memattest log --memory-dir $mem
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: the config shows `config_version = 1` and `keystore = "keyring"`;
the pubkey is 64 hex chars; `log` prints one JSON adopt entry per baseline
file, each carrying provenance (process chain, machine, `interactive_tty`);
verify prints `OK N entries verified`, exit `0`. The clean verify already
ran the signing-key cross-check against the Credential Manager entry init
created.

---

## Part B — the signing path

### B1. Record a write the way the hook would

```powershell
Set-Content -Encoding utf8 "$mem\lifecycle-note.md" "first version"
.venv\Scripts\memattest record --path "$mem\lifecycle-note.md"; $LASTEXITCODE
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: `record` prints `recorded write of lifecycle-note.md at entry N`,
exit `0` — note `--memory-dir` was omitted and derived from the file's
containing folder. Verify shows the entry count grew by one, exit `0`.

### B2. Inclusion proof

```powershell
.venv\Scripts\memattest prove --memory-dir $mem --index 0; $LASTEXITCODE
```

Expected: exit `0`, a JSON array of hex-encoded hashes — the RFC 6962
audit path for entry 0 (`[]` only when the log has a single entry). A third
party holding the pubkey and a tree head can check membership from this
alone.

---

## Part C — the tamper matrix and reconciliation

### C1. Out-of-band modification

```powershell
Set-Content -Encoding utf8 "$mem\lifecycle-note.md" "tampered version"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: exit `1`, `PROBLEM kind=modified path=lifecycle-note.md` with
`expected sha256:… found sha256:…` and the last-valid entry index and
timestamp, plus the `Remediation:` line on stdout and a one-line
`verification FAILED` alert on stderr.

### C2. Deletion and planting

```powershell
Remove-Item "$mem\lifecycle-note.md"
Set-Content -Encoding utf8 "$mem\planted.md" "never recorded"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: exit `1`, two problems — `kind=missing path=lifecycle-note.md`
(recorded in the log, absent on disk) and `kind=unlogged path=planted.md`
(on disk, never recorded).

### C3. Reconcile as the human

Type this yourself in an interactive terminal — it prompts, and it refuses
to run without a TTY. Recreate the deleted file first (or accept only the
planted one and record the deletion instead; both are legitimate flows):

```powershell
Set-Content -Encoding utf8 "$mem\lifecycle-note.md" "tampered version"
.venv\Scripts\memattest adopt --path "$mem\lifecycle-note.md" --path "$mem\planted.md" --reason "manual lifecycle test reconcile"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: the ceremony prints `About to adopt 2 file(s) as trusted in
<dir>. Reason: …`, waits for the typed word `adopt`, then `adopted 2
file(s)`, exit `0`. Verify is clean again — and `memattest log` now ends
with two adopt entries whose hashes contradict the earlier write entry's
prediction: the divergence you blessed stays permanently visible in
history.

---

## Part D — per-log config behavior

### D1. Contradicting flag

```powershell
.venv\Scripts\memattest verify --memory-dir $mem --keystore file; $LASTEXITCODE
```

Expected: exit `2`, `error: this log's config records backend keystore
'keyring'; omit --keystore, or edit .memattest/config.toml if the config
is wrong` — and no `MEMATTEST_PASSPHRASE` complaint, because the
contradiction fires before the passphrase gate.

### D2. Pre-feature simulation — delete the config, append recreates it

```powershell
Remove-Item "$mem\.memattest\config.toml"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
Set-Content -Encoding utf8 "$mem\lifecycle-note.md" "second version"
.venv\Scripts\memattest record --path "$mem\lifecycle-note.md"; $LASTEXITCODE
Get-Content "$mem\.memattest\config.toml"
```

Expected: the config-less verify still passes (legacy keyring default),
exit `0`; the record succeeds and the config reappears with
`keystore = "keyring"` — auto-migration triggered by the first successful
append, exactly what a log initialized before the config feature gets.

---

## Part E — signing-key cross-check (destructive step last)

### E1. Swapped pubkey → `key-mismatch` (reversible)

```powershell
Copy-Item "$mem\.memattest\pubkey.ed25519" "$mem\.memattest\pubkey.bak"
Set-Content -Encoding ascii "$mem\.memattest\pubkey.ed25519" ("0" * 64)
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: exit `1`, `PROBLEM kind=key-mismatch` showing the planted
`0000…` and the genuine key derived from the backend keystore. No
`bad-signature` noise — the genuine tree heads still verify against the
derived (true) key.

Restore and confirm clean:

```powershell
Copy-Item "$mem\.memattest\pubkey.bak" "$mem\.memattest\pubkey.ed25519" -Force
Remove-Item "$mem\.memattest\pubkey.bak"
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: `OK … entries verified`, exit `0`.

### E2. Deleted keystore entry → `key-missing` (ONE-WAY — this ends the test log)

The credential name is the memory directory's resolved path:

```powershell
.venv\Scripts\python -c "import keyring, sys; keyring.delete_password('memattest', sys.argv[1])" ((Resolve-Path $mem).Path)
.venv\Scripts\memattest verify --memory-dir $mem; $LASTEXITCODE
```

Expected: exit `1`, `PROBLEM kind=key-missing … the log's authorship
cannot be established (accidental key loss and a hostile rewrite are
indistinguishable) and appends will fail — manually review memory contents
before re-initializing`.

### E3. The audit opt-out

```powershell
.venv\Scripts\memattest verify --memory-dir $mem --no-key-check; $LASTEXITCODE
```

Expected: `OK … entries verified`, exit `0` — the copied-log-audit
posture: signatures, tree consistency, and file state still fully checked
against the pubkey that travels with the log; only the backend-keystore
cross-check skipped.

---

## Part F — optional: hook integration (real Claude Code project only)

Do this before Part E if you want the hooks running against a live key.
Wire the three hooks into the test project's settings by hand, following
the README's settings template (absolute `<MEMATTEST_BIN>` path, this
test project's memory dir); the PreToolUse guard exists precisely so that
agents cannot make these edits. Then:

1. Start a session in the test project. Expected: quiet success — the
   agent receives `memattest: OK … entries verified` as context, no
   console banner.
2. Tamper with a memory file (as in C1), restart the session. Expected:
   the SessionStart systemMessage in your console and the same report in
   agent context, with `kind=modified`.
3. Ask the agent to reconcile the file for you. Expected: the PreToolUse
   guard denies the attempt with the only-a-human message; reconcile it
   yourself (as in C3) and restart to confirm the quiet banner returns.

---

## Part G — cleanup

```powershell
Remove-Item -Recurse -Force "$mem\.memattest"
Remove-Item "$mem\planted.md", "$mem\lifecycle-note.md" -ErrorAction SilentlyContinue
```

The Credential Manager entry was already deleted in E2 (if you skipped
E2, run its `delete_password` line now). If you wired hooks in Part F,
remove them from the test project's settings by hand. The memory files
you did not create stay untouched throughout.

---

## Result checklist

- [ ] A2 init adopts baseline, exit 0
- [ ] A3 config records keyring; log shows provenance; clean verify
- [ ] B1 record with derived memory dir; entry count grows
- [ ] B2 inclusion proof emitted
- [ ] C1 modified detected with both hashes and last-valid entry
- [ ] C2 missing + unlogged detected together
- [ ] C3 interactive adopt ceremony; clean verify; divergence visible in log
- [ ] D1 contradicting flag exits 2 before the passphrase gate
- [ ] D2 config deleted → legacy verify OK → append recreates it
- [ ] E1 key-mismatch on swapped pubkey, no bad-signature noise, restore clean
- [ ] E2 key-missing after credential deletion
- [ ] E3 --no-key-check still verifies the disk-based checks
- [ ] F (optional) session-start delivery, tamper report, agent adopt denied
- [ ] G scratch state removed; memory files untouched
