# memattest Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **STATUS (2026-07-09): Tasks 1–13 are complete** and merged as v1 (`fadb0c6`).
> The spec §12.5 self-testing pass ran post-merge on this repository's own agent
> memory and produced a hardening round (`f8ec96e`): JSON-based hook report
> delivery (`hook session-start`), an agent-side PreToolUse guard
> (`hook pre-tool-use`) covering adopt invocations and settings-file edits,
> memory-dir derivation for adopt/record, lazy state-dir creation, lazy
> cryptography imports, and README/hardening documentation. Unchecked boxes
> below reflect that per-step tracking happened outside this file, not
> unfinished work. Remaining work is tracked in "Next steps" at the end of
> this file and spec §13.

**Goal:** Build the memattest v1 prototype — a Python library + CLI that makes an agent's memory directory tamper-evident via an RFC 6962 append-only Merkle log with signed tree heads — with a Claude Code hook integration.

**Architecture:** A pure-Python core (`canonical` JSON → `merkle` log → `entry`/`store` persistence → `identity`/`seal` signing → `provenance` claims → `core` orchestration) wrapped by an argparse CLI whose exit codes (0/1/2/3) drive harness hooks. All state lives in `<memory-dir>/.memattest/` as plain JSON. Spec: `docs/superpowers/specs/2026-07-06-memattest-design.md`.

**Tech Stack:** Python ≥3.12, `cryptography` (Ed25519, AES-GCM, scrypt), `keyring` (OS keystores), `psutil` (process provenance), `pytest`.

## Global Constraints

- Python ≥ 3.12; runtime deps limited to `cryptography>=42`, `keyring>=24`, `psutil>=5.9`; dev dep `pytest>=8`. No other dependencies.
- **venv only — never touch the global interpreter.** Every `pip`, `pytest`, and `memattest` invocation runs inside the project venv (`.venv\Scripts\...` on Windows, `.venv/bin/...` on Linux). The system Python is used for exactly one thing: creating the venv (on this machine: `C:\tools\Python\Python313\python.exe -m venv .venv`). No package is ever installed into the system/base Python.
- Hashing: SHA-256 only. Merkle construction: RFC 6962 exactly — leaf = `SHA-256(0x00 ‖ data)`, interior = `SHA-256(0x01 ‖ left ‖ right)`, empty tree = `SHA-256("")`.
- Signatures: Ed25519. Public key stored in the clear at `.memattest/pubkey.ed25519` (hex). Private key only ever inside a `KeyStore`.
- Canonical JSON (hashing/signing input): `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`. (The spec's prose dropped "sorted keys" for readability; deterministic key order remains an implementation requirement of canonicalization.)
- Entry `scheme` is the string `"v1"`. Entries with any other scheme are reported unverifiable, never guessed at.
- Exit codes: `0` clean · `1` tamper detected · `2` operational error · `3` unknown scheme version.
- State directory `. memattest/` (no space — `.memattest/`) is excluded from guarding. Layout: `entries/000000.json…`, `sth/000000.json…`, `pubkey.ed25519`.
- Entry filenames zero-padded to 6 digits. `content_hash` format: `"sha256:<hex>"`. Timestamps: UTC ISO-8601 with `Z` suffix.
- Old entries are NEVER rehashed or rewritten. Adopt appends; it never modifies existing files under `.memattest/`.
- `adopt` requires an interactive TTY, a `--reason`, and typed confirmation. No `--yes` flag may be added.
- Cross-platform Windows + Linux. No platform-conditional logic outside `provenance/builtin.py` and `KeyStore` backends.
- Commit messages: subject + body only, **no attribution/Co-Authored-By lines** (user requirement).
- Dev environment: this machine is Windows; use `py -3` / `.venv\Scripts\python`. On Linux CI use `python3` / `.venv/bin/python`. All commands below show the Windows form.

## File Structure

```
pyproject.toml                       # packaging, deps, console script
.gitignore
src/memattest/
├── __init__.py                      # version only
├── canonical.py                     # canonical_json(obj) -> bytes
├── errors.py                        # MemAttestError, KeyStoreError, TamperError (kinds)
├── merkle.py                        # RFC 6962: hashes, root, inclusion+consistency proofs
├── entry.py                         # build_entry(), file_content_hash(), SCHEME
├── store.py                         # LogStore: entries/NNNNNN.json persistence
├── identity.py                      # KeyStore ABC, KeyringKeyStore, FileKeyStore, Identity
├── seal.py                          # build_sth, verify_sth, SthChain
├── provenance.py                    # builtin claim fns + entry-point collection
├── core.py                          # MemAttest facade: init/record/adopt/verify, VerifyReport
├── cli.py                           # argparse CLI, exit-code mapping, hook subcommand
└── integrations/claude_code/
    └── settings-snippet.json        # hooks + permission deny template
tests/
├── test_canonical.py
├── test_merkle_root.py
├── test_merkle_proofs.py
├── test_entry_store.py
├── test_identity.py
├── test_seal.py
├── test_provenance.py
├── test_core.py
├── test_verify_attacks.py           # one test per threat-model claim (spec §12.2)
├── test_adopt.py
└── test_cli.py
README.md                            # written in final task
```

---

### Task 1: Project scaffold + canonical JSON

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `src/memattest/__init__.py`, `src/memattest/canonical.py`, `src/memattest/errors.py`
- Test: `tests/test_canonical.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `canonical_json(obj: Any) -> bytes` (module `memattest.canonical`); exception classes `MemAttestError(Exception)`, `KeyStoreError(MemAttestError)` (module `memattest.errors`); installed editable package `memattest` with console script `memattest = memattest.cli:main` (cli module arrives in Task 10 — the script entry is declared now so install config never changes).

- [ ] **Step 1: Verify Python 3.12+ is available**

Run: `C:\tools\Python\Python313\python.exe --version` (this machine's install; on other machines use `py -3.12 --version` or whatever ≥3.12 interpreter exists)
Expected: `Python 3.13.13`. This is the only step that touches the system interpreter, and only to create the venv in Step 3 — never to install packages.

- [ ] **Step 2: Create packaging files**

`pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "memattest"
version = "0.1.0"
description = "Tamper-evident agent memory: RFC 6962 append-only Merkle log with signed tree heads and provenance"
requires-python = ">=3.12"
dependencies = [
    "cryptography>=42",
    "keyring>=24",
    "psutil>=5.9",
]

[project.optional-dependencies]
dev = ["pytest>=8"]

[project.scripts]
memattest = "memattest.cli:main"

[tool.setuptools.packages.find]
where = ["src"]
```

`.gitignore`:

```
__pycache__/
*.egg-info/
.venv/
dist/
build/
```

`src/memattest/__init__.py`:

```python
__version__ = "0.1.0"
```

`src/memattest/errors.py`:

```python
class MemAttestError(Exception):
    """Operational error (CLI exit code 2)."""


class KeyStoreError(MemAttestError):
    """The keystore could not seal/unseal the signing key."""
```

- [ ] **Step 3: Create venv and install editable**

Run: `C:\tools\Python\Python313\python.exe -m venv .venv; .venv\Scripts\python -m pip install -e .[dev]`
Expected: ends with `Successfully installed ... memattest-0.1.0 ...` (the console script will fail to run until Task 10 — that is fine). Note the install runs via `.venv\Scripts\python` — packages land only in the venv.

- [ ] **Step 4: Write the failing test**

`tests/test_canonical.py`:

```python
from memattest.canonical import canonical_json


def test_key_order_is_deterministic():
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_compact_sorted_utf8():
    assert canonical_json({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode("utf-8")


def test_nested_structures():
    obj = {"z": [1, {"y": None, "x": True}], "a": "s"}
    assert canonical_json(obj) == b'{"a":"s","z":[1,{"x":true,"y":null}]}'
```

- [ ] **Step 5: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_canonical.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'memattest.canonical'`

- [ ] **Step 6: Write minimal implementation**

`src/memattest/canonical.py`:

```python
import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Deterministic byte serialization used for all hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

- [ ] **Step 7: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_canonical.py -v`
Expected: 3 passed

- [ ] **Step 8: Commit**

```
git add pyproject.toml .gitignore src tests
git commit -m "Scaffold memattest package with canonical JSON serialization"
```

---

### Task 2: RFC 6962 Merkle root hashing

**Files:**
- Create: `src/memattest/merkle.py`
- Test: `tests/test_merkle_root.py`

**Interfaces:**
- Consumes: nothing
- Produces (module `memattest.merkle`): `leaf_hash(data: bytes) -> bytes`, `node_hash(left: bytes, right: bytes) -> bytes`, `root_hash(leaves: Sequence[bytes]) -> bytes` (leaves are raw entry bytes, NOT pre-hashed).

- [ ] **Step 1: Write the failing test**

The known-answer vectors below are the Certificate Transparency reference vectors (google/certificate-transparency-go, `merkle_tree` tests). The naive-reference cross-check test makes the suite robust even if a vector were mistyped: if the two tests disagree, re-derive vectors from the CT repo before touching the implementation.

`tests/test_merkle_root.py`:

```python
import hashlib

from memattest.merkle import leaf_hash, node_hash, root_hash

# CT reference test vectors: leaf inputs (hex) and tree roots (hex) for sizes 1..8.
LEAF_INPUTS = [
    "", "00", "10", "2021", "3031", "40414243",
    "5051525354555657", "606162636465666768696a6b6c6d6e6f",
]
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def _naive(leaves: list[bytes]) -> bytes:
    """Independent reference implementation, structured differently on purpose."""
    n = len(leaves)
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + _naive(leaves[:k]) + _naive(leaves[k:])).digest()


def test_empty_tree_root_is_hash_of_empty_string():
    assert root_hash([]) == hashlib.sha256(b"").digest()


def test_leaf_and_node_prefixes():
    assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert node_hash(b"L", b"R") == hashlib.sha256(b"\x01LR").digest()


def test_ct_reference_vectors():
    leaves = [bytes.fromhex(h) for h in LEAF_INPUTS]
    for size in range(1, 9):
        assert root_hash(leaves[:size]).hex() == ROOTS[size - 1], f"size {size}"


def test_matches_naive_reference_for_all_sizes_to_33():
    leaves = [f"entry-{i}".encode() for i in range(33)]
    for size in range(1, 34):
        assert root_hash(leaves[:size]) == _naive(leaves[:size]), f"size {size}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_merkle_root.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'memattest.merkle'`

- [ ] **Step 3: Write minimal implementation**

`src/memattest/merkle.py`:

```python
"""RFC 6962 Merkle tree: hashing, root computation, inclusion and consistency proofs."""
import hashlib
from typing import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def root_hash(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash (RFC 6962 §2.1) over raw leaf data."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _split(n)
    return node_hash(root_hash(leaves[:k]), root_hash(leaves[k:]))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_merkle_root.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```
git add src/memattest/merkle.py tests/test_merkle_root.py
git commit -m "Add RFC 6962 Merkle root hashing with CT reference vectors"
```

---

### Task 3: Inclusion and consistency proofs

**Files:**
- Modify: `src/memattest/merkle.py` (append functions)
- Test: `tests/test_merkle_proofs.py`

**Interfaces:**
- Consumes: `leaf_hash`, `node_hash`, `root_hash`, `_split` from Task 2
- Produces (module `memattest.merkle`): `inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]`, `verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes) -> bool`, `consistency_proof(old_size: int, leaves: Sequence[bytes]) -> list[bytes]`, `verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool`

- [ ] **Step 1: Write the failing test**

Exhaustive verification for every index of every tree size up to 33 (and every prefix size for consistency) — deliberately chosen over randomized property testing: at this scale exhaustive coverage is strictly stronger.

`tests/test_merkle_proofs.py`:

```python
from memattest.merkle import (
    consistency_proof,
    inclusion_proof,
    root_hash,
    verify_consistency,
    verify_inclusion,
)

LEAVES = [f"entry-{i}".encode() for i in range(33)]


def test_inclusion_all_indices_all_sizes():
    for size in range(1, 34):
        leaves = LEAVES[:size]
        root = root_hash(leaves)
        for i in range(size):
            proof = inclusion_proof(i, leaves)
            assert verify_inclusion(leaves[i], i, size, proof, root), f"size={size} i={i}"


def test_inclusion_rejects_wrong_leaf_and_index():
    leaves = LEAVES[:7]
    root = root_hash(leaves)
    proof = inclusion_proof(3, leaves)
    assert not verify_inclusion(b"tampered", 3, 7, proof, root)
    assert not verify_inclusion(leaves[3], 2, 7, proof, root)
    assert not verify_inclusion(leaves[3], 3, 7, proof, root_hash(LEAVES[:8]))


def test_consistency_all_prefixes_all_sizes():
    for new in range(1, 34):
        leaves = LEAVES[:new]
        new_root = root_hash(leaves)
        for old in range(0, new + 1):
            proof = consistency_proof(old, leaves)
            old_root = root_hash(leaves[:old])
            assert verify_consistency(old, new, old_root, new_root, proof), f"{old}->{new}"


def test_consistency_rejects_rewritten_history():
    good = LEAVES[:8]
    # History where entry 2 was altered before extension:
    bad = good[:2] + [b"rewritten"] + good[3:]
    proof = consistency_proof(4, bad)
    assert not verify_consistency(4, 8, root_hash(good[:4]), root_hash(bad), proof)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_merkle_proofs.py -v`
Expected: FAIL — `ImportError: cannot import name 'inclusion_proof'`

- [ ] **Step 3: Write the implementation (append to `src/memattest/merkle.py`)**

```python
def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Audit path for leaf `index` (RFC 6962 §2.1.1)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, leaves[:k]) + [root_hash(leaves[k:])]
    return inclusion_proof(index - k, leaves[k:]) + [root_hash(leaves[:k])]


def verify_inclusion(leaf: bytes, index: int, tree_size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2 verification algorithm."""
    if index >= tree_size:
        return False
    fn, sn = index, tree_size - 1
    r = leaf_hash(leaf)
    for p in proof:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def consistency_proof(old_size: int, leaves: Sequence[bytes]) -> list[bytes]:
    """Proof that the first `old_size` leaves are a prefix (RFC 6962 §2.1.2)."""
    n = len(leaves)
    if old_size == 0 or old_size >= n:
        return []
    return _subproof(old_size, leaves, True)


def _subproof(m: int, leaves: Sequence[bytes], known_root: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if known_root else [root_hash(leaves)]
    k = _split(n)
    if m <= k:
        return _subproof(m, leaves[:k], known_root) + [root_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [root_hash(leaves[:k])]


def verify_consistency(old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: list[bytes]) -> bool:
    """RFC 9162 §2.1.4.2 verification algorithm."""
    if old_size > new_size:
        return False
    if old_size == new_size:
        return not proof and old_root == new_root
    if old_size == 0:
        return not proof  # the empty prefix is consistent with any tree
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # old tree is a complete subtree; its root is implied
        path = [old_root] + path
    fn, sn = old_size - 1, new_size - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1
    if not path:
        return False
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if fn % 2 == 0:
                while fn % 2 == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return sn == 0 and fr == old_root and sr == new_root
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_merkle_proofs.py tests/test_merkle_root.py -v`
Expected: all passed. If a consistency case fails, debug against the exhaustive loop output — the generation functions (`consistency_proof`/`_subproof`) follow RFC 6962 §2.1.2 verbatim and the verifier follows RFC 9162 §2.1.4.2; compare intermediate `fn`/`sn` against the RFC pseudocode.

- [ ] **Step 5: Commit**

```
git add src/memattest/merkle.py tests/test_merkle_proofs.py
git commit -m "Add Merkle inclusion and consistency proofs with exhaustive verification tests"
```

---

### Task 4: Entry building and log store

**Files:**
- Create: `src/memattest/entry.py`, `src/memattest/store.py`
- Test: `tests/test_entry_store.py`

**Interfaces:**
- Consumes: `canonical_json` (Task 1)
- Produces:
  - module `memattest.entry`: `SCHEME = "v1"`; `file_content_hash(p: Path) -> str` returning `"sha256:<hex>"`; `build_entry(index: int, op: str, path: str, content_hash: str | None, provenance: dict, reason: str | None = None, timestamp: str | None = None) -> dict` (op ∈ `"write" | "delete" | "adopt"`; `content_hash` is None only for `delete`; `reason` key present only when not None; timestamp auto-filled UTC `...Z` when None)
  - module `memattest.store`: `class LogStore` with `__init__(self, state_dir: Path)` (creates `state_dir/entries/`), `.append(entry: dict) -> None` (validates `entry["index"] == self.count()`), `.load_all() -> list[dict]` (index order), `.leaf_bytes() -> list[bytes]` (canonical bytes per entry), `.count() -> int`

- [ ] **Step 1: Write the failing test**

`tests/test_entry_store.py`:

```python
import hashlib
import json
import re

import pytest

from memattest.canonical import canonical_json
from memattest.entry import SCHEME, build_entry, file_content_hash
from memattest.store import LogStore


def test_file_content_hash(tmp_path):
    f = tmp_path / "m.md"
    f.write_bytes(b"remember this")
    assert file_content_hash(f) == "sha256:" + hashlib.sha256(b"remember this").hexdigest()


def test_build_entry_shape():
    e = build_entry(0, "write", "notes.md", "sha256:ab", {"machine": {"hostname": "h"}})
    assert e["scheme"] == SCHEME == "v1"
    assert e["index"] == 0 and e["op"] == "write" and e["path"] == "notes.md"
    assert "reason" not in e
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", e["timestamp"])


def test_build_entry_adopt_keeps_reason():
    e = build_entry(1, "adopt", "notes.md", "sha256:ab", {}, reason="initial baseline")
    assert e["reason"] == "initial baseline"


def test_store_append_load_roundtrip(tmp_path):
    store = LogStore(tmp_path / ".memattest")
    e0 = build_entry(0, "write", "a.md", "sha256:00", {}, timestamp="2026-07-06T00:00:00Z")
    e1 = build_entry(1, "write", "b.md", "sha256:01", {}, timestamp="2026-07-06T00:00:01Z")
    store.append(e0)
    store.append(e1)
    assert store.count() == 2
    assert store.load_all() == [e0, e1]
    assert store.leaf_bytes() == [canonical_json(e0), canonical_json(e1)]
    on_disk = (tmp_path / ".memattest" / "entries" / "000000.json").read_text(encoding="utf-8")
    assert json.loads(on_disk) == e0


def test_store_rejects_index_gap(tmp_path):
    store = LogStore(tmp_path / ".memattest")
    with pytest.raises(ValueError):
        store.append(build_entry(5, "write", "a.md", "sha256:00", {}))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_entry_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'memattest.entry'`

- [ ] **Step 3: Write minimal implementation**

`src/memattest/entry.py`:

```python
import hashlib
from datetime import datetime, timezone
from pathlib import Path

SCHEME = "v1"


def file_content_hash(p: Path) -> str:
    return "sha256:" + hashlib.sha256(p.read_bytes()).hexdigest()


def build_entry(
    index: int,
    op: str,
    path: str,
    content_hash: str | None,
    provenance: dict,
    reason: str | None = None,
    timestamp: str | None = None,
) -> dict:
    if op not in ("write", "delete", "adopt"):
        raise ValueError(f"unknown op: {op}")
    entry = {
        "scheme": SCHEME,
        "index": index,
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "op": op,
        "path": path,
        "content_hash": content_hash,
        "provenance": provenance,
    }
    if reason is not None:
        entry["reason"] = reason
    return entry
```

`src/memattest/store.py`:

```python
import json
from pathlib import Path

from .canonical import canonical_json


class LogStore:
    """Append-only persistence: one canonical-JSON file per leaf under entries/."""

    def __init__(self, state_dir: Path):
        self.entries_dir = state_dir / "entries"
        self.entries_dir.mkdir(parents=True, exist_ok=True)

    def count(self) -> int:
        return len(list(self.entries_dir.glob("*.json")))

    def append(self, entry: dict) -> None:
        expected = self.count()
        if entry["index"] != expected:
            raise ValueError(f"entry index {entry['index']} != next index {expected}")
        target = self.entries_dir / f"{entry['index']:06d}.json"
        target.write_bytes(canonical_json(entry))

    def load_all(self) -> list[dict]:
        files = sorted(self.entries_dir.glob("*.json"))
        return [json.loads(f.read_text(encoding="utf-8")) for f in files]

    def leaf_bytes(self) -> list[bytes]:
        return [canonical_json(e) for e in self.load_all()]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_entry_store.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```
git add src/memattest/entry.py src/memattest/store.py tests/test_entry_store.py
git commit -m "Add entry builder and append-only JSON log store"
```

---

### Task 5: KeyStore backends and Ed25519 identity

**Files:**
- Create: `src/memattest/identity.py`
- Test: `tests/test_identity.py`

**Interfaces:**
- Consumes: `KeyStoreError` (Task 1)
- Produces (module `memattest.identity`):
  - `class KeyStore(ABC)`: `seal(self, name: str, secret: bytes) -> None`, `unseal(self, name: str) -> bytes` (raises `KeyStoreError` when unavailable/missing)
  - `class KeyringKeyStore(KeyStore)` — `__init__(self, service: str = "memattest")`, backed by the `keyring` library (DPAPI / Secret Service / Keychain)
  - `class FileKeyStore(KeyStore)` — `__init__(self, path: Path, passphrase: bytes)`, scrypt + AES-256-GCM encrypted file, `0600` perms on POSIX
  - `class Identity`: `.public_key_bytes: bytes` (32 raw bytes), `.sign(data: bytes) -> bytes`; classmethods `Identity.generate(keystore: KeyStore, name: str) -> Identity` (creates + seals seed) and `Identity.load(keystore: KeyStore, name: str) -> Identity`
  - `verify_signature(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool` (module function; needs no keystore)

- [ ] **Step 1: Write the failing test**

Tests use `FileKeyStore` (deterministic, CI-safe) plus an in-memory fake to prove `Identity` only touches the `KeyStore` interface. `KeyringKeyStore` gets a smoke test skipped when no OS keyring is functional.

`tests/test_identity.py`:

```python
import pytest

from memattest.errors import KeyStoreError
from memattest.identity import FileKeyStore, Identity, KeyringKeyStore, KeyStore, verify_signature


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyStoreError(f"no key named {name!r}")
        return self.data[name]


def test_generate_sign_verify_roundtrip():
    ks = MemoryKeyStore()
    ident = Identity.generate(ks, "k1")
    sig = ident.sign(b"payload")
    assert verify_signature(ident.public_key_bytes, b"payload", sig)
    assert not verify_signature(ident.public_key_bytes, b"tampered", sig)


def test_load_restores_same_key():
    ks = MemoryKeyStore()
    a = Identity.generate(ks, "k1")
    b = Identity.load(ks, "k1")
    assert a.public_key_bytes == b.public_key_bytes
    assert verify_signature(a.public_key_bytes, b"x", b.sign(b"x"))


def test_load_missing_key_raises():
    with pytest.raises(KeyStoreError):
        Identity.load(MemoryKeyStore(), "absent")


def test_file_keystore_roundtrip(tmp_path):
    ks = FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw")
    ks.seal("k1", b"\x01" * 32)
    assert ks.unseal("k1") == b"\x01" * 32


def test_file_keystore_wrong_passphrase(tmp_path):
    FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw").seal("k1", b"\x01" * 32)
    with pytest.raises(KeyStoreError):
        FileKeyStore(tmp_path / "key.sealed", passphrase=b"wrong").unseal("k1")


def test_keyring_keystore_smoke():
    ks = KeyringKeyStore(service="memattest-test")
    try:
        ks.seal("smoke", b"\x02" * 32)
        assert ks.unseal("smoke") == b"\x02" * 32
    except KeyStoreError:
        pytest.skip("no functional OS keyring in this environment")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_identity.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'memattest.identity'`

- [ ] **Step 3: Write minimal implementation**

`src/memattest/identity.py`:

```python
import base64
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .errors import KeyStoreError


class KeyStore(ABC):
    """seal/unseal named secrets. Backends decide where and how they are protected."""

    @abstractmethod
    def seal(self, name: str, secret: bytes) -> None: ...

    @abstractmethod
    def unseal(self, name: str) -> bytes: ...


class KeyringKeyStore(KeyStore):
    """OS keystore via `keyring`: DPAPI (Windows), Secret Service (Linux), Keychain (macOS)."""

    def __init__(self, service: str = "memattest"):
        self.service = service

    def seal(self, name: str, secret: bytes) -> None:
        import keyring
        try:
            keyring.set_password(self.service, name, base64.b64encode(secret).decode("ascii"))
        except Exception as exc:  # keyring backends raise assorted types
            raise KeyStoreError(f"keyring seal failed: {exc}") from exc

    def unseal(self, name: str) -> bytes:
        import keyring
        try:
            value = keyring.get_password(self.service, name)
        except Exception as exc:
            raise KeyStoreError(f"keyring unseal failed: {exc}") from exc
        if value is None:
            raise KeyStoreError(f"no key named {name!r} in keyring service {self.service!r}")
        return base64.b64decode(value)


class FileKeyStore(KeyStore):
    """Encrypted-file fallback for headless hosts: scrypt KDF + AES-256-GCM, 0600 perms."""

    def __init__(self, path: Path, passphrase: bytes):
        self.path = Path(path)
        self.passphrase = passphrase

    def _derive(self, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(self.passphrase)

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8"))

    def seal(self, name: str, secret: bytes) -> None:
        blobs = self._load()
        salt, nonce = os.urandom(16), os.urandom(12)
        ct = AESGCM(self._derive(salt)).encrypt(nonce, secret, None)
        blobs[name] = base64.b64encode(salt + nonce + ct).decode("ascii")
        self.path.write_text(json.dumps(blobs), encoding="utf-8")
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def unseal(self, name: str) -> bytes:
        blobs = self._load()
        if name not in blobs:
            raise KeyStoreError(f"no key named {name!r} in {self.path}")
        raw = base64.b64decode(blobs[name])
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        try:
            return AESGCM(self._derive(salt)).decrypt(nonce, ct, None)
        except InvalidTag as exc:
            raise KeyStoreError("wrong passphrase or corrupted key file") from exc


class Identity:
    """Per-installation Ed25519 keypair. The keypair IS the agent identity (spec §6)."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private = private_key
        self.public_key_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    @classmethod
    def generate(cls, keystore: KeyStore, name: str) -> "Identity":
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        keystore.seal(name, seed)
        return cls(private)

    @classmethod
    def load(cls, keystore: KeyStore, name: str) -> "Identity":
        seed = keystore.unseal(name)
        return cls(Ed25519PrivateKey.from_private_bytes(seed))


def verify_signature(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, data)
        return True
    except InvalidSignature:
        return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_identity.py -v`
Expected: 6 passed (or 5 passed, 1 skipped where no OS keyring exists)

- [ ] **Step 5: Commit**

```
git add src/memattest/identity.py tests/test_identity.py
git commit -m "Add KeyStore abstraction (keyring + encrypted file) and Ed25519 identity"
```

---

### Task 6: Signed Tree Heads and STH chain

**Files:**
- Create: `src/memattest/seal.py`
- Test: `tests/test_seal.py`

**Interfaces:**
- Consumes: `canonical_json` (Task 1), `Identity`, `verify_signature` (Task 5)
- Produces (module `memattest.seal`):
  - `build_sth(tree_size: int, root: bytes, identity: Identity, timestamp: str | None = None) -> dict` — dict `{tree_size, root_hash (hex), timestamp, signature (hex)}`; signature is over `canonical_json` of the dict minus `signature`
  - `verify_sth(sth: dict, public_key_bytes: bytes) -> bool`
  - `class SthChain` — `__init__(self, state_dir: Path)` (creates `state_dir/sth/`), `.append(sth: dict) -> None` (zero-padded files like entries), `.load_all() -> list[dict]`, `.latest() -> dict | None`

- [ ] **Step 1: Write the failing test**

`tests/test_seal.py`:

```python
from memattest.identity import Identity, KeyStore
from memattest.seal import SthChain, build_sth, verify_sth
from memattest.errors import KeyStoreError


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyStoreError(name)
        return self.data[name]


def make_identity():
    return Identity.generate(MemoryKeyStore(), "k")


def test_sth_sign_and_verify():
    ident = make_identity()
    sth = build_sth(3, b"\xaa" * 32, ident, timestamp="2026-07-06T00:00:00Z")
    assert sth["tree_size"] == 3
    assert sth["root_hash"] == "aa" * 32
    assert verify_sth(sth, ident.public_key_bytes)


def test_sth_rejects_any_field_change():
    ident = make_identity()
    sth = build_sth(3, b"\xaa" * 32, ident)
    for field, bad in [("tree_size", 4), ("root_hash", "bb" * 32), ("timestamp", "2000-01-01T00:00:00Z")]:
        forged = dict(sth, **{field: bad})
        assert not verify_sth(forged, ident.public_key_bytes)


def test_sth_rejects_wrong_key():
    sth = build_sth(1, b"\xaa" * 32, make_identity())
    other = make_identity()
    assert not verify_sth(sth, other.public_key_bytes)


def test_chain_append_and_load(tmp_path):
    ident = make_identity()
    chain = SthChain(tmp_path / ".memattest")
    assert chain.latest() is None
    a = build_sth(1, b"\x01" * 32, ident)
    b = build_sth(2, b"\x02" * 32, ident)
    chain.append(a)
    chain.append(b)
    assert chain.load_all() == [a, b]
    assert chain.latest() == b
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_seal.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'memattest.seal'`

- [ ] **Step 3: Write minimal implementation**

`src/memattest/seal.py`:

```python
import json
from datetime import datetime, timezone
from pathlib import Path

from .canonical import canonical_json
from .identity import Identity, verify_signature


def _payload(sth: dict) -> bytes:
    return canonical_json({k: v for k, v in sth.items() if k != "signature"})


def build_sth(tree_size: int, root: bytes, identity: Identity, timestamp: str | None = None) -> dict:
    sth = {
        "tree_size": tree_size,
        "root_hash": root.hex(),
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    sth["signature"] = identity.sign(_payload(sth)).hex()
    return sth


def verify_sth(sth: dict, public_key_bytes: bytes) -> bool:
    return verify_signature(public_key_bytes, _payload(sth), bytes.fromhex(sth["signature"]))


class SthChain:
    """Append-only chain of signed tree heads under sth/."""

    def __init__(self, state_dir: Path):
        self.sth_dir = state_dir / "sth"
        self.sth_dir.mkdir(parents=True, exist_ok=True)

    def append(self, sth: dict) -> None:
        n = len(list(self.sth_dir.glob("*.json")))
        (self.sth_dir / f"{n:06d}.json").write_bytes(canonical_json(sth))

    def load_all(self) -> list[dict]:
        files = sorted(self.sth_dir.glob("*.json"))
        return [json.loads(f.read_text(encoding="utf-8")) for f in files]

    def latest(self) -> dict | None:
        all_sths = self.load_all()
        return all_sths[-1] if all_sths else None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_seal.py -v`
Expected: 4 passed

- [ ] **Step 5: Commit**

```
git add src/memattest/seal.py tests/test_seal.py
git commit -m "Add signed tree heads and append-only STH chain"
```

---

### Task 7: Provenance providers

**Files:**
- Create: `src/memattest/provenance.py`
- Test: `tests/test_provenance.py`

**Interfaces:**
- Consumes: nothing internal
- Produces (module `memattest.provenance`): `collect(extra: dict | None = None) -> dict` — merges built-in claims (`agent`, `process`, `machine`, `session`), third-party providers discovered from entry-point group `"memattest.providers"` (each entry point loads to a zero-arg callable returning a `dict`; claims keyed by entry-point name; a provider that raises contributes `{"error": str(exc)}` instead of aborting), and finally `extra` (highest precedence, merged per top-level key). Built-ins also exposed individually: `agent_claims()`, `process_claims()`, `machine_claims()`, `session_claims()`.

- [ ] **Step 1: Write the failing test**

`tests/test_provenance.py`:

```python
import os
import sys

from memattest import provenance


def test_process_claims_shape():
    c = provenance.process_claims()
    assert c["pid"] == os.getpid()
    assert isinstance(c["exe"], str) and c["exe"]
    assert isinstance(c["parent_chain"], list)


def test_machine_claims_shape():
    c = provenance.machine_claims()
    assert isinstance(c["hostname"], str) and c["hostname"]
    assert isinstance(c["machine_id"], str) and c["machine_id"]


def test_session_claims_shape():
    c = provenance.session_claims()
    assert isinstance(c["user"], str)
    assert isinstance(c["interactive_tty"], bool)


def test_agent_claims_reads_env(monkeypatch):
    monkeypatch.setenv("MEMATTEST_HARNESS", "claude-code")
    monkeypatch.setenv("MEMATTEST_HARNESS_VERSION", "9.9")
    assert provenance.agent_claims() == {"harness": "claude-code", "version": "9.9"}


def test_collect_merges_builtins_and_extra():
    claims = provenance.collect(extra={"custom": {"k": 1}})
    for key in ("agent", "process", "machine", "session", "custom"):
        assert key in claims


def test_collect_survives_broken_provider(monkeypatch):
    class BrokenEP:
        name = "broken"

        def load(self):
            def boom():
                raise RuntimeError("provider exploded")
            return boom

    monkeypatch.setattr(provenance, "_entry_point_providers", lambda: [BrokenEP()])
    claims = provenance.collect()
    assert claims["broken"] == {"error": "provider exploded"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_provenance.py -v`
Expected: FAIL — `ImportError` / missing module

- [ ] **Step 3: Write minimal implementation**

`src/memattest/provenance.py`:

```python
"""Provenance claim providers. Third parties extend via entry-point group 'memattest.providers'.

A provider is a zero-argument callable returning a dict of claims; its claims
appear under the entry-point name. Example third-party provider (spec §5): a
git workspace provider returning {"repo": ..., "branch": ..., "head": ...}.
"""
import getpass
import os
import platform
import socket
import sys
import uuid
from importlib.metadata import entry_points

import psutil

ENTRY_POINT_GROUP = "memattest.providers"


def agent_claims() -> dict:
    return {
        "harness": os.environ.get("MEMATTEST_HARNESS", "unknown"),
        "version": os.environ.get("MEMATTEST_HARNESS_VERSION", "unknown"),
    }


def process_claims() -> dict:
    proc = psutil.Process()
    return {
        "pid": proc.pid,
        "exe": proc.exe(),
        "parent_chain": [p.name() for p in proc.parents()[:5]],
    }


def _machine_id() -> str:
    if platform.system() == "Linux":
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path, encoding="ascii") as f:
                    return f.read().strip()
            except OSError:
                continue
    if platform.system() == "Windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return winreg.QueryValueEx(k, "MachineGuid")[0]
        except OSError:
            pass
    return f"mac:{uuid.getnode():012x}"  # last-resort fallback


def machine_claims() -> dict:
    return {"hostname": socket.gethostname(), "machine_id": _machine_id(), "platform": platform.system()}


def session_claims() -> dict:
    return {
        "user": getpass.getuser(),
        "session_id": os.environ.get("CLAUDE_SESSION_ID"),
        "interactive_tty": sys.stdin.isatty(),
    }


def _entry_point_providers():
    return list(entry_points(group=ENTRY_POINT_GROUP))


def collect(extra: dict | None = None) -> dict:
    claims = {
        "agent": agent_claims(),
        "process": process_claims(),
        "machine": machine_claims(),
        "session": session_claims(),
    }
    for ep in _entry_point_providers():
        try:
            claims[ep.name] = ep.load()()
        except Exception as exc:
            claims[ep.name] = {"error": str(exc)}
    if extra:
        claims.update(extra)
    return claims
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_provenance.py -v`
Expected: 6 passed

- [ ] **Step 5: Commit**

```
git add src/memattest/provenance.py tests/test_provenance.py
git commit -m "Add provenance providers with entry-point extension mechanism"
```

---

### Task 8: Core facade — init, record, derived state

**Files:**
- Create: `src/memattest/core.py`
- Test: `tests/test_core.py`

**Interfaces:**
- Consumes: everything from Tasks 1–7
- Produces (module `memattest.core`):
  - `class MemAttest` — `__init__(self, memory_dir: Path, keystore: KeyStore | None = None)` (default `KeyringKeyStore()`; key name = `str(memory_dir.resolve())`; state dir `memory_dir/.memattest`; exposes `.store: LogStore`, `.sth_chain: SthChain`, `.pubkey_path: Path`)
  - `.initialized: bool` property (pubkey file exists)
  - `.init(reason: str = "initial baseline") -> list[dict]` — generates identity, writes pubkey hex file, adopts every pre-existing guarded file; errors if already initialized
  - `.record(path: Path, op: str = "write", reason: str | None = None) -> dict` — appends one entry (hashing the file unless `op == "delete"`), then builds + appends a new STH
  - `.adopt(paths: list[Path], reason: str) -> list[dict]` — one `adopt` entry per path + one STH at the end
  - `.guarded_files() -> list[Path]` — every file under `memory_dir` except `.memattest/**`, sorted
  - `.derived_state() -> dict[str, str]` — relpath (posix, forward slashes) → expected content_hash after replaying entries
  - Task 9 adds `.verify()`; Task 10 wraps everything in the CLI.

- [ ] **Step 1: Write the failing test**

`tests/test_core.py`:

```python
import pytest

from memattest.core import MemAttest
from memattest.entry import file_content_hash
from memattest.errors import MemAttestError
from memattest.identity import KeyStore
from memattest.errors import KeyStoreError


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyStoreError(name)
        return self.data[name]


@pytest.fixture
def mem(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    return MemAttest(d, keystore=MemoryKeyStore())


def test_init_baselines_existing_files(mem):
    entries = mem.init()
    assert [e["op"] for e in entries] == ["adopt"]
    assert entries[0]["path"] == "MEMORY.md"
    assert entries[0]["reason"] == "initial baseline"
    assert mem.initialized
    assert mem.sth_chain.latest()["tree_size"] == 1


def test_init_twice_errors(mem):
    mem.init()
    with pytest.raises(MemAttestError):
        mem.init()


def test_record_write_appends_entry_and_sth(mem):
    mem.init()
    f = mem.memory_dir / "notes.md"
    f.write_text("hello", encoding="utf-8")
    e = mem.record(f)
    assert e["op"] == "write" and e["path"] == "notes.md" and e["index"] == 1
    assert e["content_hash"] == file_content_hash(f)
    assert "process" in e["provenance"] and "machine" in e["provenance"]
    assert mem.sth_chain.latest()["tree_size"] == 2


def test_derived_state_replays_writes_and_deletes(mem):
    mem.init()
    f = mem.memory_dir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    mem.record(f)
    f.write_text("v2", encoding="utf-8")
    mem.record(f)
    state = mem.derived_state()
    assert state["notes.md"] == file_content_hash(f)
    f.unlink()
    mem.record(f, op="delete")
    assert "notes.md" not in mem.derived_state()
    assert "MEMORY.md" in mem.derived_state()


def test_guarded_files_excludes_state_dir(mem):
    mem.init()
    names = [p.name for p in mem.guarded_files()]
    assert names == ["MEMORY.md"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_core.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'memattest.core'`

- [ ] **Step 3: Write minimal implementation**

`src/memattest/core.py`:

```python
from pathlib import Path

from . import merkle, provenance
from .entry import build_entry, file_content_hash
from .errors import MemAttestError
from .identity import Identity, KeyringKeyStore, KeyStore
from .seal import SthChain, build_sth
from .store import LogStore

STATE_DIR_NAME = ".memattest"


class MemAttest:
    """High-level facade over one guarded memory directory."""

    def __init__(self, memory_dir: Path, keystore: KeyStore | None = None):
        self.memory_dir = Path(memory_dir)
        self.keystore = keystore or KeyringKeyStore()
        self.key_name = str(self.memory_dir.resolve())
        self.state_dir = self.memory_dir / STATE_DIR_NAME
        self.store = LogStore(self.state_dir)
        self.sth_chain = SthChain(self.state_dir)
        self.pubkey_path = self.state_dir / "pubkey.ed25519"

    @property
    def initialized(self) -> bool:
        return self.pubkey_path.exists()

    def guarded_files(self) -> list[Path]:
        return sorted(
            p for p in self.memory_dir.rglob("*")
            if p.is_file() and STATE_DIR_NAME not in p.relative_to(self.memory_dir).parts
        )

    def _rel(self, path: Path) -> str:
        return Path(path).resolve().relative_to(self.memory_dir.resolve()).as_posix()

    def _identity(self) -> Identity:
        return Identity.load(self.keystore, self.key_name)

    def _seal_current_tree(self, identity: Identity) -> None:
        leaves = self.store.leaf_bytes()
        self.sth_chain.append(build_sth(len(leaves), merkle.root_hash(leaves), identity))

    def _append(self, identity: Identity, op: str, path: Path, reason: str | None) -> dict:
        content_hash = None if op == "delete" else file_content_hash(Path(path))
        entry = build_entry(
            index=self.store.count(),
            op=op,
            path=self._rel(path),
            content_hash=content_hash,
            provenance=provenance.collect(),
            reason=reason,
        )
        self.store.append(entry)
        return entry

    def init(self, reason: str = "initial baseline") -> list[dict]:
        if self.initialized:
            raise MemAttestError(f"{self.memory_dir} is already initialized")
        identity = Identity.generate(self.keystore, self.key_name)
        self.pubkey_path.write_text(identity.public_key_bytes.hex(), encoding="ascii")
        entries = [self._append(identity, "adopt", p, reason) for p in self.guarded_files()]
        self._seal_current_tree(identity)
        return entries

    def record(self, path: Path, op: str = "write", reason: str | None = None) -> dict:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        identity = self._identity()
        entry = self._append(identity, op, path, reason)
        self._seal_current_tree(identity)
        return entry

    def adopt(self, paths: list[Path], reason: str) -> list[dict]:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        identity = self._identity()
        entries = [self._append(identity, "adopt", p, reason) for p in paths]
        self._seal_current_tree(identity)
        return entries

    def derived_state(self) -> dict[str, str]:
        state: dict[str, str] = {}
        for e in self.store.load_all():
            if e["op"] in ("write", "adopt"):
                state[e["path"]] = e["content_hash"]
            elif e["op"] == "delete":
                state.pop(e["path"], None)
        return state
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_core.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```
git add src/memattest/core.py tests/test_core.py
git commit -m "Add MemAttest core facade: init, record, adopt, derived state"
```

---

### Task 9: Verification — the three checks

**Files:**
- Modify: `src/memattest/core.py` (add `VerifyReport`, `MemAttest.verify()`)
- Test: `tests/test_verify_attacks.py`

**Interfaces:**
- Consumes: Task 8's `MemAttest` internals
- Produces (module `memattest.core`):
  - `@dataclass VerifyReport`: `ok: bool`, `exit_code: int` (0/1/3 — operational errors raise `MemAttestError` instead, mapped to 2 by the CLI), `problems: list[dict]`. Problem dicts: `{"kind": str, "path": str | None, "detail": str, "last_valid_index": int | None}`. Kinds: `unknown-scheme`, `bad-signature`, `root-mismatch`, `log-truncated`, `modified`, `missing`, `unlogged`.
  - `MemAttest.verify() -> VerifyReport` implementing spec §7's three checks: (1) tree integrity — every STH signature verifies AND recomputed root over the first `tree_size` leaves matches each STH's `root_hash`; (2) history consistency — follows from check 1 applied to every STH in the chain (we hold all leaves, so recomputing each prefix root IS the consistency check), plus latest `tree_size` must equal entry count; (3) state conformance — derived state vs actual guarded files. Requires only the public key.

- [ ] **Step 1: Write the failing test**

One test per threat-model/attack claim (spec §12.2). The fixture builds a guarded dir with real history.

`tests/test_verify_attacks.py`:

```python
import json
from pathlib import Path

import pytest

from memattest.canonical import canonical_json
from memattest.core import MemAttest
from memattest.identity import Identity, KeyStore
from memattest.errors import KeyStoreError
from memattest.seal import build_sth
from memattest import merkle


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyStoreError(name)
        return self.data[name]


@pytest.fixture
def mem(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    m = MemAttest(d, keystore=MemoryKeyStore())
    m.init()
    for name, text in [("a.md", "alpha"), ("b.md", "beta"), ("c.md", "gamma")]:
        f = d / name
        f.write_text(text, encoding="utf-8")
        m.record(f)
    return m


def entry_files(m):
    return sorted(m.store.entries_dir.glob("*.json"))


def kinds(report):
    return [p["kind"] for p in report.problems]


def test_clean_history_verifies(mem):
    r = mem.verify()
    assert r.ok and r.exit_code == 0 and r.problems == []


def test_bitflip_guarded_file_detected(mem):
    (mem.memory_dir / "b.md").write_text("Beta", encoding="utf-8")
    r = mem.verify()
    assert not r.ok and r.exit_code == 1
    (p,) = r.problems
    assert p["kind"] == "modified" and p["path"] == "b.md"
    assert p["last_valid_index"] == 2  # b.md was recorded at entry index 2


def test_delete_guarded_file_detected(mem):
    (mem.memory_dir / "c.md").unlink()
    r = mem.verify()
    assert kinds(r) == ["missing"] and r.problems[0]["path"] == "c.md"


def test_unlogged_file_detected(mem):
    (mem.memory_dir / "planted.md").write_text("evil", encoding="utf-8")
    r = mem.verify()
    assert kinds(r) == ["unlogged"] and r.problems[0]["path"] == "planted.md"


def test_reorder_entries_detected(mem):
    files = entry_files(mem)
    e1, e2 = json.loads(files[1].read_text()), json.loads(files[2].read_text())
    e1["index"], e2["index"] = 2, 1  # swap positions in the sequence
    files[1].write_bytes(canonical_json(e2))
    files[2].write_bytes(canonical_json(e1))
    r = mem.verify()
    assert not r.ok and "root-mismatch" in kinds(r)


def test_replace_entry_wholesale_detected(mem):
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["content_hash"] = "sha256:" + "00" * 32
    f.write_bytes(canonical_json(e))
    assert "root-mismatch" in kinds(mem.verify())


def test_backdate_timestamp_detected(mem):
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["timestamp"] = "2020-01-01T00:00:00Z"
    f.write_bytes(canonical_json(e))
    assert "root-mismatch" in kinds(mem.verify())


def test_truncate_log_detected(mem):
    entry_files(mem)[-1].unlink()
    r = mem.verify()
    assert not r.ok and "log-truncated" in kinds(r)


def test_forged_sth_without_key_detected(mem):
    # Attacker rewrites an entry AND recomputes a matching root, but must sign
    # with their own key because they cannot unseal ours.
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["content_hash"] = "sha256:" + "ff" * 32
    f.write_bytes(canonical_json(e))
    attacker = Identity.generate(MemoryKeyStore(), "attacker")
    leaves = mem.store.leaf_bytes()
    forged = build_sth(len(leaves), merkle.root_hash(leaves), attacker)
    sth_files = sorted(mem.sth_chain.sth_dir.glob("*.json"))
    sth_files[-1].write_bytes(canonical_json(forged))
    r = mem.verify()
    assert not r.ok and "bad-signature" in kinds(r)


def test_unknown_scheme_reported_not_guessed(mem):
    f = entry_files(mem)[1]
    e = json.loads(f.read_text())
    e["scheme"] = "v99"
    f.write_bytes(canonical_json(e))
    r = mem.verify()
    assert not r.ok and r.exit_code == 3
    assert "unknown-scheme" in kinds(r)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_verify_attacks.py -v`
Expected: FAIL — `AttributeError: 'MemAttest' object has no attribute 'verify'`

- [ ] **Step 3: Write the implementation (append to `src/memattest/core.py`)**

Add imports at top of file: `from dataclasses import dataclass, field` and `from .entry import SCHEME` and `from .seal import verify_sth`.

```python
@dataclass
class VerifyReport:
    ok: bool
    exit_code: int
    problems: list = field(default_factory=list)


def _problem(kind: str, path: str | None, detail: str, last_valid_index: int | None = None) -> dict:
    return {"kind": kind, "path": path, "detail": detail, "last_valid_index": last_valid_index}
```

Add to `MemAttest`:

```python
    def verify(self) -> VerifyReport:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        problems: list[dict] = []
        entries = self.store.load_all()
        pub = bytes.fromhex(self.pubkey_path.read_text(encoding="ascii").strip())

        # Scheme dispatch (spec §9): refuse to guess at unknown schemes.
        unknown = [e for e in entries if e.get("scheme") != SCHEME]
        for e in unknown:
            problems.append(_problem("unknown-scheme", e.get("path"),
                                     f"entry {e.get('index')} has scheme {e.get('scheme')!r}"))
        if unknown:
            return VerifyReport(ok=False, exit_code=3, problems=problems)

        leaves = self.store.leaf_bytes()
        sths = self.sth_chain.load_all()

        # Check 1+2: every STH must be signed by our key AND match the recomputed
        # root of its prefix. Because we hold all leaves, recomputing every prefix
        # root is exactly the consistency check between successive STHs.
        for i, sth in enumerate(sths):
            if not verify_sth(sth, pub):
                problems.append(_problem("bad-signature", None, f"STH {i} signature invalid"))
                continue
            size = sth["tree_size"]
            if size > len(leaves):
                problems.append(_problem("log-truncated", None,
                                         f"STH {i} covers {size} entries but only {len(leaves)} exist"))
                continue
            if merkle.root_hash(leaves[:size]).hex() != sth["root_hash"]:
                problems.append(_problem("root-mismatch", None,
                                         f"recomputed root for first {size} entries != STH {i}"))
        if sths and sths[-1]["tree_size"] != len(leaves) and not any(
            p["kind"] == "log-truncated" for p in problems
        ):
            problems.append(_problem("root-mismatch", None,
                                     f"latest STH covers {sths[-1]['tree_size']} of {len(leaves)} entries"))
        if not sths and entries:
            problems.append(_problem("root-mismatch", None, "entries exist but no STH found"))

        # Check 3: state conformance — derived expected state vs actual files.
        expected = self.derived_state()
        last_index: dict[str, int] = {}
        for e in entries:
            last_index[e["path"]] = e["index"]
        actual = {self._rel(p): p for p in self.guarded_files()}
        for rel, exp_hash in expected.items():
            if rel not in actual:
                problems.append(_problem("missing", rel, "file recorded in log but absent on disk",
                                         last_index.get(rel)))
            elif file_content_hash(actual[rel]) != exp_hash:
                problems.append(_problem("modified", rel, "file content differs from last recorded hash",
                                         last_index.get(rel)))
        for rel in actual:
            if rel not in expected:
                problems.append(_problem("unlogged", rel, "file on disk was never recorded in the log"))

        ok = not problems
        return VerifyReport(ok=ok, exit_code=0 if ok else 1, problems=problems)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_verify_attacks.py tests/test_core.py -v`
Expected: all passed (10 attack/clean tests + 5 core tests)

- [ ] **Step 5: Commit**

```
git add src/memattest/core.py tests/test_verify_attacks.py
git commit -m "Add three-check verification with attack simulation test suite"
```

---

### Task 10: CLI with exit-code contract

**Files:**
- Create: `src/memattest/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `MemAttest`, `VerifyReport`, `MemAttestError`, `KeyringKeyStore`, `FileKeyStore`, `merkle.inclusion_proof`, `merkle.consistency_proof`
- Produces: `main(argv: list[str] | None = None) -> int` (console script `memattest` wraps it in `sys.exit`). Subcommands, each taking `--memory-dir PATH` (default `.`) and `--keystore keyring|file` (default `keyring`; `file` reads passphrase from env `MEMATTEST_PASSPHRASE`, key file `.memattest/key.sealed`):
  - `init` — initialize + baseline
  - `record --path FILE [--op write|delete]` — append one event (used by hooks)
  - `verify` — run checks, print one line per problem as `PROBLEM kind=<kind> path=<path> detail=<detail> last_valid=<index>`, print `OK <n> entries verified` when clean; return report exit code
  - `adopt PATHS... --reason TEXT` — TTY-guarded (see Task 11 for the guard tests; wire the guard now)
  - `log` — print each entry as one JSON line
  - `prove --index N | --old-size M` — print inclusion/consistency proof as JSON (hex node list)
  - `hook post-tool-use` — read Claude Code hook payload JSON from stdin; if `tool_input.file_path` is under the memory dir (and not under `.memattest`), record a write; silently exit 0 otherwise
- Exit codes: subcommand result or `2` on any `MemAttestError`/`KeyStoreError` (printed to stderr as `error: <msg>`).

- [ ] **Step 1: Write the failing test**

`tests/test_cli.py`:

```python
import json

import pytest

from memattest import cli


@pytest.fixture
def memdir(tmp_path, monkeypatch):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "test-pw")
    return d


def run(*args):
    return cli.main(list(args))


def base(d):
    return ["--memory-dir", str(d), "--keystore", "file"]


def test_init_then_verify_clean(memdir, capsys):
    assert run("init", *base(memdir)) == 0
    assert run("verify", *base(memdir)) == 0
    assert "OK" in capsys.readouterr().out


def test_record_and_tamper_flow(memdir, capsys):
    run("init", *base(memdir))
    f = memdir / "notes.md"
    f.write_text("v1", encoding="utf-8")
    assert run("record", *base(memdir), "--path", str(f)) == 0
    f.write_text("tampered", encoding="utf-8")
    assert run("verify", *base(memdir)) == 1
    out = capsys.readouterr().out
    assert "kind=modified" in out and "path=notes.md" in out


def test_verify_uninitialized_is_operational_error(memdir, capsys):
    assert run("verify", *base(memdir)) == 2
    assert "error:" in capsys.readouterr().err


def test_log_prints_entries_as_json_lines(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    assert run("log", *base(memdir)) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["op"] == "adopt"


def test_prove_inclusion(memdir, capsys):
    run("init", *base(memdir))
    capsys.readouterr()
    assert run("prove", *base(memdir), "--index", "0") == 0
    proof = json.loads(capsys.readouterr().out)
    assert proof == []  # single-leaf tree has an empty audit path


def test_hook_post_tool_use_records_write(memdir, capsys, monkeypatch):
    run("init", *base(memdir))
    f = memdir / "notes.md"
    f.write_text("from hook", encoding="utf-8")
    payload = json.dumps({"tool_input": {"file_path": str(f)}})
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert run("hook", "post-tool-use", *base(memdir)) == 0
    assert run("verify", *base(memdir)) == 0


def test_hook_ignores_files_outside_memory_dir(memdir, tmp_path, monkeypatch):
    run("init", *base(memdir))
    outside = tmp_path / "elsewhere.md"
    outside.write_text("x", encoding="utf-8")
    payload = json.dumps({"tool_input": {"file_path": str(outside)}})
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO(payload))
    assert run("hook", "post-tool-use", *base(memdir)) == 0
    assert run("verify", *base(memdir)) == 0  # nothing recorded, still clean
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'memattest.cli'`

- [ ] **Step 3: Write minimal implementation**

`src/memattest/cli.py`:

```python
import argparse
import json
import os
import sys
from pathlib import Path

from . import merkle
from .core import MemAttest, VerifyReport
from .errors import MemAttestError
from .identity import FileKeyStore, KeyringKeyStore


def _make_ma(args) -> MemAttest:
    memory_dir = Path(args.memory_dir)
    if args.keystore == "file":
        passphrase = os.environ.get("MEMATTEST_PASSPHRASE")
        if not passphrase:
            raise MemAttestError("keystore 'file' requires MEMATTEST_PASSPHRASE to be set")
        ks = FileKeyStore(memory_dir / ".memattest" / "key.sealed", passphrase.encode("utf-8"))
    else:
        ks = KeyringKeyStore()
    return MemAttest(memory_dir, keystore=ks)


def _print_report(report: VerifyReport, entry_count: int) -> None:
    if report.ok:
        print(f"OK {entry_count} entries verified")
        return
    for p in report.problems:
        print(f"PROBLEM kind={p['kind']} path={p['path']} detail={p['detail']} last_valid={p['last_valid_index']}")


def cmd_init(args) -> int:
    ma = _make_ma(args)
    entries = ma.init()
    print(f"initialized; adopted {len(entries)} pre-existing file(s)")
    return 0


def cmd_record(args) -> int:
    ma = _make_ma(args)
    ma.record(Path(args.path), op=args.op)
    return 0


def cmd_verify(args) -> int:
    ma = _make_ma(args)
    report = ma.verify()
    _print_report(report, ma.store.count())
    return report.exit_code


def cmd_adopt(args) -> int:
    if not sys.stdin.isatty():
        print("error: adopt requires an interactive terminal", file=sys.stderr)
        return 2
    ma = _make_ma(args)
    print(f"About to adopt {len(args.paths)} file(s) as trusted. Reason: {args.reason}")
    if input("Type 'adopt' to confirm: ").strip() != "adopt":
        print("aborted", file=sys.stderr)
        return 2
    ma.adopt([Path(p) for p in args.paths], reason=args.reason)
    print(f"adopted {len(args.paths)} file(s)")
    return 0


def cmd_log(args) -> int:
    ma = _make_ma(args)
    for e in ma.store.load_all():
        print(json.dumps(e, sort_keys=True))
    return 0


def cmd_prove(args) -> int:
    ma = _make_ma(args)
    leaves = ma.store.leaf_bytes()
    if args.index is not None:
        proof = merkle.inclusion_proof(args.index, leaves)
    elif args.old_size is not None:
        proof = merkle.consistency_proof(args.old_size, leaves)
    else:
        raise MemAttestError("prove requires --index or --old-size")
    print(json.dumps([h.hex() for h in proof]))
    return 0


def cmd_hook_post_tool_use(args) -> int:
    payload = json.load(sys.stdin)
    file_path = (payload.get("tool_input") or {}).get("file_path")
    if not file_path:
        return 0
    target = Path(file_path).resolve()
    memory_dir = Path(args.memory_dir).resolve()
    try:
        rel = target.relative_to(memory_dir)
    except ValueError:
        return 0  # write outside the guarded directory: not our concern
    if ".memattest" in rel.parts or not target.exists():
        return 0
    _make_ma(args).record(target)
    return 0


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--memory-dir", default=".")
    p.add_argument("--keystore", choices=["keyring", "file"], default="keyring")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="memattest",
                                     description="Tamper-evident agent memory (append-only Merkle log)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="initialize and baseline existing memories")
    _add_common(p)
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("record", help="append one write/delete event")
    _add_common(p)
    p.add_argument("--path", required=True)
    p.add_argument("--op", choices=["write", "delete"], default="write")
    p.set_defaults(fn=cmd_record)

    p = sub.add_parser("verify", help="run the three integrity checks")
    _add_common(p)
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("adopt", help="bless out-of-band changes (interactive only)")
    _add_common(p)
    p.add_argument("paths", nargs="+")
    p.add_argument("--reason", required=True)
    p.set_defaults(fn=cmd_adopt)

    p = sub.add_parser("log", help="print entries as JSON lines")
    _add_common(p)
    p.set_defaults(fn=cmd_log)

    p = sub.add_parser("prove", help="emit inclusion or consistency proof")
    _add_common(p)
    p.add_argument("--index", type=int)
    p.add_argument("--old-size", type=int)
    p.set_defaults(fn=cmd_prove)

    p = sub.add_parser("hook", help="harness hook entry points")
    hook_sub = p.add_subparsers(dest="hook_command", required=True)
    hp = hook_sub.add_parser("post-tool-use")
    _add_common(hp)
    hp.set_defaults(fn=cmd_hook_post_tool_use)

    args = parser.parse_args(argv)
    try:
        return args.fn(args)
    except MemAttestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv\Scripts\python -m pytest tests/test_cli.py -v`
Expected: 7 passed

- [ ] **Step 5: Commit**

```
git add src/memattest/cli.py tests/test_cli.py
git commit -m "Add CLI with 0/1/2/3 exit-code contract and post-tool-use hook"
```

---

### Task 11: Adopt semantics and protections

**Files:**
- Modify: none (behavior exists in Tasks 8/10) — this task *proves* the spec §8 guarantees
- Test: `tests/test_adopt.py`

**Interfaces:**
- Consumes: `MemAttest`, `cli.main`
- Produces: regression tests pinning the adopt protections. If any test here fails, the corresponding Task 8/10 code is wrong — fix it there, not by weakening the test.

- [ ] **Step 1: Write the failing-or-passing test**

`tests/test_adopt.py`:

```python
import io
import json

import pytest

from memattest import cli
from memattest.core import MemAttest
from memattest.identity import KeyStore
from memattest.errors import KeyStoreError


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyStoreError(name)
        return self.data[name]


@pytest.fixture
def mem(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    m = MemAttest(d, keystore=MemoryKeyStore())
    m.init()
    return m


def test_adopt_reconciles_out_of_band_edit(mem):
    f = mem.memory_dir / "MEMORY.md"
    f.write_text("hand-edited on a saturday", encoding="utf-8")
    assert not mem.verify().ok
    mem.adopt([f], reason="my own weekend edit")
    report = mem.verify()
    assert report.ok and report.exit_code == 0


def test_adopt_appends_never_rewrites(mem):
    f = mem.memory_dir / "MEMORY.md"
    original_entry_bytes = (mem.store.entries_dir / "000000.json").read_bytes()
    f.write_text("changed", encoding="utf-8")
    mem.adopt([f], reason="r")
    # The pre-existing entry file is byte-identical; history was extended, not edited.
    assert (mem.store.entries_dir / "000000.json").read_bytes() == original_entry_bytes
    entries = mem.store.load_all()
    assert len(entries) == 2 and entries[1]["op"] == "adopt" and entries[1]["reason"] == "r"
    # The old (contradicted) hash remains visible in history:
    assert entries[0]["content_hash"] != entries[1]["content_hash"]


def test_adopt_records_reason_and_provenance(mem):
    f = mem.memory_dir / "MEMORY.md"
    f.write_text("x", encoding="utf-8")
    (entry,) = mem.adopt([f], reason="because tests")
    assert entry["reason"] == "because tests"
    assert "interactive_tty" in entry["provenance"]["session"]
    assert "parent_chain" in entry["provenance"]["process"]


def test_cli_adopt_refuses_without_tty(tmp_path, monkeypatch):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO("adopt\n")
    fake_stdin.isatty = lambda: False  # simulate piped/non-interactive stdin
    monkeypatch.setattr("sys.stdin", fake_stdin)
    rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    assert rc == 2


def test_cli_adopt_requires_typed_confirmation(tmp_path, monkeypatch):
    d = tmp_path / "memory"
    d.mkdir()
    monkeypatch.setenv("MEMATTEST_PASSPHRASE", "pw")
    cli.main(["init", "--memory-dir", str(d), "--keystore", "file"])
    f = d / "new.md"
    f.write_text("x", encoding="utf-8")
    fake_stdin = io.StringIO()
    fake_stdin.isatty = lambda: True
    monkeypatch.setattr("sys.stdin", fake_stdin)
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    rc = cli.main(["adopt", str(f), "--reason", "r", "--memory-dir", str(d), "--keystore", "file"])
    assert rc == 2
```

- [ ] **Step 2: Run the tests**

Run: `.venv\Scripts\python -m pytest tests/test_adopt.py -v`
Expected: 5 passed. If any fail, fix `core.py`/`cli.py` (the spec §8 guarantees are non-negotiable), then re-run.

- [ ] **Step 3: Commit**

```
git add tests/test_adopt.py
git commit -m "Pin adopt semantics: append-only forgiveness, TTY guard, typed confirmation"
```

---

### Task 12: Claude Code integration files

**Files:**
- Create: `src/memattest/integrations/__init__.py` (empty), `src/memattest/integrations/claude_code/__init__.py` (empty), `src/memattest/integrations/claude_code/settings-snippet.json`
- Test: manual smoke test (this task is configuration, not logic; the hook logic itself was tested in Task 10)

**Interfaces:**
- Consumes: the `memattest` console script (Task 10)
- Produces: a copy-paste settings template for any Claude Code project. `<MEMORY_DIR>` is a placeholder the user replaces (e.g., `.claude/memory` or an absolute path).

- [ ] **Step 1: Create the settings snippet**

`src/memattest/integrations/claude_code/settings-snippet.json`:

```json
{
  "//": "memattest Claude Code integration template. Replace <MEMORY_DIR> with your guarded memory directory. SessionStart verifies (exit 1 = tamper report shown to user+agent); PostToolUse appends after memory writes; the deny rule keeps the agent from blessing its own tampering (spec 8).",
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "memattest verify --memory-dir <MEMORY_DIR>"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "Write|Edit",
        "hooks": [
          {
            "type": "command",
            "command": "memattest hook post-tool-use --memory-dir <MEMORY_DIR>"
          }
        ]
      }
    ]
  },
  "permissions": {
    "deny": [
      "Bash(memattest adopt:*)"
    ]
  }
}
```

- [ ] **Step 2: Smoke-test the full flow end to end**

Run (PowerShell, from repo root):

```powershell
$env:MEMATTEST_PASSPHRASE = "smoke-pw"
New-Item -ItemType Directory -Force smoke\memory | Out-Null
Set-Content smoke\memory\MEMORY.md "hello" -Encoding utf8
.venv\Scripts\memattest init --memory-dir smoke\memory --keystore file
.venv\Scripts\memattest verify --memory-dir smoke\memory --keystore file
'{"tool_input": {"file_path": "smoke/memory/notes.md"}}' | Out-File smoke\payload.json -Encoding utf8
Set-Content smoke\memory\notes.md "a new memory" -Encoding utf8
Get-Content smoke\payload.json | .venv\Scripts\memattest hook post-tool-use --memory-dir smoke\memory --keystore file
.venv\Scripts\memattest verify --memory-dir smoke\memory --keystore file
Set-Content smoke\memory\notes.md "TAMPERED" -Encoding utf8
.venv\Scripts\memattest verify --memory-dir smoke\memory --keystore file; echo "exit=$LASTEXITCODE"
```

Expected: two `OK ... entries verified` lines, then a `PROBLEM kind=modified path=notes.md ...` line with `exit=1`.

- [ ] **Step 3: Clean up smoke dir and commit**

```
Remove-Item -Recurse -Force smoke
git add src/memattest/integrations
git commit -m "Add Claude Code settings template for hooks and adopt deny rule"
```

---

### Task 13: README with security limitations

**Files:**
- Create: `README.md`

**Interfaces:**
- Consumes: everything (documentation of the finished v1)
- Produces: user-facing documentation. The spec (§2) requires the same-user-malware limitation to be documented **in bold**.

- [ ] **Step 1: Write README.md**

Content requirements (write full prose, not this outline):
- One-paragraph pitch: tamper-evident agent memory via RFC 6962 append-only Merkle log + signed tree heads; detects out-of-band edits and history rewrites; names the exact file/entry.
- What it does NOT do: content screening ("front-door" poisoning — a compromised agent recording a malicious memory through the normal write path produces a validly attested entry); point to OWASP Agent Memory Guard as the complementary content layer.
- Quickstart: `pip install -e .`, `memattest init --memory-dir <dir>`, the Claude Code settings snippet (reference `src/memattest/integrations/claude_code/settings-snippet.json`), `memattest verify`, the adopt flow for legitimate hand edits.
- Keystore section: `--keystore keyring` (default; DPAPI/Secret Service/Keychain) vs `--keystore file` + `MEMATTEST_PASSPHRASE` for headless hosts.
- Extending provenance: entry-point group `memattest.providers`, with the git-workspace provider sketched as the example (zero-arg callable returning a dict).
- Security limitations, verbatim commitments from spec §2: **"Malware running as your own OS user can unseal the signing key and forge history. memattest v1 protects against other users' processes and against agents rewriting their own history — not against same-user malware. A v2 resident validator service under a separate account is the planned mitigation."** Also: admin-level attackers and remote stores out of scope; adopt by same-user malware cannot be silent (it leaves a signed adopt event).
- Exit codes table: 0/1/2/3.

- [ ] **Step 2: Run the full test suite one final time**

Run: `.venv\Scripts\python -m pytest -v`
Expected: all tests pass (0 failures; keyring smoke test may skip).

- [ ] **Step 3: Commit**

```
git add README.md
git commit -m "Add README with quickstart, keystore options, and security limitations"
```

---

## Next steps (post-v1, in rough priority order)

Added 2026-07-09 after the self-testing/hardening round. Each item below needs its
own brainstorm/design pass before implementation; this is a roadmap, not a
task breakdown. Items 1–3 are v1.x-sized; the rest are v2-sized (spec §13).

1. **Keystore-sealed pubkey cross-check** — **done 2026-07-12**
   (spec `docs/superpowers/specs/2026-07-12-pubkey-crosscheck-design.md`,
   plan `docs/superpowers/plans/2026-07-12-pubkey-crosscheck.md`).
   Verify re-derives the public key from the backend-keystore-held signing
   seed and cross-checks the on-disk `pubkey.ed25519`; divergence is
   `key-mismatch`, a missing keystore entry is `key-missing` (both exit-1
   `PROBLEM`s), and `--no-key-check` is the explicit opt-out for copied-log
   audits.

2. **Per-log `config.toml` in `.memattest/`** (spec §13). Record the keystore
   backend chosen at init — verifying with the wrong `--keystore` today yields
   a false `key-missing` tamper finding instead of a clear "this log uses the
   file backend keystore" message. This file is also the natural home for the watch list (item 3)
   and future provider/guard-glob config. Note the config file itself is
   inside the trust boundary and must be covered by the same integrity story
   it configures (hash it into the log or seal it with the key).

3. **Watch list: attest designated files outside the memory directory.**
   The self-testing round showed the hook configuration is part of the trust
   surface: an attacker who edits the Claude Code settings files (or
   `CLAUDE.md`) can un-hook or misdirect memattest, and the current answer is
   only prevention-at-the-agent (PreToolUse guard) plus the silence canary.
   Let `init`/`adopt` record content hashes of user-designated watch files
   (e.g. `.claude/settings.json`, `settings.local.json`, `CLAUDE.md`), and
   have `verify`/`hook session-start` report divergence in them exactly like
   memory-file tampering. Detection complements the existing guard: agent
   edits are blocked, human/out-of-band edits become visible next session,
   and only total hook removal remains — caught by the silence canary.
   Open design questions for the brainstorm: watched paths live outside
   `memory_dir`, so the entry `path` namespace must distinguish them (prefix
   vs. separate log — and whether that requires a scheme bump per §9);
   watched files change legitimately more often than memories, so the
   adopt-to-reconcile flow needs to stay low-friction without becoming a
   rubber stamp; and the watch list itself must be tamper-evident (item 2).

4. **External root anchoring** (spec §13; closes the rollback limitation).
   Publish or timestamp the latest STH somewhere an attacker with local write
   access cannot reach (transparency log, RFC 3161 TSA, or even a remote git
   ref). Prerequisite thinking for the v2 validator service.

5. **v2 resident validator service** under a separate OS account
   (spec §2/§13; closes the same-user-malware gap, enables near-real-time
   watching rather than session-start batch verification).

6. **Distribution and CI**: publish to PyPI (README quickstart currently
   requires a local clone) and stand up the deferred hosted CI matrix
   (Windows + Linux) once the repo has a remote.

7. **Ecosystem** (spec §13): mediated-store mode (MCP write path,
   enforcement), middleware adapters (LangChain / mem0 / AutoGen), OWASP
   Agent Memory Guard positioning, remote/synced store support.

## Self-Review (completed during planning)

**Spec coverage check:**
- §5 components → Tasks 1–7 (canonical, merkle, entry/store, identity, seal, provenance) ✔
- §6 data model (entry fields, storage layout, keypair identity) → Tasks 4–6, 8 ✔
- §7 operations (append / verify three checks / inspect / adopt) → Tasks 8–10 ✔
- §8 adopt protections (TTY, deny rule, provenance audit) → Tasks 10–12 ✔
- §9 scheme dispatch + unknown-scheme refusal → Task 9 (`unknown-scheme`, exit 3). Countersigning/checkpoint STHs have no v1 trigger (no rotation exists yet) and are deliberately not implemented — policy documented in spec.
- §10 Claude Code integration → Tasks 10 (hook subcommand), 12 (settings template) ✔
- §11 error handling table → Task 9 (report kinds), Task 10 (exit mapping, fail-closed append via KeyStoreError→2) ✔
- §12 testing strategy → Tasks 2 (RFC vectors), 3 (exhaustive proof verification — chosen over randomized Hypothesis testing as strictly stronger at this scale, and one dependency lighter), 9 (all eight attack simulations), 11 (adopt semantics), 12 (end-to-end smoke on this Windows machine; Linux via the same pytest suite) ✔ — a hosted CI matrix is deferred until the repo has a remote.
- §12.5 self-testing → deferred by design until after v1 works (guarding this repo's own memory dir is a post-plan activity).

**Type consistency check:** `canonical_json`, `root_hash(leaves)` over raw bytes, `LogStore(state_dir)`, `Identity.generate/load(keystore, name)`, `build_sth(tree_size, root, identity)`, `collect(extra)`, `MemAttest(memory_dir, keystore)`, `VerifyReport(ok, exit_code, problems)` — used identically across Tasks 4–12. Exit codes 0/1/2/3 consistent across Tasks 9–13.
