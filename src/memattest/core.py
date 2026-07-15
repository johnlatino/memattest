from dataclasses import dataclass, field
from pathlib import Path

from . import merkle, per_log_config, provenance
from .entry import SCHEME, build_entry, file_content_hash
from .errors import KeyNotFoundError, KeyStoreError, MemAttestError
from .identity import Identity, KeyringKeyStore, KeyStore
from .seal import SthChain, build_sth, verify_sth
from .store import LogStore

STATE_DIR_NAME = ".memattest"


@dataclass
class VerifyReport:
    ok: bool
    exit_code: int
    problems: list = field(default_factory=list)


def _problem(kind: str, path: str | None, detail: str, last_valid_index: int | None = None) -> dict:
    return {"kind": kind, "path": path, "detail": detail, "last_valid_index": last_valid_index}


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
        try:
            rel = Path(path).resolve().relative_to(self.memory_dir.resolve())
        except ValueError as exc:
            raise MemAttestError(f"{path} is not under the guarded memory directory {self.memory_dir}") from exc
        if STATE_DIR_NAME in rel.parts:
            raise MemAttestError(f"{path} is inside the memattest state directory and cannot be recorded")
        return rel.as_posix()

    def _identity(self) -> Identity:
        return Identity.load(self.keystore, self.key_name)

    def _write_config_if_named(self) -> None:
        # Called only after the backend keystore has demonstrably held the
        # signing key (init just sealed it; the record/adopt that just
        # succeeded signed with it), so the recorded name is proven, not
        # guessed, and a failed append leaves no config (spec 2026-07-13 §7).
        if self.keystore.config_name is None:
            return
        if per_log_config.load_config(self.state_dir) is None:
            per_log_config.write_config(self.state_dir, self.keystore.config_name)

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
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.pubkey_path.write_text(identity.public_key_bytes.hex(), encoding="ascii")
        self._write_config_if_named()
        entries = [self._append(identity, "adopt", p, reason) for p in self.guarded_files()]
        self._seal_current_tree(identity)
        return entries

    def record(self, path: Path, op: str = "write", reason: str | None = None) -> dict:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        identity = self._identity()
        entry = self._append(identity, op, path, reason)
        self._seal_current_tree(identity)
        self._write_config_if_named()
        return entry

    def adopt(self, paths: list[Path], reason: str) -> list[dict]:
        if not self.initialized:
            raise MemAttestError("not initialized; run init first")
        identity = self._identity()
        entries = [self._append(identity, "adopt", p, reason) for p in paths]
        self._seal_current_tree(identity)
        self._write_config_if_named()
        return entries

    def derived_state(self) -> dict[str, str]:
        state: dict[str, str] = {}
        for e in self.store.load_all():
            if e["op"] in ("write", "adopt"):
                state[e["path"]] = e["content_hash"]
            elif e["op"] == "delete":
                state.pop(e["path"], None)
        return state

    def verify(self, key_check: bool = True) -> VerifyReport:
        problems: list[dict] = []
        entries = self.store.load_all()
        sths = self.sth_chain.load_all()

        if not entries and not sths and not self.initialized:
            raise MemAttestError("not initialized; run init first")

        # Try to load pubkey first; missing/unreadable/corrupted pubkey is an operational error
        try:
            pub = bytes.fromhex(self.pubkey_path.read_text(encoding="ascii").strip())
        except (OSError, ValueError) as exc:
            raise MemAttestError(f"cannot load public key from {self.pubkey_path}: {exc}") from exc

        # If we have entries/STHs but no initialization-level setup, that's an error
        if not entries and not sths:
            raise MemAttestError("not initialized; run init first")

        # Cross-check (spec 2026-07-12): re-derive the public key from the
        # signing seed held in the backend keystore and compare it with the
        # on-disk pubkey. The backend keystore entry is the trust anchor; the
        # disk file is only the claim being checked. On mismatch the derived
        # key takes over as the STH verification key below, so a re-signed
        # forged history also fails as bad-signature instead of verifying
        # against the attacker's planted pubkey.
        if key_check:
            try:
                derived = Identity.load(self.keystore, self.key_name).public_key_bytes
            except KeyNotFoundError:
                problems.append(_problem(
                    "key-missing", None,
                    f"backend keystore has no signing key for {self.key_name!r}; "
                    "the log's authorship cannot be established (accidental key "
                    "loss and a hostile rewrite are indistinguishable) and "
                    "appends will fail — manually review memory contents "
                    "before re-initializing",
                ))
            except KeyStoreError as exc:
                raise MemAttestError(
                    f"keystore unavailable for signing-key cross-check: {exc}; "
                    "pass --no-key-check to verify without it"
                ) from exc
            else:
                if derived != pub:
                    problems.append(_problem(
                        "key-mismatch", None,
                        f"pubkey.ed25519 contains {pub.hex()} but the key "
                        f"derived from the backend keystore is {derived.hex()}; "
                        "the on-disk pubkey was replaced",
                    ))
                    pub = derived

        # Scheme dispatch (spec §9): refuse to guess at unknown schemes.
        # Intentional: unknown schemes make the log unverifiable as a whole; report only exit-3 problems rather than guessing at tree/state checks.
        unknown = [e for e in entries if e.get("scheme") != SCHEME]
        for e in unknown:
            problems.append(_problem("unknown-scheme", e.get("path"),
                                     f"entry {e.get('index')} has scheme {e.get('scheme')!r}"))
        if unknown:
            return VerifyReport(ok=False, exit_code=3, problems=problems)

        leaves = self.store.leaf_bytes()

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

        # Check 3: state conformance — derived expected state vs actual guarded files.
        expected = self.derived_state()
        last_entry: dict[str, dict] = {}
        for e in entries:
            last_entry[e["path"]] = e
        actual = {self._rel(p): p for p in self.guarded_files()}
        for rel, exp_hash in expected.items():
            e = last_entry[rel]
            if rel not in actual:
                detail = (
                    f"file recorded in log (expected {exp_hash}) but absent on disk; "
                    f"last recorded at entry {e['index']} ({e['timestamp']})"
                )
                problems.append(_problem("missing", rel, detail, e["index"]))
            else:
                actual_hash = file_content_hash(actual[rel])
                if actual_hash != exp_hash:
                    detail = (
                        f"expected {exp_hash}, found {actual_hash}; "
                        f"last recorded at entry {e['index']} ({e['timestamp']})"
                    )
                    problems.append(_problem("modified", rel, detail, e["index"]))
        for rel in actual:
            if rel not in expected:
                problems.append(_problem("unlogged", rel, "file on disk was never recorded in the log"))

        ok = not problems
        return VerifyReport(ok=ok, exit_code=0 if ok else 1, problems=problems)
