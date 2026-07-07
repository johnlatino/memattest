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
        try:
            return Path(path).resolve().relative_to(self.memory_dir.resolve()).as_posix()
        except ValueError as exc:
            raise MemAttestError(f"{path} is not under the guarded memory directory {self.memory_dir}") from exc

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
