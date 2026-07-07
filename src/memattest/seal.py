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
