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
