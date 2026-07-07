import json
from typing import Any


def canonical_json(obj: Any) -> bytes:
    """Deterministic byte serialization used for all hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
