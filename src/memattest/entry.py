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
    scope: str = "memory",
) -> dict:
    if op not in ("write", "delete", "adopt"):
        raise ValueError(f"unknown op: {op}")
    if scope not in ("memory", "watch"):
        raise ValueError(f"unknown scope: {scope}")
    entry = {
        "scheme": SCHEME,
        "index": index,
        "timestamp": timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "op": op,
        "scope": scope,
        "path": path,
        "content_hash": content_hash,
        "provenance": provenance,
    }
    if reason is not None:
        entry["reason"] = reason
    return entry
