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


def test_store_never_overwrites_existing_entry_file(tmp_path):
    store = LogStore(tmp_path / ".memattest")
    store.append(build_entry(0, "write", "a.md", "sha256:00", {}))
    # Simulate a non-contiguous entries dir: index 1 exists on disk but count() sees 2 files.
    (tmp_path / ".memattest" / "entries" / "000002.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="append-only"):
        store.append(build_entry(2, "write", "b.md", "sha256:01", {}))
