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


def test_record_outside_memory_dir_raises_memattest_error(mem, tmp_path):
    mem.init()
    outsider = tmp_path / "outside.md"
    outsider.write_text("x", encoding="utf-8")
    with pytest.raises(MemAttestError, match="not under the guarded memory directory"):
        mem.record(outsider)


def test_record_before_init_raises_memattest_error(mem):
    f = mem.memory_dir / "notes.md"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(MemAttestError, match="not initialized"):
        mem.record(f)


def test_record_inside_state_dir_raises_memattest_error(mem):
    mem.init()
    target = mem.store.entries_dir / "000000.json"
    with pytest.raises(MemAttestError, match="state directory"):
        mem.record(target)


def test_verify_before_init_raises_not_initialized(mem):
    with pytest.raises(MemAttestError, match="not initialized"):
        mem.verify()
