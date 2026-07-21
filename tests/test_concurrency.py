from pathlib import Path

import pytest

from memattest.core import MemAttest
from memattest.identity import FileKeyStore


def _file_ma(tmp_path):
    d = tmp_path / "memory"
    d.mkdir()
    (d / "MEMORY.md").write_text("index", encoding="utf-8")
    ks = FileKeyStore(d / ".memattest" / "key.sealed", b"pw")
    return MemAttest(d, keystore=ks)


def test_lock_file_lives_in_state_dir(tmp_path):
    ma = _file_ma(tmp_path)
    ma.init()
    f = ma.memory_dir / "note.md"
    f.write_text("x", encoding="utf-8")
    ma.record(f)
    assert (ma.state_dir / "append.lock").exists()
    # The lock file must not be counted as an entry or flagged unlogged.
    assert ma.verify().ok


def test_timeout_becomes_operational_error(tmp_path, monkeypatch):
    # filelock is reentrant within one process, so a real same-process hold
    # would not time out. Force the Timeout deterministically instead and
    # assert record translates it to an operational error.
    import filelock
    from memattest.errors import MemAttestError
    ma = _file_ma(tmp_path)
    ma.init()
    f = ma.memory_dir / "note.md"
    f.write_text("x", encoding="utf-8")

    class _AlwaysTimeout:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            raise filelock.Timeout("busy")

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(filelock, "FileLock", _AlwaysTimeout)
    with pytest.raises(MemAttestError, match="could not acquire the append lock"):
        ma.record(f)
