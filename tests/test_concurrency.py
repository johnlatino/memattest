import multiprocessing as mp
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


def _record_worker(memory_dir, key_path, passphrase, filename, content, barrier):
    from memattest.core import MemAttest
    from memattest.identity import FileKeyStore
    ma = MemAttest(Path(memory_dir), keystore=FileKeyStore(Path(key_path), passphrase))
    f = Path(memory_dir) / filename
    f.write_text(content, encoding="utf-8")
    barrier.wait()  # all workers hit record() together, forcing contention
    ma.record(f)


def test_concurrent_records_all_land_and_verify_clean(tmp_path):
    ma = _file_ma(tmp_path)
    ma.init()
    base = ma.store.count()
    key_path = str(ma.state_dir / "key.sealed")
    n = 8
    # A worker that dies before the barrier breaks it, so the survivors raise
    # BrokenBarrierError promptly instead of blocking until the join timeout.
    barrier = mp.Barrier(n, timeout=30)
    procs = [
        mp.Process(target=_record_worker,
                   args=(str(ma.memory_dir), key_path, b"pw", f"note{i}.md", f"c{i}", barrier))
        for i in range(n)
    ]
    try:
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=60)
        for i, p in enumerate(procs):
            assert p.exitcode == 0, f"worker {i} exited with {p.exitcode}"  # no crash, no hang
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()  # never leave a stuck worker orphaned

    reader = MemAttest(ma.memory_dir, keystore=FileKeyStore(Path(key_path), b"pw"))
    assert reader.store.count() == base + n  # every write landed, none dropped
    report = reader.verify()
    assert report.ok and report.exit_code == 0, report.problems  # tree-head chain stayed consistent
