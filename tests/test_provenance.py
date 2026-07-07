import os
import sys

from memattest import provenance


def test_process_claims_shape():
    c = provenance.process_claims()
    assert c["pid"] == os.getpid()
    assert isinstance(c["exe"], str) and c["exe"]
    assert isinstance(c["parent_chain"], list)


def test_machine_claims_shape():
    c = provenance.machine_claims()
    assert isinstance(c["hostname"], str) and c["hostname"]
    assert isinstance(c["machine_id"], str) and c["machine_id"]


def test_session_claims_shape():
    c = provenance.session_claims()
    assert isinstance(c["user"], str)
    assert isinstance(c["interactive_tty"], bool)


def test_agent_claims_reads_env(monkeypatch):
    monkeypatch.setenv("MEMATTEST_HARNESS", "claude-code")
    monkeypatch.setenv("MEMATTEST_HARNESS_VERSION", "9.9")
    assert provenance.agent_claims() == {"harness": "claude-code", "version": "9.9"}


def test_collect_merges_builtins_and_extra():
    claims = provenance.collect(extra={"custom": {"k": 1}})
    for key in ("agent", "process", "machine", "session", "custom"):
        assert key in claims


def test_collect_survives_broken_provider(monkeypatch):
    class BrokenEP:
        name = "broken"

        def load(self):
            def boom():
                raise RuntimeError("provider exploded")
            return boom

    monkeypatch.setattr(provenance, "_entry_point_providers", lambda: [BrokenEP()])
    claims = provenance.collect()
    assert claims["broken"] == {"error": "provider exploded"}
