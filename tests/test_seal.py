import pytest

from memattest.identity import Identity, KeyStore
from memattest.seal import SthChain, build_sth, verify_sth
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


def make_identity():
    return Identity.generate(MemoryKeyStore(), "k")


def test_sth_sign_and_verify():
    ident = make_identity()
    sth = build_sth(3, b"\xaa" * 32, ident, timestamp="2026-07-06T00:00:00Z")
    assert sth["tree_size"] == 3
    assert sth["root_hash"] == "aa" * 32
    assert verify_sth(sth, ident.public_key_bytes)


def test_sth_rejects_any_field_change():
    ident = make_identity()
    sth = build_sth(3, b"\xaa" * 32, ident)
    for field, bad in [("tree_size", 4), ("root_hash", "bb" * 32), ("timestamp", "2000-01-01T00:00:00Z")]:
        forged = dict(sth, **{field: bad})
        assert not verify_sth(forged, ident.public_key_bytes)


def test_sth_rejects_wrong_key():
    sth = build_sth(1, b"\xaa" * 32, make_identity())
    other = make_identity()
    assert not verify_sth(sth, other.public_key_bytes)


def test_chain_append_and_load(tmp_path):
    ident = make_identity()
    chain = SthChain(tmp_path / ".memattest")
    assert chain.latest() is None
    a = build_sth(1, b"\x01" * 32, ident)
    b = build_sth(2, b"\x02" * 32, ident)
    chain.append(a)
    chain.append(b)
    assert chain.load_all() == [a, b]
    assert chain.latest() == b


def test_chain_append_never_overwrites(tmp_path):
    ident = make_identity()
    chain = SthChain(tmp_path / ".memattest")
    chain.append(build_sth(1, b"\x01" * 32, ident))
    # Simulate a second writer/count desync targeting the same slot:
    (tmp_path / ".memattest" / "sth" / "000002.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="append-only"):
        chain.append(build_sth(2, b"\x02" * 32, ident))


def test_verify_sth_malformed_returns_false():
    ident = make_identity()
    sth = build_sth(1, b"\xaa" * 32, ident)
    missing = {k: v for k, v in sth.items() if k != "signature"}
    assert not verify_sth(missing, ident.public_key_bytes)
    bad_hex = dict(sth, signature="zz-not-hex")
    assert not verify_sth(bad_hex, ident.public_key_bytes)
