import pytest

from memattest.errors import KeyStoreError
from memattest.identity import FileKeyStore, Identity, KeyringKeyStore, KeyStore, verify_signature


class MemoryKeyStore(KeyStore):
    def __init__(self):
        self.data = {}

    def seal(self, name, secret):
        self.data[name] = secret

    def unseal(self, name):
        if name not in self.data:
            raise KeyStoreError(f"no key named {name!r}")
        return self.data[name]


def test_generate_sign_verify_roundtrip():
    ks = MemoryKeyStore()
    ident = Identity.generate(ks, "k1")
    sig = ident.sign(b"payload")
    assert verify_signature(ident.public_key_bytes, b"payload", sig)
    assert not verify_signature(ident.public_key_bytes, b"tampered", sig)


def test_load_restores_same_key():
    ks = MemoryKeyStore()
    a = Identity.generate(ks, "k1")
    b = Identity.load(ks, "k1")
    assert a.public_key_bytes == b.public_key_bytes
    assert verify_signature(a.public_key_bytes, b"x", b.sign(b"x"))


def test_load_missing_key_raises():
    with pytest.raises(KeyStoreError):
        Identity.load(MemoryKeyStore(), "absent")


def test_file_keystore_roundtrip(tmp_path):
    ks = FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw")
    ks.seal("k1", b"\x01" * 32)
    assert ks.unseal("k1") == b"\x01" * 32


def test_file_keystore_wrong_passphrase(tmp_path):
    FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw").seal("k1", b"\x01" * 32)
    with pytest.raises(KeyStoreError):
        FileKeyStore(tmp_path / "key.sealed", passphrase=b"wrong").unseal("k1")


def test_keyring_keystore_smoke():
    ks = KeyringKeyStore(service="memattest-test")
    try:
        ks.seal("smoke", b"\x02" * 32)
        assert ks.unseal("smoke") == b"\x02" * 32
    except KeyStoreError:
        pytest.skip("no functional OS keyring in this environment")
