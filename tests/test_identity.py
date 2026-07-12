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


def test_file_keystore_corrupted_file_raises_keystoreerror(tmp_path):
    path = tmp_path / "key.sealed"
    path.write_text("{ not valid json", encoding="utf-8")
    ks = FileKeyStore(path, passphrase=b"pw")
    with pytest.raises(KeyStoreError):
        ks.unseal("k1")


def test_file_keystore_truncated_blob_raises_keystoreerror(tmp_path):
    import base64, json
    path = tmp_path / "key.sealed"
    path.write_text(json.dumps({"k1": base64.b64encode(b"short").decode("ascii")}), encoding="utf-8")
    ks = FileKeyStore(path, passphrase=b"pw")
    with pytest.raises(KeyStoreError):
        ks.unseal("k1")


def test_keyring_keystore_smoke():
    ks = KeyringKeyStore(service="memattest-test")
    try:
        ks.seal("smoke", b"\x02" * 32)
        assert ks.unseal("smoke") == b"\x02" * 32
    except KeyStoreError:
        pytest.skip("no functional OS keyring in this environment")


# --- KeyNotFoundError: "the backend keystore answered: no such key" ---------
# Verify (spec 2026-07-12) must distinguish a genuinely absent key
# (evidence-grade key-missing problem) from an unreachable backend keystore
# (operational error), so both backend keystores type their not-found case.


def test_keynotfounderror_is_a_keystoreerror():
    from memattest.errors import KeyNotFoundError
    assert issubclass(KeyNotFoundError, KeyStoreError)


def test_keyring_keystore_missing_key_raises_keynotfounderror(monkeypatch):
    import keyring
    from memattest.errors import KeyNotFoundError
    monkeypatch.setattr(keyring, "get_password", lambda service, name: None)
    with pytest.raises(KeyNotFoundError):
        KeyringKeyStore(service="memattest-test").unseal("absent")


def test_file_keystore_missing_file_raises_keynotfounderror(tmp_path):
    from memattest.errors import KeyNotFoundError
    ks = FileKeyStore(tmp_path / "no-such-file.sealed", passphrase=b"pw")
    with pytest.raises(KeyNotFoundError):
        ks.unseal("k1")


def test_file_keystore_absent_name_raises_keynotfounderror(tmp_path):
    from memattest.errors import KeyNotFoundError
    ks = FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw")
    ks.seal("k1", b"\x01" * 32)
    with pytest.raises(KeyNotFoundError):
        ks.unseal("other")


def test_file_keystore_wrong_passphrase_is_not_keynotfound(tmp_path):
    from memattest.errors import KeyNotFoundError
    FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw").seal("k1", b"\x01" * 32)
    with pytest.raises(KeyStoreError) as exc_info:
        FileKeyStore(tmp_path / "key.sealed", passphrase=b"wrong").unseal("k1")
    assert not isinstance(exc_info.value, KeyNotFoundError)


# --- invalid seed material must not escape as a raw ValueError --------------
# A sealed value that unseals cleanly but is the wrong length for an Ed25519
# seed used to reach Ed25519PrivateKey.from_private_bytes() unguarded, which
# raises plain ValueError -- invisible to callers that only catch
# KeyStoreError (e.g. the verify cross-check and the SessionStart hook).


def test_load_wrong_length_seed_raises_keystoreerror_not_valueerror():
    ks = MemoryKeyStore()
    ks.seal("k1", b"\x01" * 16)  # Ed25519 seeds are 32 bytes
    with pytest.raises(KeyStoreError):
        Identity.load(ks, "k1")


def test_file_keystore_wrong_length_seed_raises_keystoreerror(tmp_path):
    ks = FileKeyStore(tmp_path / "key.sealed", passphrase=b"pw")
    ks.seal("k1", b"\x01" * 16)
    with pytest.raises(KeyStoreError):
        Identity.load(ks, "k1")


def test_keyring_bad_base64_raises_keystoreerror_not_binascii_error(monkeypatch):
    import keyring
    monkeypatch.setattr(keyring, "get_password", lambda service, name: "%%%not-base64%%%")
    with pytest.raises(KeyStoreError):
        KeyringKeyStore(service="memattest-test").unseal("whatever")
