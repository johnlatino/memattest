import base64
import binascii
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .errors import KeyNotFoundError, KeyStoreError


class KeyStore(ABC):
    """seal/unseal named secrets. Backends decide where and how they are protected."""

    @abstractmethod
    def seal(self, name: str, secret: bytes) -> None: ...

    @abstractmethod
    def unseal(self, name: str) -> bytes: ...


class KeyringKeyStore(KeyStore):
    """OS keystore via `keyring`: DPAPI (Windows), Secret Service (Linux), Keychain (macOS)."""

    def __init__(self, service: str = "memattest"):
        self.service = service

    def seal(self, name: str, secret: bytes) -> None:
        import keyring
        try:
            keyring.set_password(self.service, name, base64.b64encode(secret).decode("ascii"))
        except Exception as exc:  # keyring backends raise assorted types
            raise KeyStoreError(f"keyring seal failed: {exc}") from exc

    def unseal(self, name: str) -> bytes:
        import keyring
        try:
            value = keyring.get_password(self.service, name)
        except Exception as exc:
            raise KeyStoreError(f"keyring unseal failed: {exc}") from exc
        if value is None:
            raise KeyNotFoundError(f"no key named {name!r} in keyring service {self.service!r}")
        try:
            return base64.b64decode(value)
        except binascii.Error as exc:
            raise KeyStoreError(f"keyring unseal failed: {exc}") from exc


class FileKeyStore(KeyStore):
    """Encrypted-file fallback for headless hosts: scrypt KDF + AES-256-GCM, 0600 perms."""

    def __init__(self, path: Path, passphrase: bytes):
        self.path = Path(path)
        self.passphrase = passphrase

    def _derive(self, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(self.passphrase)

    def _load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise KeyStoreError(f"unreadable or corrupted key file {self.path}: {exc}") from exc

    def seal(self, name: str, secret: bytes) -> None:
        blobs = self._load()
        salt, nonce = os.urandom(16), os.urandom(12)
        ct = AESGCM(self._derive(salt)).encrypt(nonce, secret, None)
        blobs[name] = base64.b64encode(salt + nonce + ct).decode("ascii")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.write_text(json.dumps(blobs), encoding="utf-8")
        except OSError as exc:
            raise KeyStoreError(f"cannot write key file {self.path}: {exc}") from exc
        if os.name == "posix":
            os.chmod(self.path, 0o600)

    def unseal(self, name: str) -> bytes:
        blobs = self._load()
        if name not in blobs:
            raise KeyNotFoundError(f"no key named {name!r} in {self.path}")
        try:
            raw = base64.b64decode(blobs[name])
        except binascii.Error as exc:
            raise KeyStoreError(f"corrupted key blob for {name!r} in {self.path}") from exc
        if len(raw) < 29:  # 16 salt + 12 nonce + at least 1 ciphertext byte
            raise KeyStoreError(f"corrupted key blob for {name!r} in {self.path}")
        salt, nonce, ct = raw[:16], raw[16:28], raw[28:]
        try:
            return AESGCM(self._derive(salt)).decrypt(nonce, ct, None)
        except InvalidTag as exc:
            raise KeyStoreError("wrong passphrase or corrupted key file") from exc


class Identity:
    """Per-installation Ed25519 keypair. The keypair IS the agent identity (spec §6)."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private = private_key
        self.public_key_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, data: bytes) -> bytes:
        return self._private.sign(data)

    @classmethod
    def generate(cls, keystore: KeyStore, name: str) -> "Identity":
        private = Ed25519PrivateKey.generate()
        seed = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        keystore.seal(name, seed)
        return cls(private)

    @classmethod
    def load(cls, keystore: KeyStore, name: str) -> "Identity":
        seed = keystore.unseal(name)
        try:
            private = Ed25519PrivateKey.from_private_bytes(seed)
        except ValueError as exc:
            raise KeyStoreError(f"sealed value is not a valid Ed25519 seed: {exc}") from exc
        return cls(private)


def verify_signature(public_key_bytes: bytes, data: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, data)
        return True
    except InvalidSignature:
        return False
