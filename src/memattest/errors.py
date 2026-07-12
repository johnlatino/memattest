class MemAttestError(Exception):
    """Operational error (CLI exit code 2)."""


class KeyStoreError(MemAttestError):
    """The keystore could not seal/unseal the signing key."""


class KeyNotFoundError(KeyStoreError):
    """The backend keystore answered the lookup: nothing stored under that name.

    A statement about the key (evidence-grade), unlike its parent
    KeyStoreError, which covers the unreachable-backend-keystore case
    (operational).
    """
