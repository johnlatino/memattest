class MemAttestError(Exception):
    """Operational error (CLI exit code 2)."""


class KeyStoreError(MemAttestError):
    """The keystore could not seal/unseal the signing key."""
