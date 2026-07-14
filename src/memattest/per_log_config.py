"""Per-log configuration stored at .memattest/config.toml (spec 2026-07-13).

Records choices made at init — today only the backend keystore — so later
invocations need no flags. Ships without cryptographic protection: the
signing-key cross-check makes every lie this file can tell fail-noisy
(spec 2026-07-13 §6); sealing arrives with the watch list.

Deliberately light: no heavy imports, safe anywhere in the CLI.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from .errors import MemAttestError

CONFIG_NAME = "config.toml"
CONFIG_VERSION = 1
KNOWN_KEYSTORES = ("keyring", "file")

_TEMPLATE = """\
# memattest per-log configuration
config_version = {version}
keystore = "{keystore}"
"""


def load_config(state_dir: Path) -> dict | None:
    """Return the parsed config, or None when the file is absent.

    Raises MemAttestError (operational, exit 2) naming the file for any
    defect: unparseable TOML, missing or unknown keys, an unknown backend
    keystore name, or an unknown config_version (refuse-to-guess, like the
    entry scheme).
    """
    path = Path(state_dir) / CONFIG_NAME
    if not path.exists():
        return None
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise MemAttestError(f"unreadable or invalid config {path}: {exc}") from exc
    version = data.get("config_version")
    if version != CONFIG_VERSION:
        raise MemAttestError(
            f"config {path} has config_version {version!r}; this memattest "
            f"understands only {CONFIG_VERSION} (config written by a newer memattest?)"
        )
    unknown = set(data) - {"config_version", "keystore"}
    if unknown:
        raise MemAttestError(f"config {path} has unknown keys: {sorted(unknown)}")
    keystore = data.get("keystore")
    if keystore not in KNOWN_KEYSTORES:
        raise MemAttestError(
            f"config {path} names unknown backend keystore {keystore!r}; "
            f"expected one of {list(KNOWN_KEYSTORES)}"
        )
    return data


def write_config(state_dir: Path, keystore: str) -> None:
    state_dir = Path(state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / CONFIG_NAME).write_text(
        _TEMPLATE.format(version=CONFIG_VERSION, keystore=keystore), encoding="utf-8"
    )
