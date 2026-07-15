import pytest

from memattest.errors import MemAttestError
from memattest.per_log_config import CONFIG_VERSION, load_config, write_config


def test_write_then_load_roundtrip(tmp_path):
    write_config(tmp_path, "keyring")
    assert load_config(tmp_path) == {"config_version": CONFIG_VERSION, "keystore": "keyring"}


def test_absent_config_returns_none(tmp_path):
    assert load_config(tmp_path) is None


def test_unparseable_toml_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text("keystore = [unclosed", encoding="utf-8")
    with pytest.raises(MemAttestError, match="config.toml"):
        load_config(tmp_path)


def test_invalid_utf8_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_bytes(b"config_version = 1\nkeystore = \xff\xfe\n")
    with pytest.raises(MemAttestError, match="config.toml"):
        load_config(tmp_path)


def test_missing_keystore_key_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text("config_version = 1\n", encoding="utf-8")
    with pytest.raises(MemAttestError, match="missing the 'keystore' key"):
        load_config(tmp_path)


def test_unknown_key_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text(
        'config_version = 1\nkeystore = "keyring"\ncolor = "red"\n', encoding="utf-8")
    with pytest.raises(MemAttestError, match="unknown keys"):
        load_config(tmp_path)


def test_unknown_keystore_value_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text(
        'config_version = 1\nkeystore = "tpm"\n', encoding="utf-8")
    with pytest.raises(MemAttestError, match="unknown backend keystore"):
        load_config(tmp_path)


def test_unknown_config_version_is_operational_error(tmp_path):
    (tmp_path / "config.toml").write_text(
        'config_version = 99\nkeystore = "keyring"\n', encoding="utf-8")
    with pytest.raises(MemAttestError, match="newer memattest"):
        load_config(tmp_path)


def test_write_config_rejects_unknown_keystore_name(tmp_path):
    with pytest.raises(MemAttestError, match="unknown backend keystore"):
        write_config(tmp_path, "tpm")
    assert not (tmp_path / "config.toml").exists()
