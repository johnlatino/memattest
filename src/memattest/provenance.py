"""Provenance claim providers. Third parties extend via entry-point group 'memattest.providers'.

A provider is a zero-argument callable returning a dict of claims; its claims
appear under the entry-point name. Example third-party provider (spec §5): a
git workspace provider returning {"repo": ..., "branch": ..., "head": ...}.
"""
import getpass
import os
import platform
import socket
import sys
import uuid
from importlib.metadata import entry_points

import psutil

ENTRY_POINT_GROUP = "memattest.providers"


def agent_claims() -> dict:
    return {
        "harness": os.environ.get("MEMATTEST_HARNESS", "unknown"),
        "version": os.environ.get("MEMATTEST_HARNESS_VERSION", "unknown"),
    }


def process_claims() -> dict:
    proc = psutil.Process()
    return {
        "pid": proc.pid,
        "exe": proc.exe(),
        "parent_chain": [p.name() for p in proc.parents()[:5]],
    }


def _machine_id() -> str:
    if platform.system() == "Linux":
        for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                with open(path, encoding="ascii") as f:
                    return f.read().strip()
            except OSError:
                continue
    if platform.system() == "Windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as k:
                return winreg.QueryValueEx(k, "MachineGuid")[0]
        except OSError:
            pass
    return f"mac:{uuid.getnode():012x}"  # last-resort fallback


def machine_claims() -> dict:
    return {"hostname": socket.gethostname(), "machine_id": _machine_id(), "platform": platform.system()}


def session_claims() -> dict:
    return {
        "user": getpass.getuser(),
        "session_id": os.environ.get("CLAUDE_SESSION_ID"),
        "interactive_tty": sys.stdin.isatty(),
    }


def _entry_point_providers():
    return list(entry_points(group=ENTRY_POINT_GROUP))


def collect(extra: dict | None = None) -> dict:
    claims = {
        "agent": agent_claims(),
        "process": process_claims(),
        "machine": machine_claims(),
        "session": session_claims(),
    }
    for ep in _entry_point_providers():
        try:
            claims[ep.name] = ep.load()()
        except Exception as exc:
            claims[ep.name] = {"error": str(exc)}
    if extra:
        claims.update(extra)
    return claims
