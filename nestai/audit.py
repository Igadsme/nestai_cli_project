"""
Audit logging system for NestAI.

- Tracks all prompts, final prompts, red/blue results, code paths, and simulation.
- Stores history in ~/.nestai/history
- Supports individual vs enterprise mode
    * Individual users can modify or delete history
    * Enterprise developer users cannot modify/delete history
    * Enterprise admin can modify/delete
- Provides hash-chain tamper detection in enterprise mode
"""

from __future__ import annotations

import json
import os
import hashlib
import time
from pathlib import Path
from typing import Any, Dict, Optional

# ============================================================
# CONSTANT PATHS
# ============================================================

CONFIG_PATH = Path.home() / ".nestai" / "config.json"
HISTORY_ROOT = Path.home() / ".nestai" / "history"


# ============================================================
# CUSTOM ERRORS
# ============================================================

class AuditTamperError(Exception):
    """Raised when history integrity is violated in enterprise mode."""


class AuditPermissionError(Exception):
    """Raised when a user tries to modify history without permission."""


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _ensure_dirs() -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    HISTORY_ROOT.mkdir(parents=True, exist_ok=True)


def _load_config() -> Dict[str, Any]:
    """
    Loads config file. If missing, defaults to individual mode.
    Possible modes:
        - individual
        - enterprise_dev
        - enterprise_admin
    """
    _ensure_dirs()

    if not CONFIG_PATH.exists():
        config = {"mode": "individual"}
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        return config

    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


# PUBLIC WRAPPER (needed for history_cli)
def load_config() -> Dict[str, Any]:
    return _load_config()


def _save_config(cfg: Dict[str, Any]) -> None:
    _ensure_dirs()
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


def _compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _get_latest_hash() -> Optional[str]:
    entries = sorted(HISTORY_ROOT.glob("*.json"))
    if not entries:
        return None
    with open(entries[-1], "r") as f:
        obj = json.load(f)
    return obj.get("entry_hash")


# ============================================================
# PUBLIC API
# ============================================================

def append_history_entry(
    *,
    original_prompt: str,
    final_prompt: Optional[str],
    controller_result: Dict[str, Any],
    red_team_results: Any,
    blue_team_results: Any,
    code_path: Optional[str] = None
) -> None:
    """
    Saves a new history entry. Hash-chains entries in enterprise mode.
    """

    _ensure_dirs()
    cfg = _load_config()
    mode = cfg.get("mode", "individual")

    timestamp = int(time.time())
    prev_hash = _get_latest_hash() if mode.startswith("enterprise") else None

    entry = {
        "timestamp": timestamp,
        "original_prompt": original_prompt,
        "final_prompt": final_prompt,
        "controller": controller_result,
        "red_team": red_team_results,
        "blue_team": blue_team_results,
        "code_path": code_path,
        "previous_hash": prev_hash,
    }

    serialized = json.dumps(entry, sort_keys=True)
    entry_hash = _compute_hash(serialized)
    entry["entry_hash"] = entry_hash

    filename = HISTORY_ROOT / f"history_{timestamp}_{entry_hash[:6]}.json"
    with open(filename, "w") as f:
        json.dump(entry, f, indent=2)


def list_history_entries() -> list[Path]:
    _ensure_dirs()
    return sorted(HISTORY_ROOT.glob("*.json"))


def load_history_entry(index: int) -> Dict[str, Any]:
    files = list_history_entries()
    if index < 1 or index > len(files):
        raise IndexError("History entry does not exist.")

    fp = files[index - 1]
    with open(fp, "r") as f:
        return json.load(f)


def search_history(keyword: str) -> list[tuple[int, Path]]:
    """
    Returns list of (index, file_path) matching keyword.
    """
    matches = []
    files = list_history_entries()

    for i, fp in enumerate(files, start=1):
        with open(fp, "r") as f:
            data = f.read().lower()
        if keyword.lower() in data:
            matches.append((i, fp))
    return matches


def enforce_edit_permissions() -> None:
    """
    Ensures delete/edit operations follow enterprise rules.
    """
    cfg = _load_config()
    mode = cfg.get("mode", "individual")

    if mode == "individual":
        return

    if mode == "enterprise_dev":
        raise AuditPermissionError("Enterprise developers cannot modify or delete history.")

    if mode == "enterprise_admin":
        return


def delete_history_entry(index: int) -> None:
    enforce_edit_permissions()

    files = list_history_entries()
    if index < 1 or index > len(files):
        raise IndexError("History entry does not exist.")

    fp = files[index - 1]
    fp.unlink()


def verify_integrity_chain() -> None:
    """
    In enterprise mode only: verify hash-chain for tamper detection.
    """
    cfg = _load_config()
    if cfg.get("mode") == "individual":
        return

    files = list_history_entries()
    previous_hash = None

    for fp in files:
        with open(fp, "r") as f:
            entry = json.load(f)

        if entry.get("previous_hash") != previous_hash:
            raise AuditTamperError(f"History tampering detected at: {fp.name}")

        serialized = json.dumps(
            {k: entry[k] for k in entry if k != "entry_hash"},
            sort_keys=True
        )
        if _compute_hash(serialized) != entry["entry_hash"]:
            raise AuditTamperError(f"Hash mismatch in: {fp.name}")

        previous_hash = entry["entry_hash"]
