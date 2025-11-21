# nestai/audit.py
from __future__ import annotations

import json
import time
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------

APP_DIR = Path.home() / ".nestai"
HISTORY_DIR = APP_DIR / "history"
HISTORY_DIR.mkdir(parents=True, exist_ok=True)


# ----------------------------------------------------------------------------
# JSON-SAFE UTILITY
# ----------------------------------------------------------------------------

def _make_json_safe(obj: Any) -> Any:
    """Convert arbitrary nested Python objects to JSON-safe structures."""
    if obj is None:
        return None

    if isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, list):
        return [_make_json_safe(x) for x in obj]

    if isinstance(obj, dict):
        return {str(k): _make_json_safe(v) for k, v in obj.items()}

    if hasattr(obj, "to_dict"):
        try:
            return _make_json_safe(obj.to_dict())
        except Exception:
            pass

    try:
        # dataclass
        if hasattr(obj, "__dataclass_fields__"):
            from dataclasses import asdict
            return _make_json_safe(asdict(obj))
    except Exception:
        pass

    # fallback
    return repr(obj)


# ----------------------------------------------------------------------------
# WRITE HISTORY ENTRY
# ----------------------------------------------------------------------------

def save_history_entry(data: Dict[str, Any]) -> Path:
    """
    Save one pipeline result to a uniquely-named JSON file.
    Returns path to the saved file.
    """

    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    ts = int(time.time())
    filename = f"history_{ts}.json"
    path = HISTORY_DIR / filename

    safe = _make_json_safe(data)
    path.write_text(json.dumps(safe, indent=2), encoding="utf-8")

    return path


# ----------------------------------------------------------------------------
# LIST HISTORY ENTRIES
# ----------------------------------------------------------------------------

def list_history_entries() -> List[Dict[str, Any]]:
    """
    Returns metadata for all history files.
    DOES NOT load full results — just metadata for listing.
    """

    entries = []

    if not HISTORY_DIR.exists():
        return entries

    for file in sorted(HISTORY_DIR.glob("history_*.json"), reverse=True):
        try:
            content = json.loads(file.read_text(encoding="utf-8"))
            entries.append({
                "id": file.stem.replace("history_", ""),
                "file": str(file),
                "timestamp": content.get("timestamp"),
                "original_prompt": content.get("original_prompt"),
                "final_prompt": content.get("final_prompt"),
                "risk": content.get("overall_risk"),
            })
        except Exception:
            continue

    return entries


# ----------------------------------------------------------------------------
# LOAD A SINGLE HISTORY ENTRY
# ----------------------------------------------------------------------------

def load_history_entry(entry_id: str) -> Optional[Dict[str, Any]]:
    """
    Load one saved history entry by its ID.
    """

    file_path = HISTORY_DIR / f"history_{entry_id}.json"
    if not file_path.exists():
        return None

    try:
        return json.loads(file_path.read_text(encoding="utf-8"))
    except Exception:
        return None
