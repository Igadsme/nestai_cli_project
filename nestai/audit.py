from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from nestai.models import make_json_safe

APP_DIR = Path.home() / ".nestai"
HISTORY_DIR = APP_DIR / "history"


def _ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)


def _compute_hash(data: Dict[str, Any]) -> str:
    payload = json.dumps(make_json_safe(data), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def append_history_entry(
    *,
    original_prompt: str,
    final_prompt: Optional[str],
    controller_result: Dict[str, Any],
    static_prompt_result: Dict[str, Any],
    red_team_results: List[Dict[str, Any]],
    blue_team_results: List[Dict[str, Any]],
    static_generated_result: Optional[Dict[str, Any]],
    attack_result: Optional[Dict[str, Any]],
    code_path: Optional[Union[str, Path]],
) -> Path:
    """
    Append a single pipeline run to history.

    "Tamper-evident" via a simple hash chain:
    - Each file stores its own hash and the previous file's hash.
    """
    _ensure_dirs()

    ts = time.strftime("%Y%m%d_%H%M%S")
    filename = f"history_{ts}.json"
    path = HISTORY_DIR / filename

    # Find last entry's hash
    history_files = sorted(HISTORY_DIR.glob("history_*.json"))
    prev_hash = None
    if history_files:
        last = history_files[-1]
        try:
            last_data = json.loads(last.read_text(encoding="utf-8"))
            prev_hash = last_data.get("self_hash")
        except Exception:
            prev_hash = None

    entry: Dict[str, Any] = {
        "timestamp": ts,
        "original_prompt": original_prompt,
        "final_prompt": final_prompt,
        "controller_result": controller_result,
        "static_prompt_result": static_prompt_result,
        "red_team_results": red_team_results,
        "blue_team_results": blue_team_results,
        "static_generated_result": static_generated_result,
        "attack_result": attack_result,
        "code_path": str(code_path) if code_path is not None else None,
        "prev_hash": prev_hash,
    }

    entry["self_hash"] = _compute_hash(entry)

    path.write_text(json.dumps(make_json_safe(entry), indent=2), encoding="utf-8")
    return path


def list_history_entries(limit: int = 50) -> List[Dict[str, Any]]:
    _ensure_dirs()
    entries: List[Dict[str, Any]] = []

    for idx, path in enumerate(sorted(HISTORY_DIR.glob("history_*.json"), reverse=True)):
        if idx >= limit:
            break
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        entries.append(
            {
                "id": path.stem.replace("history_", ""),
                "file": str(path),
                "timestamp": data.get("timestamp", ""),
                "original_prompt": data.get("original_prompt", ""),
                "final_prompt": data.get("final_prompt", ""),
                "risk": (data.get("controller_result") or {}).get("metadata", {}).get(
                    "static_overall_risk", ""
                ),
            }
        )
    return entries


def load_history_entry(entry_id: str) -> Optional[Dict[str, Any]]:
    _ensure_dirs()
    path = HISTORY_DIR / f"history_{entry_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
