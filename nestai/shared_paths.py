# nestai/shared_paths.py

from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List

import json
from dataclasses import asdict

# ─────────────────────────────────────────────
# SHARED CONSTANTS (NO CIRCULAR IMPORTS)
# ─────────────────────────────────────────────

APP_DIR = Path.home() / ".nestai"
GENERATED_DIR = APP_DIR / "generated"
REPORTS_DIR = APP_DIR / "reports"
LAST_RESULT_JSON = APP_DIR / "last_result.json"

def ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────
# SHARED JSON-SAFE SERIALIZER
# (copied from cli.py to avoid circular import)
# ─────────────────────────────────────────────

def make_json_safe(obj: Any) -> Any:
    if obj is None:
        return None

    # dataclasses
    try:
        if hasattr(obj, "__dataclass_fields__"):
            return make_json_safe(asdict(obj))
    except Exception:
        pass

    # dict
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}

    # list/tuple
    if isinstance(obj, (list, tuple)):
        return [make_json_safe(v) for v in obj]

    # primitives
    if isinstance(obj, (str, int, float, bool)):
        return obj

    # fallback
    return repr(obj)
