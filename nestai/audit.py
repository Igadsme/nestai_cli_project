# nestai/audit.py
from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime
from typing import Any, Dict

from nestai.models import make_json_safe

AUDIT_DIR = Path.home() / ".nestai" / "audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)


def append_history_entry(**kwargs: Any):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = AUDIT_DIR / f"audit_{ts}.json"
    safe = make_json_safe(kwargs)
    path.write_text(json.dumps(safe, indent=2))
    return path
