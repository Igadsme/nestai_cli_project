# models.py
from __future__ import annotations

import json
import os
import re
from dataclasses import asdict
from typing import Any, Dict, List

from openai import OpenAI


# ======================================================================
# OpenAI Client
# ======================================================================

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# ======================================================================
# AgentResult (kept for compatibility, but Pipeline A uses pure dicts)
# ======================================================================

class AgentResult:
    """
    Legacy class. Pipeline A does NOT use it for agents, but some
    components may still call .to_dict() on them.
    """

    def __init__(
        self,
        agent_name: str,
        findings: List[str] = None,
        severity: str = None,
        parsed: Dict[str, Any] = None,
        raw: str = "",
        role: str = "",
    ):
        self.agent_name = agent_name
        self.findings = findings or []
        self.severity = severity
        self.parsed = parsed or {}
        self.raw = raw
        self.role = role

    @classmethod
    def from_raw_dict(cls, data: Dict[str, Any]) -> "AgentResult":
        return cls(
            agent_name=data.get("name", data.get("agent_name", "")),
            findings=data.get("findings", []),
            severity=(data.get("parsed") or {}).get("severity"),
            parsed=data.get("parsed", {}),
            raw=data.get("raw", ""),
            role=data.get("role", ""),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_name": self.agent_name,
            "findings": self.findings,
            "severity": self.severity,
            "parsed": self.parsed,
            "raw": self.raw,
            "role": self.role,
        }


# ======================================================================
# JSON-SAFE SERIALIZER
# ======================================================================

def make_json_safe(obj: Any) -> Any:
    """
    Recursively convert any Python object into JSON-safe structures.
    """
    if obj is None:
        return None

    # AgentResult → convert to clean dict
    if hasattr(obj, "to_dict"):
        try:
            return make_json_safe(obj.to_dict())
        except Exception:
            pass

    # Dataclass → convert
    try:
        if hasattr(obj, "__dataclass_fields__"):
            return make_json_safe(asdict(obj))
    except Exception:
        pass

    # Dict
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}

    # List / Tuple
    if isinstance(obj, (list, tuple)):
        return [make_json_safe(x) for x in obj]

    # JSON-safe primitives
    if isinstance(obj, (str, int, float, bool)):
        return obj

    # Fallback — convert to string
    return repr(obj)


# ======================================================================
# REAL AI CALL WITH JSON ENFORCEMENT
# ======================================================================

def _extract_json(text: str) -> Dict[str, Any]:
    """
    Extract valid JSON from possibly malformed model output.
    Auto-repairs common formatting issues.
    """

    # Try direct raw JSON
    try:
        return json.loads(text)
    except Exception:
        pass

    # Try extracting {...}
    try:
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if match:
            return json.loads(match.group(0))
    except Exception:
        pass

    # Replace invalid python literals
    repaired = (
        text.replace("None", "null")
            .replace("True", "true")
            .replace("False", "false")
    )

    try:
        return json.loads(repaired)
    except Exception:
        pass

    # Failed completely → return fallback safe JSON
    return {
        "agent_name": "unknown",
        "error": "Invalid JSON received from model",
        "raw_output": text,
    }


def call_json_model(system_prompt: str, user_prompt: str) -> Dict[str, Any]:
    """
    Execute a real OpenAI call to gpt-4.1-mini and enforce strict JSON-only output.
    """

    full_prompt = f"""
SYSTEM INSTRUCTIONS:
- You MUST ALWAYS return ONLY valid JSON.
- DO NOT return text outside JSON.
- DO NOT use markdown or code fences.
- Produce ONE SINGLE JSON object.

SYSTEM PROMPT:
{system_prompt}

USER INPUT:
{user_prompt}
"""

    try:
        response = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": full_prompt},
            ],
            temperature=0.2,
            max_tokens=1200,
        )

        content: str = response.choices[0].message.content.strip()
        return _extract_json(content)

    except Exception as e:
        # Return safe error JSON — do not crash the pipeline
        return {
            "agent_name": "error_agent",
            "error": str(e),
            "raw_output": "",
        }
