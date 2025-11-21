from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from openai import OpenAI

# Single OpenAI client (uses OPENAI_API_KEY from environment)
client = OpenAI()


# ---------------------------------------------------------------------------
# JSON-safe helper
# ---------------------------------------------------------------------------

def make_json_safe(obj: Any) -> Any:
    """
    Recursively convert ANY Python object into JSON-serializable primitives.
    Used across CLI, audit, and pipeline.
    """
    if obj is None:
        return None

    if isinstance(obj, (str, int, float, bool)):
        return obj

    if isinstance(obj, list):
        return [make_json_safe(x) for x in obj]

    if isinstance(obj, dict):
        return {str(k): make_json_safe(v) for k, v in obj.items()}

    # Dataclass
    try:
        if hasattr(obj, "__dataclass_fields__"):
            return make_json_safe(asdict(obj))
    except Exception:
        pass

    # Custom agent with to_dict()
    if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        try:
            return make_json_safe(obj.to_dict())
        except Exception:
            pass

    # Fallback: string repr
    return repr(obj)


# ---------------------------------------------------------------------------
# Agent / Controller results
# ---------------------------------------------------------------------------

@dataclass
class AgentResult:
    """
    Unified structure for any agent (red, blue, static, attack, malicious).
    """
    name: str
    role: str
    raw: str
    parsed: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "raw": self.raw,
            "parsed": self.parsed,
        }

    @classmethod
    def from_parsed(cls, name: str, role: str, parsed: Dict[str, Any]) -> "AgentResult":
        return cls(
            name=name,
            role=role,
            raw=json.dumps(parsed, indent=2),
            parsed=parsed,
        )

    @classmethod
    def from_raw_dict(cls, data: Dict[str, Any]) -> "AgentResult":
        return cls(
            name=data.get("name", data.get("agent_name", "unknown")),
            role=data.get("role", "generic"),
            raw=data.get("raw", json.dumps(data.get("parsed", {}), indent=2)),
            parsed=data.get("parsed", {}),
        )


@dataclass
class ControllerResult:
    final_prompt: str
    blocked: bool
    reasons: List[str]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "final_prompt": self.final_prompt,
            "blocked": self.blocked,
            "reasons": self.reasons,
            "metadata": make_json_safe(self.metadata),
        }


# ---------------------------------------------------------------------------
# OpenAI JSON helper
# ---------------------------------------------------------------------------

def call_json_model(system_prompt: str, user_payload: Any) -> Dict[str, Any]:
    """
    Call OpenAI with strict JSON response_format.

    - system_prompt: full instructions, including JSON schema and rules
    - user_payload: str or dict; dict will be JSON-dumped for the user message

    Returns a parsed dict. If parsing fails, returns a fallback structure.
    """
    if not isinstance(user_payload, str):
        user_payload = json.dumps(user_payload, indent=2)

    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_payload},
        ],
        response_format={"type": "json_object"},
        temperature=0.1,
    )
    content = resp.choices[0].message.content or ""

    try:
        return json.loads(content)
    except Exception:
        # Try to salvage JSON substring
        try:
            start = content.index("{")
            end = content.rindex("}") + 1
            return json.loads(content[start:end])
        except Exception:
            return {
                "error": "non_json_response",
                "raw": content,
            }
