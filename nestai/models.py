# nestai/models.py
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List


# =====================================================================
# JSON-SAFE CONVERSION (GLOBAL, CONSISTENT, NEVER FAILS)
# =====================================================================

def make_json_safe(obj: Any) -> Any:
    """
    Recursively converts ANY Python object into JSON-serializable form.

    Supported:
    - AgentResult objects
    - Dataclasses
    - dicts, lists, tuples
    - primitives (str, int, float, bool, None)

    Fallback:
    - repr(obj)
    """

    if obj is None:
        return None

    # Standard AgentResult
    if isinstance(obj, AgentResult):
        return obj.to_dict()

    # Dataclass
    if hasattr(obj, "__dataclass_fields__"):
        return {k: make_json_safe(v) for k, v in obj.__dict__.items()}

    # Dict
    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}

    # List / tuple
    if isinstance(obj, (list, tuple)):
        return [make_json_safe(x) for x in obj]

    # Primitive JSON-safe types
    if isinstance(obj, (str, int, float, bool)):
        return obj

    # Unknown type — give safe fallback
    return repr(obj)


# =====================================================================
# LOCAL FAKE MODEL FOR NON-CODEGEN AGENTS (Static / Red / Blue / Attack)
# =====================================================================

def call_json_model(system_prompt: str, user_prompt: str) -> Dict[str, Any]:
    """
    Local deterministic simulation of an LLM for:
    - Red Team Agents
    - Blue Team Agents
    - Static Analysis Agent
    - Attack Simulation Agent

    This is used everywhere EXCEPT codegen (which uses gpt-4.1-mini).
    It ALWAYS returns a valid JSON dictionary and NEVER crashes.

    Output includes:
      - detailed OWASP / MITRE style risks
      - suggested constraints
      - notes
      - severity auto-evaluated
    """

    sp = (system_prompt.lower() + " " + user_prompt.lower())

    risks = []
    constraints = []
    notes = []

    # -------------------------
    # KEYWORD-BASED RISK HEURISTICS
    # -------------------------

    if "auth" in sp or "login" in sp or "password" in sp:
        risks.append(
            "Authentication surface may expose weaknesses (OWASP ASVS 2.x). "
            "Review MFA enforcement, credential lifecycle, session fixation protection."
        )
        constraints.append("Enforce MFA for all authentication workflows.")
        constraints.append("Use Argon2id or bcrypt for password hashing.")
        notes.append("Authentication posture requires layered defense.")

    if "sql" in sp or "db" in sp or "query" in sp:
        risks.append(
            "Potential SQL injection surface detected. "
            "Ensure strict parameterization and input sanitation (OWASP A03)."
        )
        constraints.append("Use prepared statements only.")
        constraints.append("Reject unvalidated user input aggressively.")
        notes.append("SAST tools should run continuously for injection detection.")

    if "api" in sp or "endpoint" in sp:
        risks.append(
            "API exposure detected. Validate schemas strictly, enforce RBAC/ABAC, "
            "and apply rate limiting (OWASP API Security Top 10)."
        )
        constraints.append("Enable endpoint-level access control checks.")
        constraints.append("Log and monitor all access control failures.")

    if "token" in sp or "jwt" in sp or "crypto" in sp:
        risks.append(
            "Cryptographic handling may be insufficient. Check signing algorithms, "
            "token expiry, integrity protection, and secret rotation (NIST 800-57)."
        )
        constraints.append("Rotate secrets through a hardened vault.")
        constraints.append("Use high-entropy signing keys (≥ 256 bits).")

    # fallback generic risk
    if not risks:
        risks.append(
            "Baseline review indicates the need for improved input normalization, "
            "error handling, secure defaults, and dependency scanning."
        )

    # -------------------------
    # SEVERITY HEURISTICS
    # -------------------------
    severity = "medium"
    if len(risks) >= 3:
        severity = "high"
    if len(risks) >= 5:
        severity = "critical"

    full_notes = " ".join(notes) if notes else ""

    return make_json_safe({
        "agent_name": "local_reasoner",
        "severity": severity,
        "risks": risks,
        "suggested_constraints": constraints,
        "notes": full_notes,
        "model_simulated": True,
    })


# =====================================================================
# CANONICAL AGENT RESULT CLASS
# =====================================================================

@dataclass
class AgentResult:
    """
    Canonical multi-agent result object.

    Required fields across all agents:
    - name (red_auth, blue_1, static_analysis_generated, attack_simulation, etc.)
    - role ("red", "blue", "static", "attack", "malicious")
    - raw (raw JSON string)
    - parsed (Python dict with detailed findings)
    """

    name: str
    role: str
    raw: str
    parsed: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """
        JSON-safe representation of this agent.
        """
        return {
            "name": self.name,
            "role": self.role,
            "raw": self.raw,
            "parsed": make_json_safe(self.parsed),
        }

    @classmethod
    def from_raw_dict(cls, data: Dict[str, Any]) -> "AgentResult":
        """Factory that safely constructs AgentResult from dict."""
        parsed = make_json_safe(data.get("parsed", {}))

        # raw fallback
        raw_str = data.get("raw")
        if raw_str is None:
            try:
                raw_str = json.dumps(parsed, indent=2)
            except Exception:
                raw_str = str(parsed)

        return cls(
            name=data.get("name", "unknown_agent"),
            role=data.get("role", "unknown"),
            raw=raw_str,
            parsed=parsed,
        )
