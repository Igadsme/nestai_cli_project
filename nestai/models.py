# nestai/models.py
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List


# ================================================================
# JSON-SAFE CONVERSION
# ================================================================

def make_json_safe(obj: Any) -> Any:
    """
    Fully converts any nested object into JSON-serializable structures.

    Supports:
    - AgentResult
    - Dataclasses
    - dicts, lists, tuples
    - primitives (str/int/bool/None)
    Ensures NOTHING breaks downstream pipeline or CLI rendering.
    """

    if obj is None:
        return None

    if isinstance(obj, AgentResult):
        return obj.to_dict()

    if hasattr(obj, "__dataclass_fields__"):
        return {k: make_json_safe(v) for k, v in obj.__dict__.items()}

    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [make_json_safe(x) for x in obj]

    if isinstance(obj, (str, int, float, bool)):
        return obj

    return repr(obj)


# ================================================================
# HACKATHON "LLM" — Stable, deterministic, detailed
# ================================================================

def call_json_model(system_prompt: str, user_prompt: str) -> Dict[str, Any]:
    """
    Deterministic local model simulator.
    It ALWAYS returns valid JSON with realistic, industry-grade
    security findings based on keyword heuristics.

    This keeps your pipeline:
    - Stable offline
    - Fast
    - Hackathon-ready
    - Professional and believable
    """

    sp = (system_prompt.lower() + " " + user_prompt.lower())

    risks = []
    constraints = []
    notes = []

    # ---------------------------
    # Authentication-related risks
    # ---------------------------
    if "login" in sp or "auth" in sp:
        risks.append(
            "Potential weaknesses in authentication workflows. "
            "Ensure MFA enforcement, rate limiting, credential lockout, "
            "secure password hashing (Argon2/bcrypt), and session integrity "
            "per OWASP ASVS 2.1/2.2."
        )
        constraints.append("Enforce MFA and strong password policy.")
        constraints.append("Implement lockout after repeated failures.")
        notes.append("Authentication workflows require defense-in-depth controls.")

    # ---------------------------
    # Injection & validation
    # ---------------------------
    if "sql" in sp or "input" in sp or "query" in sp:
        risks.append(
            "Potential injection vectors detected. Inputs must be sanitized, "
            "validated, and parameterized (OWASP A03:2021 Injection)."
        )
        constraints.append("Use parameterized queries only.")
        constraints.append("Apply strict input validation and sanitization.")
        notes.append("Apply defense-in-depth to prevent command/SQL injection.")

    # ---------------------------
    # Cryptography & data handling
    # ---------------------------
    if "token" in sp or "crypto" in sp or "jwt" in sp:
        risks.append(
            "Cryptographic material handling may be insufficient. "
            "Keys must be rotated, stored securely, and algorithms must meet "
            "NIST SP 800-57 recommendations."
        )
        constraints.append("Rotate secrets and store them in a secure vault.")
        constraints.append("Avoid weak hashing algorithms; prefer Argon2id.")
        notes.append("Verify token expiry and integrity protection.")

    # ---------------------------
    # API exposure & endpoints
    # ---------------------------
    if "api" in sp or "endpoint" in sp:
        risks.append(
            "Exposed API surfaces require robust access control, "
            "rate limiting, and logging per OWASP API Top 10."
        )
        constraints.append("Enforce RBAC/ABAC on all endpoints.")
        constraints.append("Add rate limiting and audit logging.")
        notes.append("Review endpoint security posture holistically.")

    # If nothing detected, add a default professional note
    if not risks:
        risks.append(
            "No explicit high-risk indicators detected, but baseline review "
            "suggests verifying input validation, authentication state "
            "management, and dependency hardening."
        )

    # Severity heuristic
    severity = "medium"
    if len(risks) >= 3:
        severity = "high"
    if len(risks) >= 5:
        severity = "critical"

    return make_json_safe({
        "agent_name": "local_reasoner",
        "severity": severity,
        "risks": risks,
        "suggested_constraints": constraints,
        "notes": " ".join(notes) if notes else "",
        "model_simulated": True,
    })


# ================================================================
# AGENT RESULT – Canonical response object
# ================================================================

@dataclass
class AgentResult:
    """
    Canonical structure used across the entire multi-agent system.
    Every agent returns AgentResult for consistency.
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
            "parsed": make_json_safe(self.parsed),
        }

    @classmethod
    def from_raw_dict(cls, data: Dict[str, Any]) -> "AgentResult":
        parsed = make_json_safe(data.get("parsed", {}))
        raw_str = data.get("raw", json.dumps(parsed, indent=2))

        return cls(
            name=data.get("name", "unknown"),
            role=data.get("role", "unknown"),
            raw=raw_str,
            parsed=parsed,
        )
