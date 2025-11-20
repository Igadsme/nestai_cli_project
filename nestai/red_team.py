# nestai/red_team.py
from __future__ import annotations

import json
from typing import Any, Dict, List

from nestai.models import AgentResult, call_json_model


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _contains_any(text: str, needles: List[str]) -> bool:
    t = text.lower()
    return any(n.lower() in t for n in needles)


def _base_parsed(name: str) -> Dict[str, Any]:
    return {
        "agent_name": name,
        "severity": "low",
        "risks": [],
        "suggested_constraints": [],
        "notes": "",
    }


def _ui_enhance(parsed: Dict[str, Any], name: str) -> Dict[str, Any]:
    """Attach CLI UI helpers."""
    severity = parsed.get("severity", "medium").lower()

    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bright_red",
    }

    parsed["severity_color"] = color_map.get(severity, "yellow")
    parsed["short_summary"] = f"{name.upper()} Risk: {severity.upper()}"
    parsed["badge"] = "RED"
    return parsed


# ---------------------------------------------------------------------------
# Individual red-team heuristics
#   (medium-detail, deterministic, JSON-friendly)
# ---------------------------------------------------------------------------

def _analyze_auth(user_prompt: str) -> Dict[str, Any]:
    parsed = _base_parsed("auth_red")

    risks: List[str] = []
    constraints: List[str] = []

    if _contains_any(user_prompt, ["password", "login", "auth"]):
        if not _contains_any(user_prompt, ["hash", "hashed", "bcrypt", "argon2"]):
            risks.append("Passwords may be stored or compared in plaintext.")
            constraints.append("Use a strong password hashing algorithm (bcrypt or argon2).")

        if not _contains_any(user_prompt, ["mfa", "2fa", "multi-factor"]):
            risks.append("No multi-factor authentication requirement is described.")
            constraints.append("Add optional MFA/2FA for high-risk accounts.")

        if _contains_any(user_prompt, ["debug", "stack trace", "traceback"]):
            risks.append("Authentication errors may leak stack traces or debug messages.")
            constraints.append("Return generic error messages without exposing internals.")

    if not risks:
        parsed["severity"] = "low"
        parsed["notes"] = "No major authentication issues detected from the prompt."
    else:
        parsed["severity"] = "medium"
        parsed["risks"] = risks
        parsed["suggested_constraints"] = constraints

    return parsed


def _analyze_rbac(user_prompt: str) -> Dict[str, Any]:
    parsed = _base_parsed("rbac_red")
    risks: List[str] = []
    constraints: List[str] = []

    if _contains_any(user_prompt, ["admin", "role", "permission"]):
        if not _contains_any(user_prompt, ["role-based", "rbac", "permissions"]):
            risks.append("Roles are mentioned but no explicit RBAC model is defined.")
            constraints.append("Design explicit roles and permissions for sensitive operations.")
    else:
        risks.append("Prompt does not describe authorization or access control.")
        constraints.append("Introduce RBAC with least-privilege defaults.")

    parsed["severity"] = "medium"
    parsed["risks"] = risks
    parsed["suggested_constraints"] = constraints
    return parsed


def _analyze_injection(user_prompt: str) -> Dict[str, Any]:
    parsed = _base_parsed("injection_red")
    risks: List[str] = []
    constraints: List[str] = []

    if _contains_any(user_prompt, ["sql", "database", "query", "mysql", "postgres"]):
        if not _contains_any(user_prompt, ["parameterized", "prepared statement", "orm"]):
            risks.append("Database access may be vulnerable to SQL injection.")
            constraints.append("Use parameterized queries or an ORM that avoids string concatenation.")

    if _contains_any(user_prompt, ["shell", "os.system", "subprocess", "command"]):
        risks.append("User input might be passed to system commands.")
        constraints.append("Avoid direct shell execution; if required, whitelist commands and arguments.")

    if risks:
        parsed["severity"] = "high"
    else:
        parsed["severity"] = "low"
        parsed["notes"] = "No obvious injection vectors described in the prompt."

    parsed["risks"] = risks
    parsed["suggested_constraints"] = constraints
    return parsed


def _analyze_crypto(user_prompt: str) -> Dict[str, Any]:
    parsed = _base_parsed("crypto_red")
    risks: List[str] = []
    constraints: List[str] = []

    if _contains_any(user_prompt, ["https", "ssl", "tls", "encryption"]):
        parsed["notes"] = "Prompt mentions encrypted transport, but implementation still must enforce HTTPS-only."
        constraints.append("Enforce HTTPS/TLS at the web server or framework level.")
    else:
        risks.append("No mention of HTTPS/TLS or secure transport.")
        constraints.append("Require HTTPS for all API endpoints and secure cookies for sessions.")

    if _contains_any(user_prompt, ["jwt", "token"]):
        if not _contains_any(user_prompt, ["expiry", "expiration", "rotate"]):
            risks.append("JWT or token usage without clear expiry/rotation semantics.")
            constraints.append("Use short-lived tokens with rotation and revocation support.")

    parsed["severity"] = "medium" if risks else "low"
    parsed["risks"] = risks
    parsed["suggested_constraints"] = constraints
    return parsed


def _analyze_logic(user_prompt: str) -> Dict[str, Any]:
    parsed = _base_parsed("logic_red")
    risks: List[str] = []
    constraints: List[str] = []

    if _contains_any(user_prompt, ["unlimited", "infinite", "no limit", "any number of times"]):
        risks.append("Business logic allows unlimited actions, which may enable brute-force or abuse.")
        constraints.append("Introduce sensible rate limits and lockout policies.")

    if _contains_any(user_prompt, ["debug endpoint", "test endpoint", "admin debug"]):
        risks.append("Debug or admin endpoints may be exposed in production.")
        constraints.append("Protect debug/admin endpoints behind strong authentication and environment flags.")

    parsed["severity"] = "medium" if risks else "low"
    parsed["risks"] = risks
    parsed["suggested_constraints"] = constraints
    return parsed


def _analyze_api(user_prompt: str) -> Dict[str, Any]:
    parsed = _base_parsed("api_red")
    risks: List[str] = []
    constraints: List[str] = []

    if _contains_any(user_prompt, ["api", "endpoint", "route"]):
        if not _contains_any(user_prompt, ["rate limit", "throttle", "429"]):
            risks.append("No explicit API rate limiting strategy is described.")
            constraints.append("Apply rate limits and IP-based throttling on authentication endpoints.")

        if not _contains_any(user_prompt, ["logging", "monitoring", "audit"]):
            risks.append("Security-relevant events (logins, failures) may not be logged.")
            constraints.append("Log authentication attempts and security events with correlation IDs.")

    parsed["severity"] = "medium" if risks else "low"
    parsed["risks"] = risks
    parsed["suggested_constraints"] = constraints
    return parsed


# ---------------------------------------------------------------------------
# Malicious-intent agent
# ---------------------------------------------------------------------------

def _analyze_malicious(user_prompt: str) -> Dict[str, Any]:
    """
    Very simple heuristic: if user explicitly asks to hack, bypass security, etc.,
    we flag as blocked. Otherwise we mark as allowed.
    """
    lower = user_prompt.lower()
    malicious_keywords = [
        "bypass security",
        "exploit",
        "hack into",
        "ddos",
        "ransomware",
        "steal data",
    ]

    blocked = any(k in lower for k in malicious_keywords)

    parsed: Dict[str, Any] = {
        "agent_name": "malicious_red",
        "malicious_agent_blocked": blocked,
        "reasons": [],
        "attack_ideas": [],
        "notes": "",
    }

    if blocked:
        parsed["reasons"].append("Prompt appears to request assistance with harmful or unauthorized activity.")
        parsed["block_message"] = "=== MALICIOUS INTENT DETECTED: Request will be blocked by NestAI. ==="
        parsed["severity"] = "critical"
    else:
        parsed["notes"] = "Prompt appears focused on defensive or neutral coding tasks."
        parsed["severity"] = "low"
        parsed["block_message"] = "No malicious intent detected."

    parsed = _ui_enhance(parsed, "malicious_red")
    return parsed


# ---------------------------------------------------------------------------
# RedTeam class (Architecture A)
# ---------------------------------------------------------------------------

class RedTeam:
    """
    Runs multiple red-team agents over the user prompt and returns AgentResult objects.
    """

    def run_security_agents(self, user_prompt: str) -> List[AgentResult]:
        agents_parsed: List[Dict[str, Any]] = []

        agents_parsed.append(_ui_enhance(_analyze_auth(user_prompt), "auth_red"))
        agents_parsed.append(_ui_enhance(_analyze_rbac(user_prompt), "rbac_red"))
        agents_parsed.append(_ui_enhance(_analyze_injection(user_prompt), "injection_red"))
        agents_parsed.append(_ui_enhance(_analyze_crypto(user_prompt), "crypto_red"))
        agents_parsed.append(_ui_enhance(_analyze_logic(user_prompt), "logic_red"))
        agents_parsed.append(_ui_enhance(_analyze_api(user_prompt), "api_red"))

        results: List[AgentResult] = []
        for parsed in agents_parsed:
            name = parsed.get("agent_name", "red_agent")
            result = AgentResult(
                name=name,
                role="red",
                raw=json.dumps(parsed, indent=2),
                parsed=parsed,
            )
            results.append(result)

        return results

    def run_malicious_agent(self, user_prompt: str) -> AgentResult:
        parsed = _analyze_malicious(user_prompt)
        result = AgentResult(
            name="malicious_red",
            role="malicious",
            raw=json.dumps(parsed, indent=2),
            parsed=parsed,
        )
        return result

    def run_all(self, user_prompt: str) -> List[AgentResult]:
        results = self.run_security_agents(user_prompt)
        results.append(self.run_malicious_agent(user_prompt))
        return results

