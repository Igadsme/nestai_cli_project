# nestai/attack_simulation.py
from __future__ import annotations

import json
from typing import Any, Dict

from nestai.models import AgentResult, call_json_model


ATTACK_SIM_SYSTEM_PROMPT = """
You are the Attack Simulation Agent.

You conceptually simulate how an attacker might abuse the generated code.
You DO NOT provide exploit code, only high-level descriptions of risk.

Return ONLY valid JSON with this shape:

{
  "agent_name": "attack_simulation",
  "simulated_attacks": ["string"],
  "weak_points": ["string"],
  "severity": "low|medium|high|critical",
  "notes": "optional"
}
"""


def _ui_enhance(parsed: Dict[str, Any]) -> Dict[str, Any]:
    sev = parsed.get("severity", "low").lower()
    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bright_red",
    }
    parsed["severity_color"] = color_map.get(sev, "yellow")
    parsed["short_summary"] = f"Attack Simulation: {sev.upper()} RISK"
    parsed["badge"] = "ATTACK"
    return parsed


class AttackSimulationAgent:
    """
    Conceptual threat-modelling agent for the generated code.
    """

    def run(
        self,
        *,
        original_prompt: str,
        final_prompt: str,
        code: str,
    ) -> AgentResult:
        lower = code.lower()

        simulated_attacks = []
        weak_points = []

        if "login" in lower or "authenticate" in lower:
            simulated_attacks.append(
                "Automated credential-stuffing attacks against the login endpoint."
            )
            weak_points.append(
                "Lack of rate limiting or account lockout may allow brute-force attempts."
            )

        if "password" in lower and "bcrypt" not in lower and "argon2" not in lower:
            simulated_attacks.append(
                "Database compromise exposes plaintext or weakly protected passwords."
            )
            weak_points.append(
                "Passwords are not strongly hashed before storage."
            )

        if "execute(" in lower or "select " in lower:
            simulated_attacks.append(
                "Attacker submits crafted input to manipulate SQL queries."
            )
            weak_points.append(
                "Potential SQL injection if queries interpolate user input."
            )

        if not simulated_attacks:
            simulated_attacks.append(
                "No obvious high-risk exploit paths identified from the generated code stub."
            )
            weak_points.append(
                "Further manual review and dynamic testing are recommended."
            )

        severity = "high" if len(simulated_attacks) > 1 else "medium"

        parsed: Dict[str, Any] = {
            "agent_name": "attack_simulation",
            "simulated_attacks": simulated_attacks,
            "weak_points": weak_points,
            "severity": severity,
            "notes": "Conceptual simulation only; run full DAST in staging.",
        }

        parsed = _ui_enhance(parsed)

        return AgentResult(
            name="attack_simulation",
            role="attack",
            raw=json.dumps(parsed, indent=2),
            parsed=parsed,
        )
