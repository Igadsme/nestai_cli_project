# nestai/blue_team.py
from __future__ import annotations

import json
from typing import Any, Dict, List

from nestai.models import AgentResult, call_json_model, make_json_safe


BLUE_SYSTEM_PROMPT = """
You are a Senior Defensive Security Engineer (Blue Team)
performing a defensive prompt transformation according to:

- OWASP ASVS 4.0 (Requirement Hardening)
- NIST 800-53 (AC, IA, SC Controls)
- OWASP Proactive Controls
- SANS CWE Mitigation Guidance

Return ONLY JSON:
{
  "agent_name": "string",
  "rewritten_prompt": "string",
  "constraints": ["string"],
  "assumptions": ["string"],
  "notes": "string"
}

Your job:
- Strengthen the user’s prompt
- Add detailed constraints
- Remove dangerous ambiguity
- Apply secure defaults
- Enforce best-practice design
- Produce enterprise-grade advice
"""


def _generate_blue_result(system_prompt: str, user_prompt: str, name: str) -> AgentResult:
    parsed = call_json_model(system_prompt, user_prompt)

    # Add defensive rewrite content
    parsed["agent_name"] = name
    parsed.setdefault("constraints", [])
    parsed.setdefault("assumptions", [])
    parsed.setdefault("notes", "")

    # Add more detailed industry-grade defensive requirements
    parsed["constraints"].extend([
        "Enforce least-privilege and deny-by-default access control.",
        "Ensure strict validation for all input fields (whitelisting preferred).",
        "Require TLS enforcement for all data-in-transit.",
        "Implement structured audit logging for sensitive operations.",
        "Ensure all secrets are retrieved from a hardened secret vault.",
    ])

    parsed["assumptions"].extend([
        "The underlying infrastructure supports MFA and session integrity.",
        "Code generation must meet OWASP ASVS level 2 or higher.",
        "Access control model will rely on RBAC/ABAC principles.",
    ])

    parsed["rewritten_prompt"] = (
        "Generate a highly secure implementation aligned with OWASP, "
        "NIST, and industry-grade secure coding practices. "
        f"User request: {user_prompt}"
    )

    return AgentResult.from_raw_dict({
        "name": name,
        "role": "blue",
        "raw": json.dumps(make_json_safe(parsed), indent=2),
        "parsed": parsed,
    })


class BlueTeam:
    def __init__(self, num_agents: int = 5) -> None:
        self.num_agents = num_agents

    def run_all(self, user_prompt: str) -> List[AgentResult]:
        results: List[AgentResult] = []
        for i in range(1, self.num_agents + 1):
            name = f"blue_{i}"
            system_prompt = BLUE_SYSTEM_PROMPT
            results.append(_generate_blue_result(system_prompt, user_prompt, name))
        return results
