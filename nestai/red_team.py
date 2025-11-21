from __future__ import annotations

import json
from typing import Dict, List

from nestai.models import AgentResult, call_json_model

JSON_STRICT_HEADER = """
YOU MUST ALWAYS RETURN A VALID JSON OBJECT.
NEVER return markdown, code fences, or prose outside JSON.
"""

RED_TEAM_AGENTS: Dict[str, str] = {
    "auth_red": f"""
{JSON_STRICT_HEADER}

You are the Authentication & Session Security Red Team Agent.

Return JSON:
{{
  "agent_name": "auth_red",
  "severity": "low|medium|high|critical",
  "risks": ["string"],
  "suggested_constraints": ["string"],
  "notes": "string"
}}
""",
    "rbac_red": f"""
{JSON_STRICT_HEADER}

You are the Authorization & RBAC Red Team Agent.

Return JSON:
{{
  "agent_name": "rbac_red",
  "severity": "low|medium|high|critical",
  "risks": ["string"],
  "suggested_constraints": ["string"],
  "notes": "string"
}}
""",
    "injection_red": f"""
{JSON_STRICT_HEADER}

You are the Injection & Input Validation Red Team Agent.

Return JSON:
{{
  "agent_name": "injection_red",
  "severity": "low|medium|high|critical",
  "risks": ["string"],
  "suggested_constraints": ["string"],
  "notes": "string"
}}
""",
    "crypto_red": f"""
{JSON_STRICT_HEADER}

You are the Cryptography & Secrets Red Team Agent.

Return JSON:
{{
  "agent_name": "crypto_red",
  "severity": "low|medium|high|critical",
  "risks": ["string"],
  "suggested_constraints": ["string"],
  "notes": "string"
}}
""",
    "logic_red": f"""
{JSON_STRICT_HEADER}

You are the Business Logic & Abuse Flows Red Team Agent.

Return JSON:
{{
  "agent_name": "logic_red",
  "severity": "low|medium|high|critical",
  "risks": ["string"],
  "suggested_constraints": ["string"],
  "notes": "string"
}}
""",
    "api_red": f"""
{JSON_STRICT_HEADER}

You are the API Surface & Rate Limiting Red Team Agent.

Return JSON:
{{
  "agent_name": "api_red",
  "severity": "low|medium|high|critical",
  "risks": ["string"],
  "suggested_constraints": ["string"],
  "notes": "string"
}}
""",
}

MALICIOUS_SYSTEM_PROMPT = f"""
{JSON_STRICT_HEADER}

You are the Malicious Intent Gate Agent. Detect whether the USER INTENT is malicious.

If malicious or clearly abusive (e.g., hacking, exploitation, fraud):
{{
  "agent_name": "malicious_red",
  "malicious": true,
  "malicious_agent_blocked": true,
  "block_message": "=== MALICIOUS INTENT DETECTED ===",
  "reasons": ["string"]
}}

Else:
{{
  "agent_name": "malicious_red",
  "malicious": false,
  "malicious_agent_blocked": false,
  "block_message": "",
  "reasons": []
}}
"""


def _ui_enhance(parsed: dict, name: str) -> dict:
    severity = parsed.get("severity", "medium")

    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bright_red",
    }
    parsed["severity"] = severity
    parsed["severity_color"] = color_map.get(severity, "yellow")
    parsed["short_summary"] = f"{name.upper()} Risk: {severity.upper()}"
    parsed["badge"] = "RED"
    return parsed


class RedTeam:
    def __init__(self) -> None:
        self.agent_prompts = RED_TEAM_AGENTS
        self.malicious_system_prompt = MALICIOUS_SYSTEM_PROMPT

    def run_security_agents(self, user_prompt: str) -> List[AgentResult]:
        results: List[AgentResult] = []

        for name, system_prompt in self.agent_prompts.items():
            payload = {
                "user_prompt": user_prompt,
                "agent_name": name,
            }
            parsed = call_json_model(system_prompt, payload)
            parsed.setdefault("severity", "medium")
            parsed.setdefault("risks", [])
            parsed.setdefault("suggested_constraints", [])
            parsed.setdefault("notes", "")
            parsed = _ui_enhance(parsed, name)

            results.append(
                AgentResult.from_parsed(
                    name=name,
                    role="red",
                    parsed=parsed,
                )
            )

        return results

    def run_malicious_agent(self, user_prompt: str) -> AgentResult:
        payload = {"user_prompt": user_prompt}
        parsed = call_json_model(self.malicious_system_prompt, payload)
        parsed.setdefault("malicious", False)
        parsed.setdefault("malicious_agent_blocked", parsed.get("malicious", False))
        parsed.setdefault("reasons", [])
        parsed = _ui_enhance(parsed, "malicious_red")

        return AgentResult.from_parsed(
            name="malicious_red",
            role="malicious",
            parsed=parsed,
        )

    def run_all(self, user_prompt: str) -> List[AgentResult]:
        results = self.run_security_agents(user_prompt)
        results.append(self.run_malicious_agent(user_prompt))
        return results
