from __future__ import annotations

import json
from typing import List

from nestai.models import AgentResult, call_json_model

BLUE_AGENT_SYSTEM_PROMPT = """
YOU ARE A BLUE TEAM DEFENSIVE PROMPT ENGINEER.

You receive:
- The raw user prompt.
- A summary of Red Team risks (auth, rbac, injection, crypto, logic, api).

Your job:
- Rewrite the prompt to enforce strict security controls.
- Add concrete, enforceable constraints.
- Clarify vague requirements.
- Align with OWASP ASVS, OWASP API Security, NIST SP 800-53.

Return ONLY valid JSON:

{
  "agent_name": "blue_X",
  "rewritten_prompt": "string",
  "constraints": ["string"],
  "assumptions": ["string"],
  "notes": "string"
}
"""


def _ui_enhance(parsed: dict, name: str) -> dict:
    parsed["severity_color"] = "blue"
    parsed["short_summary"] = f"{name}: Defensive Rewrite"
    parsed["badge"] = "BLUE"
    return parsed


class BlueTeam:
    def __init__(self, num_agents: int = 5) -> None:
        self.num_agents = num_agents

    def run_all(
        self,
        user_prompt: str,
        red_risks_summary: str,
    ) -> List[AgentResult]:
        results: List[AgentResult] = []

        for i in range(1, self.num_agents + 1):
            name = f"blue_{i}"
            payload = {
                "agent_name": name,
                "user_prompt": user_prompt,
                "red_team_risks": red_risks_summary,
            }

            parsed = call_json_model(BLUE_AGENT_SYSTEM_PROMPT, payload)
            parsed.setdefault("agent_name", name)
            parsed.setdefault("rewritten_prompt", user_prompt)
            parsed.setdefault("constraints", [])
            parsed.setdefault("assumptions", [])
            parsed.setdefault("notes", "")
            parsed = _ui_enhance(parsed, name)

            results.append(
                AgentResult.from_parsed(
                    name=name,
                    role="blue",
                    parsed=parsed,
                )
            )

        return results
