# blue_team.py
from __future__ import annotations

import json
from typing import List

from nestai.models import call_json_model


BLUE_AGENT_SYSTEM_PROMPT = """
YOU MUST ALWAYS RETURN VALID JSON ONLY.

You are a Blue Team Defensive Engineer.

Provide a MEDIUM-detail secure rewrite of the user's request.
Return 1 secure rewritten prompt + constraints + assumptions.

Return JSON:
{
  "agent_name": "blue_X",
  "rewritten_prompt": "Rewrite the user prompt securely using input validation, password hashing, rate limiting, and RBAC.",
  "constraints": [
    "Use bcrypt/argon2",
    "Validate all user inputs",
    "Enforce HTTPS",
    "Use role-based access control"
  ],
  "assumptions": [
    "All user input is untrusted",
    "Attackers may brute-force credentials"
  ],
  "notes": "Medium-level defensive improvements applied."
}
"""


def _ui_enhance(parsed: dict, name: str) -> dict:
    parsed["severity_color"] = "blue"
    parsed["short_summary"] = f"{name}: Defensive Rewrite"
    parsed["badge"] = "BLUE"
    return parsed


class BlueTeam:
    def __init__(self, num_agents: int = 3) -> None:
        self.num_agents = num_agents

    def run_all(self, user_prompt: str) -> List[dict]:
        results = []
        for i in range(1, self.num_agents + 1):
            name = f"blue_{i}"
            payload = {
                "agent_name": name,
                "user_prompt": user_prompt
            }

            parsed = call_json_model(
                BLUE_AGENT_SYSTEM_PROMPT,
                json.dumps(payload, indent=2)
            )

            parsed["agent_name"] = name
            parsed = _ui_enhance(parsed, name)

            results.append({
                "name": name,
                "role": "blue",
                "parsed": parsed,
                "raw": json.dumps(parsed, indent=2)
            })

        return results
