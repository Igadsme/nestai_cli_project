from __future__ import annotations

import json
from typing import Any, Dict

from nestai.models import AgentResult, call_json_model

ATTACK_SIM_PROMPT = """
YOU ARE THE ATTACK SIMULATION AGENT.

Your job:
- Review the AI-generated code.
- Conceptually simulate realistic attacker behavior (NO exploit code).
- Identify exploit paths, insecure flows, or missing protections.
- Summarize risk and weakest paths.

Return ONLY valid JSON:

{
  "agent_name": "attack_simulation",
  "simulated_attacks": ["string"],
  "weak_points": ["string"],
  "severity": "low|medium|high|critical",
  "notes": "string"
}
"""


class AttackSimulationAgent:
    def run(
        self,
        *,
        original_prompt: str,
        final_prompt: str,
        code: str,
    ) -> AgentResult:
        payload: Dict[str, Any] = {
            "original_prompt": original_prompt,
            "final_prompt": final_prompt,
            "generated_code": code[:20000],
        }

        parsed = call_json_model(ATTACK_SIM_PROMPT, payload)
        parsed.setdefault("agent_name", "attack_simulation")
        parsed.setdefault("simulated_attacks", [])
        parsed.setdefault("weak_points", [])
        parsed.setdefault("severity", "low")
        parsed.setdefault("notes", "")

        return AgentResult.from_parsed(
            name="attack_simulation",
            role="attack",
            parsed=parsed,
        )
