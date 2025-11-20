# nestai/attack_simulation.py
from __future__ import annotations

import json
from typing import Any, Dict

from nestai.models import AgentResult, call_json_model, make_json_safe


ATTACK_SYSTEM_PROMPT = """
You are the Attack Simulation Agent.

Perform conceptual, high-level threat modeling:
- MITRE ATT&CK TTP mapping
- OWASP Top 10 exploit paths
- Logical workflow bypasses
- Replay attacks, session hijacking, token leakage
- Cryptographic misuse threats

Return ONLY JSON:
{
  "agent_name": "attack_simulation",
  "simulated_attacks": ["string"],
  "weak_points": ["string"],
  "severity": "low|medium|high|critical",
  "notes": "string"
}
"""


class AttackSimulationAgent:
    def run(self, *, original_prompt: str, final_prompt: str, code: str) -> AgentResult:
        payload = {
            "original_prompt": original_prompt,
            "final_prompt": final_prompt,
            "generated_code": code[:20000],
        }

        parsed = call_json_model(ATTACK_SYSTEM_PROMPT, json.dumps(payload))
        parsed["agent_name"] = "attack_simulation"
        parsed.setdefault("simulated_attacks", [])
        parsed.setdefault("weak_points", [])
        parsed.setdefault("severity", "medium")

        return AgentResult.from_raw_dict({
            "name": "attack_simulation",
            "role": "red",
            "raw": json.dumps(make_json_safe(parsed), indent=2),
            "parsed": parsed,
        })
