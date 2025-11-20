# nestai/controller.py
from __future__ import annotations

import json
from typing import List, Dict, Any

from nestai.models import AgentResult, make_json_safe


class ControllerResult:
    """
    Simple object used by the controller to standardize unified results.
    """
    def __init__(self, final_prompt: str, blocked: bool = False, reason: str = ""):
        self.final_prompt = final_prompt
        self.blocked = blocked
        self.reason = reason

    def to_dict(self):
        return make_json_safe({
            "final_prompt": self.final_prompt,
            "blocked": self.blocked,
            "reason": self.reason
        })


class Controller:
    """
    Aggregates:
    - Static prompt analysis
    - All red team results
    - All blue team defensive rewrites

    Produces:
    - Final secure prompt
    - Block decisions for malicious intent
    """

    def unify(
        self,
        user_prompt: str,
        red_team_results: List[AgentResult],
        blue_team_results: List[AgentResult],
    ) -> ControllerResult:

        # Check malicious agent
        for r in red_team_results:
            if r.name == "malicious_red" and r.parsed.get("malicious_agent_blocked"):
                return ControllerResult(
                    final_prompt="",
                    blocked=True,
                    reason="malicious_intent_detected"
                )

        # Combine all constraints from blue team
        combined_constraints = []
        for blue in blue_team_results:
            combined_constraints.extend(blue.parsed.get("constraints", []))

        # Build final prompt
        final_prompt = (
            "Generate secure, production-grade code according to:\n"
            "- OWASP ASVS, NIST 800-53, MITRE ATT&CK\n"
            "- Strict constraints extracted from Blue Team Agents:\n"
        )

        for c in combined_constraints:
            final_prompt += f"- {c}\n"

        final_prompt += "\nUser request:\n" + user_prompt

        return ControllerResult(final_prompt=final_prompt, blocked=False)
