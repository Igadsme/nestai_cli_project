# controller.py

from __future__ import annotations
from typing import Any, Dict, List

from nestai.models import make_json_safe
from nestai.red_team import RedTeam
from nestai.blue_team import BlueTeam
from nestai.static_analysis import StaticAnalysisAgent
from nestai.attack_simulation import AttackSimulationAgent
from nestai.codegen import generate_code


class Controller:
    """
    NEW ARCHITECTURE A — SINGLE ORCHESTRATOR

    Controller handles the full secure-coding pipeline:

      1. Static Analysis (prompt)
      2. Red Team (threat discovery)
      3. Malicious agent extraction
      4. Blue Team (defensive rewrite)
      5. Secure final prompt synthesis
      6. Code generation
      7. Static Analysis (generated code)
      8. Attack simulation
      9. JSON-safe unified output
    """

    def run_full_pipeline(self, user_prompt: str) -> Dict[str, Any]:

        static_agent = StaticAnalysisAgent()
        red_team = RedTeam()
        blue_team = BlueTeam()
        attack_sim = AttackSimulationAgent()

        # 1. Static analysis (initial prompt)
        static_prompt = static_agent.run_on_prompt(user_prompt)

        # 2. Red Team
        red_results = red_team.run_all(user_prompt)
        red_results_safe = make_json_safe(red_results)

        # 3. Malicious Agent Gate
        malicious = None
        for r in red_results:
            parsed = r.get("parsed", {})
            if parsed.get("malicious_agent_blocked", False):
                malicious = r
                break

        if malicious:
            return make_json_safe({
                "input_prompt": user_prompt,
                "allowed": False,
                "blocked_reason": "malicious_intent",
                "static_analysis_prompt": static_prompt,
                "red_team_findings": red_results_safe,
                "blue_team_actions": [],
                "final_prompt": "",
                "code": "",
                "static_analysis_generated": None,
                "attack_simulation": None,
            })

        # 4. Blue Team rewrites
        blue_results = blue_team.run_all(user_prompt)
        blue_results_safe = make_json_safe(blue_results)

        # 5. Final prompt synthesis
        # For now, simplest: pick strongest blue agent final prompt
        final_prompt = ""
        for b in blue_results:
            parsed = b.get("parsed", {})
            if parsed.get("rewritten_prompt"):
                final_prompt = parsed["rewritten_prompt"]
                break

        if not final_prompt:
            final_prompt = user_prompt  # fallback

        # 6. Code Generation
        code_output = generate_code(final_prompt)

        # 7. Static Analysis (on generated code)
        static_generated = static_agent.run_on_generated_code(
            original_prompt=user_prompt,
            final_prompt=final_prompt,
            code=code_output,
        )

        # 8. Attack Simulation
        attack_result = attack_sim.run(
            original_prompt=user_prompt,
            final_prompt=final_prompt,
            code=code_output,
        )

        # 9. Unified JSON-safe output
        output = {
            "input_prompt": user_prompt,
            "allowed": True,
            "static_analysis_prompt": static_prompt,
            "red_team_findings": red_results_safe,
            "blue_team_actions": blue_results_safe,
            "final_prompt": final_prompt,
            "code": code_output,
            "static_analysis_generated": make_json_safe(static_generated),
            "attack_simulation": make_json_safe(attack_result),
        }

        return make_json_safe(output)
