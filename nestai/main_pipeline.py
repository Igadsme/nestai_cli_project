# nestai/main_pipeline.py
from __future__ import annotations

from typing import Any, Dict, List

from nestai.red_team import RedTeam
from nestai.blue_team import BlueTeam
from nestai.static_analysis import StaticAnalysisAgent
from nestai.attack_simulation import AttackSimulationAgent
from nestai.controller import Controller
from nestai.codegen import generate_code
from nestai.models import AgentResult, make_json_safe


def _agent_list_to_dict(results: List[AgentResult]) -> List[Dict[str, Any]]:
    return [r.to_dict() for r in results]


def run_nestai(user_prompt: str) -> Dict[str, Any]:
    red_team = RedTeam()
    blue_team = BlueTeam()
    static_agent = StaticAnalysisAgent()
    attack_agent = AttackSimulationAgent()
    controller = Controller()

    # 1. Static analysis on prompt
    static_prompt = static_agent.run_on_prompt(user_prompt)

    # 2. Red Team
    red_results = red_team.run_all(user_prompt)

    # 3. Controller malicious gate
    mal = None
    for r in red_results:
        if r.name == "malicious_red":
            mal = r

    if mal and mal.parsed.get("malicious_agent_blocked"):
        return {
            "original_prompt": user_prompt,
            "allowed": False,
            "final_prompt": "",
            "code": "",
            "static_agent": static_prompt.to_dict(),
            "red_team_agents": _agent_list_to_dict(red_results),
            "malicious_agent": mal.to_dict(),
            "static_generated_agent": None,
            "attack_result": None,
        }

    # 4. Blue Team
    blue_results = blue_team.run_all(user_prompt)

    # 5. Controller unify
    controller_result = controller.unify(
        user_prompt,
        red_team_results=red_results,
        blue_team_results=blue_results,
    )

    if controller_result.blocked:
        return {
            "original_prompt": user_prompt,
            "allowed": False,
            "final_prompt": "",
            "code": "",
            "static_agent": static_prompt.to_dict(),
            "red_team_agents": _agent_list_to_dict(red_results),
            "malicious_agent": mal.to_dict() if mal else None,
            "static_generated_agent": None,
            "attack_result": None,
        }

    # 6. CodeGen
    code = generate_code(controller_result.final_prompt)

    # 7. Static analysis on generated code
    static_generated = static_agent.run_on_generated_code(
        original_prompt=user_prompt,
        final_prompt=controller_result.final_prompt,
        code=code,
    )

    # 8. Attack Simulation
    attack_result = attack_agent.run(
        original_prompt=user_prompt,
        final_prompt=controller_result.final_prompt,
        code=code,
    )

    return {
        "original_prompt": user_prompt,
        "allowed": True,
        "final_prompt": controller_result.final_prompt,
        "code": code,
        "static_agent": static_prompt.to_dict(),
        "red_team_agents": _agent_list_to_dict(red_results),
        "malicious_agent": mal.to_dict() if mal else None,
        "blue_team_agents": _agent_list_to_dict(blue_results),
        "static_generated_agent": static_generated.to_dict(),
        "attack_result": attack_result.to_dict(),
    }
