from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional

from nestai.red_team import RedTeam
from nestai.blue_team import BlueTeam
from nestai.controller import Controller
from nestai.static_analysis import StaticAnalysisAgent
from nestai.codegen import generate_code
from nestai.attack_simulation import AttackSimulationAgent
from nestai.audit import append_history_entry
from nestai.models import AgentResult, make_json_safe, ControllerResult


def _find_malicious_agent(red_results: List[AgentResult]) -> Optional[AgentResult]:
    for r in red_results:
        if r.name == "malicious_red":
            return r
    return None


def _agent_list_to_dict(results: List[AgentResult]) -> List[Dict[str, Any]]:
    return [r.to_dict() for r in results]


def run_nestai(user_prompt: str) -> Dict[str, Any]:
    """
    Full NestAI pipeline as per the ASCII architecture:

    1) Static Analysis (prompt)
    2) Red Team (6 agents) + Malicious Gate
    3) Blue Team (5 defensive agents)
    4) Controller (unified secure prompt)
    5) CodeGen (OpenAI)
    6) Static Analysis (generated code)
    7) Attack Simulation
    8) Audit History
    """

    # Instantiate agents
    red_team = RedTeam()
    blue_team = BlueTeam()
    controller = Controller()
    static_agent = StaticAnalysisAgent()
    attack_sim = AttackSimulationAgent()

    # 1) Static Analysis (prompt)
    static_prompt_result = static_agent.run_on_prompt(user_prompt)

    # 2) Red Team
    red_results: List[AgentResult] = red_team.run_all(user_prompt)
    malicious_agent = _find_malicious_agent(red_results)

    # Malicious gate (hard block)
    if malicious_agent and malicious_agent.parsed.get("malicious", False):
        controller_result = ControllerResult(
            final_prompt="",
            blocked=True,
            reasons=["Malicious intent detected by malicious_red agent."],
            metadata={},
        )
        # Audit
        append_history_entry(
            original_prompt=user_prompt,
            final_prompt=None,
            controller_result=controller_result.to_dict(),
            static_prompt_result=static_prompt_result.to_dict(),
            red_team_results=_agent_list_to_dict(red_results),
            blue_team_results=[],
            static_generated_result=None,
            attack_result=None,
            code_path=None,
        )
        return {
            "original_prompt": user_prompt,
            "final_prompt": "",
            "code": "",
            "allowed": False,
            "static_agent": static_prompt_result,
            "red_team_agents": red_results,
            "blue_team_agents": [],
            "malicious_agent": malicious_agent,
            "static_generated_agent": None,
            "attack_result": None,
            "controller_result": controller_result,
        }

    # 3) Blue Team – build red-risk summary text
    red_risk_lines: List[str] = []
    for r in red_results:
        rp = r.parsed or {}
        sev = rp.get("severity", "medium")
        for risk in rp.get("risks", []):
            red_risk_lines.append(f"[{r.name} - {sev}] {risk}")
    red_risks_summary = "\n".join(red_risk_lines)

    blue_results: List[AgentResult] = blue_team.run_all(user_prompt, red_risks_summary)

    # 4) Controller
    controller_result = controller.unify(
        user_prompt=user_prompt,
        static_prompt=static_prompt_result,
        red_results=red_results,
        blue_results=blue_results,
    )

    if controller_result.blocked:
        append_history_entry(
            original_prompt=user_prompt,
            final_prompt=None,
            controller_result=controller_result.to_dict(),
            static_prompt_result=static_prompt_result.to_dict(),
            red_team_results=_agent_list_to_dict(red_results),
            blue_team_results=_agent_list_to_dict(blue_results),
            static_generated_result=None,
            attack_result=None,
            code_path=None,
        )
        return {
            "original_prompt": user_prompt,
            "final_prompt": "",
            "code": "",
            "allowed": False,
            "static_agent": static_prompt_result,
            "red_team_agents": red_results,
            "blue_team_agents": blue_results,
            "malicious_agent": malicious_agent,
            "static_generated_agent": None,
            "attack_result": None,
            "controller_result": controller_result,
        }

    final_prompt = controller_result.final_prompt

    # 5) CodeGen
    code_output = generate_code(final_prompt)

    # 6) Static Analysis (generated code)
    static_generated_result = static_agent.run_on_generated_code(
        original_prompt=user_prompt,
        final_prompt=final_prompt,
        code=code_output,
    )

    # 7) Attack Simulation
    attack_result = attack_sim.run(
        original_prompt=user_prompt,
        final_prompt=final_prompt,
        code=code_output,
    )

    # 8) Audit History
    append_history_entry(
        original_prompt=user_prompt,
        final_prompt=final_prompt,
        controller_result=controller_result.to_dict(),
        static_prompt_result=static_prompt_result.to_dict(),
        red_team_results=_agent_list_to_dict(red_results),
        blue_team_results=_agent_list_to_dict(blue_results),
        static_generated_result=static_generated_result.to_dict(),
        attack_result=attack_result.to_dict(),
        code_path=None,
    )

    return {
        "original_prompt": user_prompt,
        "final_prompt": final_prompt,
        "code": code_output,
        "allowed": True,
        "static_agent": static_prompt_result,
        "red_team_agents": red_results,
        "blue_team_agents": blue_results,
        "malicious_agent": malicious_agent,
        "static_generated_agent": static_generated_result,
        "attack_result": attack_result,
        "controller_result": controller_result,
    }
