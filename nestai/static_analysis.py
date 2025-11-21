from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

from nestai.models import AgentResult, call_json_model

JSON_STRICT_HEADER = """
YOU MUST ALWAYS RETURN A VALID JSON OBJECT.
NEVER return plain text or markdown.
Return ONLY a single JSON dictionary.
"""

BASE_SYSTEM_PROMPT = f"""
{JSON_STRICT_HEADER}

You are the Static Analysis + SAST Agent in a secure development pipeline.

You DO NOT execute code.
You emulate:
- Bandit
- Semgrep
- Ruff
- Pyright
- SCA / dependency analyzers

Return JSON:

{{
  "agent_name": "static_analysis",
  "scope": "prompt|generated_code",
  "issues": [
    {{
      "tool": "bandit|semgrep|ruff|pyright|sca|generic",
      "severity": "low|medium|high|critical",
      "message": "description",
      "file": "string",
      "line": "string",
      "rule_id": "B101|SQLI001|..."
    }}
  ],
  "summary": "short summary",
  "overall_risk": "low|medium|high|critical",
  "recommendations": ["string"]
}}
"""


def _ui_enhance(parsed: Dict[str, Any]) -> Dict[str, Any]:
    severity = parsed.get("overall_risk", "low")

    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bright_red",
    }

    parsed["overall_risk"] = severity
    parsed["severity_color"] = color_map.get(severity, "green")
    parsed["short_summary"] = f"Static Analysis Risk: {severity.upper()}"
    parsed["badge"] = "STATIC"
    return parsed


def _run_static_model(system_prompt: str, user_payload: Dict[str, Any]) -> Dict[str, Any]:
    parsed = call_json_model(system_prompt, user_payload)

    parsed.setdefault("agent_name", "static_analysis")
    parsed.setdefault("issues", [])
    parsed.setdefault("overall_risk", "low")
    parsed.setdefault("summary", "")
    parsed.setdefault("recommendations", [])

    return _ui_enhance(parsed)


@dataclass
class StaticAnalysisAgent:
    def run_on_prompt(self, user_prompt: str) -> AgentResult:
        system_prompt = BASE_SYSTEM_PROMPT + "\nYou are analyzing the ORIGINAL USER PROMPT.\n"
        payload = {
            "context": "original_user_prompt",
            "prompt_text": user_prompt,
        }
        parsed = _run_static_model(system_prompt, payload)

        return AgentResult.from_parsed(
            name="static_analysis_prompt",
            role="red",
            parsed=parsed,
        )

    def run_on_generated_code(
        self,
        *,
        original_prompt: str,
        final_prompt: str,
        code: str,
    ) -> AgentResult:
        system_prompt = BASE_SYSTEM_PROMPT + "\nYou are analyzing the AI-GENERATED CODE.\n"
        payload = {
            "context": "generated_code",
            "original_prompt": original_prompt,
            "final_prompt": final_prompt,
            "generated_code": code[:20000],
        }
        parsed = _run_static_model(system_prompt, payload)

        return AgentResult.from_parsed(
            name="static_analysis_generated",
            role="red",
            parsed=parsed,
        )
