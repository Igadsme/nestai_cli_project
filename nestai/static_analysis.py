# nestai/static_analysis.py
from __future__ import annotations

import json
from typing import Dict, Any

from nestai.models import AgentResult, call_json_model, make_json_safe


STATIC_SYSTEM_PROMPT = """
You are the Static Analysis + SAST Agent.

Emulate enterprise-grade tooling:
- Bandit (Python security linter)
- Semgrep (SAST rules)
- Pyright (type system issues)
- Ruff (lint errors)
- Dependency scanning (SCA)
- OWASP ASVS
- CWE weakness catalog

Return ONLY JSON:
{
  "agent_name": "static_analysis",
  "scope": "prompt|generated_code",
  "issues": [
    {
      "tool": "bandit|semgrep|sca|...",
      "severity": "low|medium|high|critical",
      "message": "string",
      "file": "string",
      "line": "string",
      "rule_id": "string"
    }
  ],
  "summary": "string",
  "overall_risk": "low|medium|high|critical",
  "recommendations": ["string"]
}
"""


def _build_sast_result(parsed: Dict[str, Any], name: str) -> AgentResult:
    parsed["agent_name"] = name
    parsed.setdefault("issues", [])
    parsed.setdefault("overall_risk", "medium")
    parsed.setdefault("summary", "")
    parsed.setdefault("recommendations", [])

    # Add extra OWASP / CWE aligned recommendations
    parsed["recommendations"].extend([
        "Validate all untrusted input using strict schema enforcement.",
        "Prefer parameterized queries to avoid injection.",
        "Avoid unsafe deserialization flows.",
        "Ensure proper access control on all API endpoints.",
    ])

    return AgentResult.from_raw_dict({
        "name": name,
        "role": "red",
        "raw": json.dumps(make_json_safe(parsed), indent=2),
        "parsed": parsed,
    })


class StaticAnalysisAgent:
    def run_on_prompt(self, user_prompt: str) -> AgentResult:
        payload = {
            "context": "original_prompt",
            "prompt_text": user_prompt,
        }
        parsed = call_json_model(STATIC_SYSTEM_PROMPT, json.dumps(payload))
        return _build_sast_result(parsed, "static_analysis_prompt")

    def run_on_generated_code(self, *, original_prompt: str, final_prompt: str, code: str) -> AgentResult:
        payload = {
            "context": "generated_code",
            "original_prompt": original_prompt,
            "final_prompt": final_prompt,
            "generated_code": code[:20000],
        }
        parsed = call_json_model(STATIC_SYSTEM_PROMPT, json.dumps(payload))
        return _build_sast_result(parsed, "static_analysis_generated")
