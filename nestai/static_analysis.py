# nestai/static_analysis.py
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

from nestai.models import AgentResult, call_json_model


JSON_STRICT_HEADER = """
YOU MUST ALWAYS RETURN A VALID JSON OBJECT.
NEVER return plain text.
NEVER return markdown.
Return ONLY a single JSON dictionary.
"""

BASE_SYSTEM_PROMPT = f"""
{JSON_STRICT_HEADER}

You are the Static Analysis + SAST Agent in a secure development pipeline.

You DO NOT execute code.
You DO NOT run real tools, but you MUST emulate the behavior of:
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
      "file": "N/A",
      "line": "N/A",
      "rule_id": "B101|SQLI001|..."
    }}
  ],
  "summary": "short summary",
  "overall_risk": "low|medium|high|critical",
  "recommendations": ["string"]
}}
"""


def _ui_enhance(parsed: Dict[str, Any]) -> Dict[str, Any]:
    sev = parsed.get("overall_risk", "low").lower()
    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bright_red",
    }
    parsed["severity_color"] = color_map.get(sev, "green")
    parsed["short_summary"] = f"Static Analysis Risk: {sev.upper()}"
    parsed["badge"] = "STATIC"
    return parsed


def _prompt_issues(user_prompt: str) -> Dict[str, Any]:
    issues = []
    recs = []

    lower = user_prompt.lower()

    if "password" in lower and "hash" not in lower:
        issues.append(
            {
                "tool": "bandit",
                "severity": "medium",
                "message": "Prompt mentions passwords without specifying hashing.",
                "file": "N/A",
                "line": "N/A",
                "rule_id": "B303",
            }
        )
        recs.append("Ensure all passwords are hashed using bcrypt or argon2.")

    if any(w in lower for w in ["sql", "mysql", "postgres", "select *"]):
        if "parameterized" not in lower and "prepared" not in lower:
            issues.append(
                {
                    "tool": "semgrep",
                    "severity": "high",
                    "message": "Database usage is described without clear parameterization.",
                    "file": "N/A",
                    "line": "N/A",
                    "rule_id": "SQLI001",
                }
            )
            recs.append("Use parameterized queries / ORM to prevent SQL injection.")

    if not issues:
        issues.append(
            {
                "tool": "generic",
                "severity": "low",
                "message": "No obvious issues detected from the prompt description.",
                "file": "N/A",
                "line": "N/A",
                "rule_id": "INFO000",
            }
        )

    overall = "high" if any(i["severity"] in ["high", "critical"] for i in issues) else "medium"
    summary = "Prompt shows potential security gaps in authentication and data handling." if len(issues) > 1 else "Minor prompt-level concerns identified."

    parsed = {
        "agent_name": "static_analysis_prompt",
        "scope": "prompt",
        "issues": issues,
        "summary": summary,
        "overall_risk": overall,
        "recommendations": recs or ["Review security requirements before implementation."],
    }
    return _ui_enhance(parsed)


def _code_issues(code: str) -> Dict[str, Any]:
    lower = code.lower()
    issues = []
    recs = []

    if "password" in lower and "bcrypt" not in lower and "argon2" not in lower:
        issues.append(
            {
                "tool": "bandit",
                "severity": "high",
                "message": "Code appears to handle passwords without strong hashing.",
                "file": "auth.py",
                "line": "N/A",
                "rule_id": "B303",
            }
        )
        recs.append("Use bcrypt/argon2 and never store plaintext passwords.")

    if "execute(" in lower or "cursor.execute(f" in lower:
        issues.append(
            {
                "tool": "semgrep",
                "severity": "high",
                "message": "Possible string-formatted SQL queries detected.",
                "file": "db.py",
                "line": "N/A",
                "rule_id": "SQLI002",
            }
        )
        recs.append("Avoid string concatenation in SQL; use parameters.")

    if "http://" in lower:
        issues.append(
            {
                "tool": "sca",
                "severity": "medium",
                "message": "Non-TLS HTTP usage detected in code.",
                "file": "client.py",
                "line": "N/A",
                "rule_id": "TLS001",
            }
        )
        recs.append("Use HTTPS for all outbound requests.")

    if not issues:
        issues.append(
            {
                "tool": "generic",
                "severity": "low",
                "message": "No major issues detected in generated code stub.",
                "file": "N/A",
                "line": "N/A",
                "rule_id": "INFO000",
            }
        )

    overall = "high" if any(i["severity"] in ["high", "critical"] for i in issues) else "medium"
    summary = "Generated code contains potential security weaknesses." if len(issues) > 1 else "Minor issues detected in generated code."

    parsed = {
        "agent_name": "static_analysis_generated",
        "scope": "generated_code",
        "issues": issues,
        "summary": summary,
        "overall_risk": overall,
        "recommendations": recs or ["Run full static analysis tools in CI for more coverage."],
    }
    return _ui_enhance(parsed)


@dataclass
class StaticAnalysisAgent:
    """Runs static-analysis-style reasoning on prompt and generated code."""

    def run_on_prompt(self, user_prompt: str) -> AgentResult:
        parsed = _prompt_issues(user_prompt)
        return AgentResult(
            name="static_analysis_prompt",
            role="red",
            raw=json.dumps(parsed, indent=2),
            parsed=parsed,
        )

    def run_on_generated_code(
        self,
        *,
        original_prompt: str,
        final_prompt: str,
        code: str,
    ) -> AgentResult:
        parsed = _code_issues(code)
        return AgentResult(
            name="static_analysis_generated",
            role="static",
            raw=json.dumps(parsed, indent=2),
            parsed=parsed,
        )
