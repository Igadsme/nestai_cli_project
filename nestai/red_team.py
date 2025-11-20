# nestai/red_team.py
from __future__ import annotations

import json
from typing import List, Dict, Any

from nestai.models import AgentResult, call_json_model, make_json_safe


# ================================================================
# INDUSTRY-GRADE RED TEAM PROMPTS
# ================================================================

# These prompts instruct the local_reasoner to produce detailed,
# enterprise-quality findings (OWASP, MITRE ATT&CK, NIST, SANS, CWE).


BASE_RED_PROMPT = """
You are a Senior Application Security Engineer conducting a deep-dive threat
analysis according to:

- OWASP ASVS 4.0
- OWASP Top 10 (2021 / 2023)
- OWASP API Security Top 10
- MITRE ATT&CK (Enterprise)
- CWE/SANS Top 25
- NIST SP 800-53 and 800-63

You MUST return ONLY a JSON object with fields:
{
  "agent_name": "string",
  "severity": "low|medium|high|critical",
  "risks": ["detailed textual explanations"],
  "suggested_constraints": ["detailed remediation steps"],
  "notes": "optional deeper analysis"
}

Make findings DETAILED, INDUSTRY-GRADE, and PROFESSIONAL.
"""


RED_AGENTS: Dict[str, str] = {
    "auth_red": BASE_RED_PROMPT + """
Analyze authentication surfaces, identity verification,
MFA enforcement, credential workflows, session integrity,
and user enumeration vectors.
""",

    "rbac_red": BASE_RED_PROMPT + """
Analyze authorization posture, RBAC/ABAC enforcement,
broken access control indicators, privilege escalation risk,
multi-tenant isolation, horizontal/vertical access control.
""",

    "injection_red": BASE_RED_PROMPT + """
Analyze data handling for SQL injection, command injection,
template injection, path traversal, deserialization attacks,
and insufficient input validation.
""",

    "crypto_red": BASE_RED_PROMPT + """
Analyze cryptographic operations, token signing, secret
handling, entropy, key rotation, algorithm safety, and secure
storage of sensitive materials.
""",

    "logic_red": BASE_RED_PROMPT + """
Analyze business logic flaws: bypasses, workflow tampering,
state machine abuse, replay issues, predictable flows, privilege confusion.
""",

    "api_red": BASE_RED_PROMPT + """
Analyze API endpoints, request validation, schema enforcement,
rate limiting, versioning, pagination security, and misuse of HTTP verbs.
""",
}


MALICIOUS_AGENT_PROMPT = """
You are the Malicious Intent Detection Agent.

Return ONLY JSON:
{
  "agent_name": "malicious_red",
  "malicious_agent_blocked": true|false,
  "reasons": ["detailed"],
  "notes": "optional"
}

If user intent suggests:
- exploitation
- data exfiltration
- unauthorized access
- malware creation
- harmful behavior

…then malicious_agent_blocked MUST be true.
"""


# ================================================================
# INTERNAL NORMALIZATION
# ================================================================

def _normalize(system_prompt: str, name: str, user_prompt: str) -> AgentResult:
    parsed = call_json_model(system_prompt, f"User prompt: {user_prompt}")
    parsed["agent_name"] = name

    return AgentResult.from_raw_dict({
        "name": name,
        "role": "red",
        "raw": json.dumps(make_json_safe(parsed), indent=2),
        "parsed": parsed,
    })


# ================================================================
# RED TEAM CLASS
# ================================================================

class RedTeam:
    def __init__(self):
        self.red_agents = RED_AGENTS
        self.malicious_prompt = MALICIOUS_AGENT_PROMPT

    def run_security_agents(self, user_prompt: str) -> List[AgentResult]:
        results: List[AgentResult] = []
        for name, system_prompt in self.red_agents.items():
            results.append(_normalize(system_prompt, name, user_prompt))
        return results

    def run_malicious_agent(self, user_prompt: str) -> AgentResult:
        parsed = call_json_model(self.malicious_prompt, f"User prompt: {user_prompt}")
        parsed["agent_name"] = "malicious_red"

        return AgentResult.from_raw_dict({
            "name": "malicious_red",
            "role": "malicious",
            "raw": json.dumps(make_json_safe(parsed), indent=2),
            "parsed": parsed,
        })

    def run_all(self, user_prompt: str) -> List[AgentResult]:
        results = self.run_security_agents(user_prompt)
        results.append(self.run_malicious_agent(user_prompt))
        return results
