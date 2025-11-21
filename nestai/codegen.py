from __future__ import annotations

import json
from textwrap import dedent
from typing import Dict, Any

from nestai.models import call_json_model

SYSTEM_PROMPT = """
You are the CODEGEN Agent in the NestAI Secure Coding Pipeline.

You receive:
- A FINAL UNIFIED SECURE PROMPT that already includes strict security constraints.

Your job:
- Generate secure, production-grade Python code that follows the constraints.
- Prefer frameworks like FastAPI or Flask with strong security posture.
- Implement:
  - input validation
  - authentication
  - minimal RBAC
  - proper error handling
  - logging hooks (no secrets in logs)
- NEVER return explanations, only code.

Return ONLY valid JSON:

{
  "generated_code": "python source code as a single string"
}
"""


def generate_code(final_prompt: str) -> str:
    """
    Calls OpenAI to generate secure Python code as per the final unified prompt.

    Requires OPENAI_API_KEY to be set in environment.
    """
    user_payload: Dict[str, Any] = {
        "final_secure_prompt": final_prompt,
        "language": "python",
        "framework_preference": "FastAPI",
    }

    parsed = call_json_model(SYSTEM_PROMPT, user_payload)
    code = parsed.get("generated_code", "")

    if not isinstance(code, str):
        code = json.dumps(code, indent=2)

    # Clean up leading/trailing whitespace
    code = dedent(code).strip("\n")
    return code
