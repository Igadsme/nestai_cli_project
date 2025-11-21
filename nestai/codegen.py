# nestai/codegen.py
from __future__ import annotations

# Tell Pylance to ignore f-string template warnings in this file
# pyright: reportInvalidStringEscapeSequence=false
# pyright: reportUndefinedVariable=false

import json
from textwrap import dedent
from typing import Any, Dict

try:
    from openai import OpenAI
except ImportError:
    raise RuntimeError(
        "OpenAI SDK not installed. Run: pip install openai>=1.0.0"
    )

from nestai.models import call_json_model


# ---------------------------------------------------------------------
# OpenAI client (global, safe)
# ---------------------------------------------------------------------
client = OpenAI()   # Uses OPENAI_API_KEY from environment


# ---------------------------------------------------------------------
# SYSTEM PROMPT FOR SECURE CODE GENERATION
# ---------------------------------------------------------------------
SYSTEM_PROMPT = dedent("""
You are the NestAI Secure Code Generation Agent.

Your job:
- Produce SECURE production-quality code ONLY.
- Follow OWASP, CERT, NIST, and industry best practices.
- Never return explanations.
- Output ONLY valid JSON of the following schema:

{
  "generated_code": "string of python code"
}

Rules:
- NO markdown
- NO comments outside JSON
- The code must be secure, sanitized, validated, robust.
- MUST be pure Python unless the prompt explicitly requests another language.
- Minimize dependencies unless required for security.
- NEVER output prose explanations.
- ALWAYS output valid JSON.
""")


# ---------------------------------------------------------------------
# generate_code
# ---------------------------------------------------------------------
def generate_code(final_prompt: str) -> str:
    """
    LLM-powered secure code generator using gpt-4.1-mini.

    final_prompt is produced by Controller.
    We call the OpenAI API using a strict JSON response.
    """

    payload = {
        "final_prompt": final_prompt
    }

    # Call OpenAI with strict JSON format
    response = client.chat.completions.create(
        model="gpt-4.1-mini",
        temperature=0,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": json.dumps(payload, indent=2)
            }
        ]
    )

    raw = response.choices[0].message.content

    try:
        parsed = json.loads(raw)
    except Exception as e:
        raise RuntimeError(
            f"Codegen output was not valid JSON:\n{raw}"
        ) from e

    code = parsed.get("generated_code", "")
    if not isinstance(code, str):
        code = str(code)

    # Strip leading/trailing whitespace
    return code.strip()
