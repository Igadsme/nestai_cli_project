from __future__ import annotations

from typing import Any, Dict, List, Tuple

from nestai.models import AgentResult, ControllerResult, make_json_safe


class Controller:
    """
    Controller merges:
    - Static analysis (prompt)
    - Red team agents (incl. injection, crypto, etc.)
    - Blue team defensive rewrites

    It emits ONE final unified secure prompt and can hard-block unsafe scenarios.
    """

    def unify(
        self,
        user_prompt: str,
        static_prompt: AgentResult,
        red_results: List[AgentResult],
        blue_results: List[AgentResult],
    ) -> ControllerResult:
        reasons: List[str] = []
        metadata: Dict[str, Any] = {}

        # 1. Gather all red-team constraints
        hard_constraints: List[str] = []
        soft_constraints: List[str] = []

        max_severity_rank = 0
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        for r in red_results:
            parsed = r.parsed or {}
            sev = (parsed.get("severity") or "medium").lower()
            max_severity_rank = max(max_severity_rank, severity_rank.get(sev, 2))

            for c in parsed.get("suggested_constraints", []):
                if sev in {"high", "critical"}:
                    hard_constraints.append(c)
                else:
                    soft_constraints.append(c)

        # 2. Add static analysis recommendations
        static_parsed = static_prompt.parsed or {}
        static_overall = (static_parsed.get("overall_risk") or "low").lower()
        static_sev_rank = severity_rank.get(static_overall, 1)
        max_severity_rank = max(max_severity_rank, static_sev_rank)

        for rec in static_parsed.get("recommendations", []):
            soft_constraints.append(rec)

        # 3. Merge blue-team constraints and rewrites
        blue_constraints: List[str] = []
        blue_rewrites: List[str] = []
        for b in blue_results:
            bp = b.parsed or {}
            blue_rewrites.append(bp.get("rewritten_prompt", user_prompt))
            blue_constraints.extend(bp.get("constraints", []))

        # 4. Decide if we must block
        blocked = False
        if max_severity_rank >= severity_rank["critical"]:
            blocked = True
            reasons.append("One or more agents reported CRITICAL severity.")

        # 5. Build unified constraints
        unified_constraints = list(dict.fromkeys(
            hard_constraints + blue_constraints + soft_constraints
        ))

        # 6. Build final unified prompt (if not blocked)
        if blocked:
            final_prompt = ""
        else:
            merged_blue = "\n".join(f"- {c}" for c in unified_constraints)
            final_prompt = (
                "Generate secure, production-grade code according to:\n"
                "- OWASP ASVS, OWASP API Security Top 10, NIST SP 800-53\n"
                "- The following enforced security constraints:\n"
                f"{merged_blue}\n\n"
                "User request:\n"
                f"{user_prompt}"
            )

        metadata["unified_constraints"] = unified_constraints
        metadata["max_severity_rank"] = max_severity_rank
        metadata["static_overall_risk"] = static_overall

        return ControllerResult(
            final_prompt=final_prompt,
            blocked=blocked,
            reasons=reasons,
            metadata=make_json_safe(metadata),
        )
