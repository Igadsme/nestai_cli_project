# nestai/report_cli.py

from __future__ import annotations
from pathlib import Path
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console

from nestai.shared_paths import (
    LAST_RESULT_JSON,
    REPORTS_DIR,
    ensure_dirs,
    make_json_safe,
)



def generate_html_report_from_last() -> Optional[Path]:
    """
    Builds a small HTML dashboard from ~/.nestai/last_result.json.
    Returns path or None if not available.
    """

    if not LAST_RESULT_JSON.exists():
        return None

    try:
        data = json.loads(LAST_RESULT_JSON.read_text(encoding="utf-8"))
    except Exception:
        return None

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("nestai_report_%Y%m%d_%H%M%S.html")
    out_path = REPORTS_DIR / ts

    original_prompt = data.get("original_prompt", "")
    final_prompt = data.get("final_prompt", "")
    static_agent = data.get("static_agent") or {}
    static_gen = data.get("static_generated_agent") or {}
    attack_result = data.get("attack_result") or {}
    red_team_agents = data.get("red_team_agents") or []

    def _extract_static_block(block: Dict[str, Any]) -> Dict[str, Any]:
        parsed = (block or {}).get("parsed") or {}
        return {
            "overall_risk": parsed.get("overall_risk", "unknown"),
            "summary": parsed.get("summary", ""),
            "issues": parsed.get("issues", []),
        }

    static_prompt_info = _extract_static_block(static_agent)
    static_gen_info = _extract_static_block(static_gen)

    attack_parsed = (attack_result or {}).get("parsed") or {}
    attack_info = {
        "severity": attack_parsed.get("severity", "unknown"),
        "weak_points": attack_parsed.get("weak_points", []),
    }

    html: List[str] = []
    html.append("<!doctype html><html><head><meta charset='utf-8'>")
    html.append("<title>NestAI Secure Coding Report</title>")

    html.append(
        "<style>"
        "body{font-family:system-ui;background:#020617;color:#e5e7eb;padding:24px;}"
        "h1,h2,h3{color:#38bdf8;}"
        "pre{background:#0f172a;padding:12px;border-radius:8px;}"
        ".card{background:#020617;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-bottom:16px;}"
        ".badge{padding:2px 6px;border-radius:999px;font-size:12px;}"
        ".low{background:#064e3b;color:#bbf7d0;}"
        ".medium{background:#78350f;color:#fed7aa;}"
        ".high{background:#7f1d1d;color:#fecaca;}"
        ".critical{background:#b91c1c;color:#fee2e2;}"
        "</style>"
    )

    html.append("</head><body>")
    html.append("<h1>NestAI – Secure Coding Report</h1>")

    if original_prompt:
        html.append("<div class='card'><h2>Original Prompt</h2>")
        html.append(f"<pre>{original_prompt}</pre></div>")

    if final_prompt:
        html.append("<div class='card'><h2>Final Secure Prompt</h2>")
        html.append(f"<pre>{final_prompt}</pre></div>")

    # Static
    def _render_static_block(title: str, info: Dict[str, Any]):
        risk = info.get("overall_risk", "unknown").lower()
        summary = info.get("summary", "")
        issues = info.get("issues", [])

        html.append("<div class='card'>")
        html.append(f"<h2>{title} <span class='badge {risk}'>{risk.upper()}</span></h2>")
        if summary:
            html.append(f"<p><b>Summary:</b> {summary}</p>")

        if issues:
            html.append("<ul>")
            for issue in issues:
                tool = issue.get("tool", "generic")
                msg = issue.get("message", "")
                rule = issue.get("rule_id", "")
                html.append(f"<li>[{tool}] {msg} ({rule})</li>")
            html.append("</ul>")
        html.append("</div>")

    _render_static_block("Static Prompt Analysis", static_prompt_info)
    _render_static_block("Generated Code Static Analysis", static_gen_info)

    # Attack Sim
    sev = attack_info.get("severity", "unknown").lower()
    weak = attack_info.get("weak_points", [])
    html.append("<div class='card'>")
    html.append(f"<h2>Attack Simulation <span class='badge {sev}'>{sev.upper()}</span></h2>")
    if weak:
        html.append("<ul>")
        for w in weak:
            html.append(f"<li>{w}</li>")
        html.append("</ul>")
    html.append("</div>")

    html.append("</body></html>")
    out_path.write_text("\n".join(html), encoding="utf-8")
    return out_path


def run_report_command(args: List[str], console: Console) -> None:
    """
    CLI entry for: nestai report html
    """
    if not args or args[0] != "html":
        console.print("[red]Usage: nestai report html[/red]")
        return

    path = generate_html_report_from_last()
    if not path:
        console.print("[red]No last result found.[/red]")
        return

    console.print(f"[green]HTML report generated:[/green] [bold]{path}[/bold]")
