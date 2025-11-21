# nestai/cli.py
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.prompt import Prompt
from rich.syntax import Syntax

from nestai.main_pipeline import run_nestai
from nestai.history_cli import run_history_command
from nestai.config_cli import run_config_command


# ─────────────────────────────────────────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────────────────────────────────────────

APP_DIR = Path.home() / ".nestai"
GENERATED_DIR = APP_DIR / "generated"
REPORTS_DIR = APP_DIR / "reports"
LAST_RESULT_JSON = APP_DIR / "last_result.json"


def _ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# JSON SAFE
# ─────────────────────────────────────────────────────────────────────────────

def make_json_safe(obj: Any) -> Any:
    if obj is None:
        return None

    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        try:
            return make_json_safe(obj.to_dict())
        except Exception:
            pass

    try:
        if hasattr(obj, "__dataclass_fields__"):
            return make_json_safe(asdict(obj))
    except Exception:
        pass

    if isinstance(obj, dict):
        return {k: make_json_safe(v) for k, v in obj.items()}

    if isinstance(obj, (list, tuple)):
        return [make_json_safe(x) for x in obj]

    if isinstance(obj, (str, int, float, bool)):
        return obj

    return repr(obj)


# ─────────────────────────────────────────────────────────────────────────────
# CODE SAVE + PREVIEW
# ─────────────────────────────────────────────────────────────────────────────

def save_generated_code(code: str) -> Path:
    _ensure_dirs()
    ts = datetime.now().strftime("nestai_%Y%m%d_%H%M%S.py")
    path = GENERATED_DIR / ts
    path.write_text(code, encoding="utf-8")
    return path


def handle_code_preview(
    console: Console,
    code: str,
    path: Path,
    minimal: bool = False,
) -> None:
    console.print(
        f"[green]Code generated and saved to[/green] [bold]{path}[/bold]\n"
        "[cyan]You can open this file in your editor.[/cyan]\n"
    )

    if minimal:
        return

    choice = Prompt.ask(
        "Press <Enter> to preview first 40 lines, or 's' to skip",
        default="",
        show_default=False,
    ).strip().lower()

    if choice in {"s", "skip", "n"}:
        console.print("Skipping preview.")
        return

    preview = "\n".join(code.splitlines()[:40])
    syntax = Syntax(preview, "python", line_numbers=True, theme="monokai")
    console.print(Rule("[bold green]Code Preview[/bold green]"))
    console.print(syntax)
    console.print("[dim]… full code in file above[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# SAVE LAST RESULT
# ─────────────────────────────────────────────────────────────────────────────

def save_last_result(result: Dict[str, Any]) -> None:
    _ensure_dirs()
    safe = make_json_safe(result)
    LAST_RESULT_JSON.write_text(json.dumps(safe, indent=2), encoding="utf-8")


# ─────────────────────────────────────────────────────────────────────────────
# REPORT GENERATION
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report_from_last() -> Optional[Path]:
    """
    Build a small HTML dashboard from the last pipeline result saved in
    ~/.nestai/last_result.json. Returns the path to the generated file,
    or None if there is no last result.
    """
    _ensure_dirs()

    if not LAST_RESULT_JSON.exists():
        return None

    try:
        data = json.loads(LAST_RESULT_JSON.read_text(encoding="utf-8"))
    except Exception:
        return None

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
    html.append("<!doctype html>")
    html.append("<html><head><meta charset='utf-8'>")
    html.append("<title>NestAI Secure Coding Report</title>")
    html.append(
        "<style>"
        "body{font-family:-apple-system,BlinkMacSystemFont,system-ui,Segoe UI,Roboto,"
        "Helvetica,Arial,sans-serif;background:#020617;color:#e5e7eb;padding:24px;}"
        "h1,h2,h3{color:#38bdf8;}"
        "code,pre{background:#020617;border-radius:6px;padding:8px;display:block;}"
        "table{border-collapse:collapse;width:100%;margin:16px 0;}"
        "th,td{border:1px solid #1f2937;padding:8px;font-size:14px;}"
        "th{background:#0f172a;text-align:left;}"
        ".badge{padding:2px 6px;border-radius:999px;font-size:12px;display:inline-block;}"
        ".low{background:#064e3b;color:#bbf7d0;}"
        ".medium{background:#78350f;color:#fed7aa;}"
        ".high{background:#7f1d1d;color:#fecaca;}"
        ".critical{background:#b91c1c;color:#fee2e2;}"
        ".card{background:#020617;border:1px solid #1f2937;border-radius:10px;"
        "padding:16px;margin-bottom:16px;}"
        ".section-title{margin-bottom:4px;}"
        "</style>"
    )
    html.append("</head><body>")

    html.append("<h1>NestAI – Secure Coding Report</h1>")

    if original_prompt:
        html.append("<div class='card'>")
        html.append("<h2 class='section-title'>Original Prompt</h2>")
        html.append(f"<pre>{original_prompt}</pre>")
        html.append("</div>")

    if final_prompt:
        html.append("<div class='card'>")
        html.append("<h2 class='section-title'>Final Secure Prompt</h2>")
        html.append(f"<pre>{final_prompt}</pre>")
        html.append("</div>")

    # Red Team
    if red_team_agents:
        html.append("<div class='card'>")
        html.append("<h2 class='section-title'>Red Team Findings</h2>")
        for agent in red_team_agents:
            a = agent or {}
            name = a.get("name", a.get("agent_name", "unknown"))
            parsed = (a.get("parsed") or {})
            severity = (parsed.get("severity", "unknown") or "unknown").lower()
            risks = parsed.get("risks", [])
            constraints = parsed.get("suggested_constraints", [])
            notes = parsed.get("notes", "")

            html.append("<div style='margin-bottom:12px;'>")
            html.append(
                f"<h3>{name} "
                f"<span class='badge {severity}'>{severity.upper()}</span></h3>"
            )

            if risks:
                html.append("<strong>Risks:</strong><ul>")
                for r in risks:
                    html.append(f"<li>{r}</li>")
                html.append("</ul>")

            if constraints:
                html.append("<strong>Suggested Constraints:</strong><ul>")
                for c in constraints:
                    html.append(f"<li>{c}</li>")
                html.append("</ul>")

            if notes:
                html.append(f"<p><strong>Notes:</strong> {notes}</p>")

            html.append("</div>")
        html.append("</div>")

    # Static Analysis
    html.append("<div class='card'>")
    html.append("<h2 class='section-title'>Static Analysis</h2>")

    def _render_static_block(title: str, info: Dict[str, Any]) -> None:
        risk = (info.get("overall_risk", "unknown") or "unknown").lower()
        summary = info.get("summary", "")
        issues = info.get("issues", [])

        html.append("<div style='margin-bottom:12px;'>")
        html.append(
            f"<h3>{title} "
            f"<span class='badge {risk}'>{risk.upper()}</span></h3>"
        )
        if summary:
            html.append(f"<p><strong>Summary:</strong> {summary}</p>")

        if issues:
            html.append("<table>")
            html.append("<tr><th>Tool</th><th>Rule</th><th>Message</th></tr>")
            for issue in issues:
                tool = issue.get("tool", "generic")
                rule_id = issue.get("rule_id", "")
                msg = issue.get("message", "")
                html.append(
                    f"<tr><td>{tool}</td><td>{rule_id}</td><td>{msg}</td></tr>"
                )
            html.append("</table>")
        html.append("</div>")

    _render_static_block("Prompt Static Analysis", static_prompt_info)
    _render_static_block("Generated Code Static Analysis", static_gen_info)

    html.append("</div>")  # end static card

    # Attack Simulation
    html.append("<div class='card'>")
    html.append("<h2 class='section-title'>Attack Simulation</h2>")
    sev = (attack_info.get("severity", "unknown") or "unknown").lower()
    html.append(
        f"<p><span class='badge {sev}'>"
        f"{sev.upper()}</span></p>"
    )
    weak_points = attack_info.get("weak_points", [])
    if weak_points:
        html.append("<ul>")
        for w in weak_points:
            html.append(f"<li>{w}</li>")
        html.append("</ul>")
    html.append("</div>")

    html.append("</body></html>")
    out_path.write_text("\n".join(html), encoding="utf-8")
    return out_path


def run_report_command(args: List[str], console: Console) -> None:
    """
    CLI entry for `nestai report ...`.
    Currently supports:
        nestai report html
    """
    if not args or args[0] != "html":
        console.print("[red]Usage:[/red] nestai report html")
        return

    path = generate_html_report_from_last()
    if not path:
        console.print("[red]No last result found to build a report.[/red]")
        return

    console.print(
        f"[green]HTML report generated:[/green] [bold]{path}[/bold]"
    )


# ─────────────────────────────────────────────────────────────────────────────
# CONSOLE / UI HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def get_console(theme: Optional[str]) -> Console:
    if theme == "light":
        return Console(highlight=False, style="black on white")
    return Console(highlight=False)


def gradient_title(text: str) -> Text:
    colors = ["cyan", "magenta", "blue", "bright_magenta", "bright_cyan"]
    t = Text()
    for i, ch in enumerate(text):
        t.append(ch, style=f"bold {colors[i % len(colors)]}")
    return t


def print_ascii_banner(console: Console, animated: bool = True) -> None:
    banner_lines = [
        " _   _        _     _     ___ ",
        "| \\ | |  ___ | |_  (_)   / _ \\",
        "|  \\| | / _ \\| __| | |  | | | |",
        "| |\\  ||  __/| |_  | |  | |_| |",
        "|_| \\_| \\___| \\__| |_|   \\___/",
    ]
    subtitle = "NESTAI – Secure Coding Pipeline"

    inner = Text()
    for line in banner_lines:
        inner.append(line + "\n", style="bold cyan")

    # FIX: Append newline as Text, then gradient title as Text
    inner.append("\n")
    inner.append(gradient_title(subtitle))

    panel = Panel(inner, box=box.ROUNDED, padding=(1, 4), border_style="bright_magenta")

    if not animated:
        console.print(panel)
        return

    with Live(panel, console=console, refresh_per_second=10):
        time.sleep(0.3)



# ─────────────────────────────────────────────────────────────────────────────
# RISK BADGE + SUMMARY TABLE
# ─────────────────────────────────────────────────────────────────────────────

def risk_badge(risk: str) -> Text:
    r = (risk or "unknown").lower()

    color_map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold blink bright_red",
    }
    color = color_map.get(r, "cyan")
    return Text(f" {r.upper()} ", style=f"bold {color} on black")


def pulsing_high_risk(console: Console, overall_risk: str) -> None:
    if overall_risk.lower() in {"high", "critical"}:
        console.print(
            Text(
                " !!! HIGH RISK: REVIEW BEFORE DEPLOYMENT !!! ",
                style="bold blink bright_red on black",
            )
        )


def build_summary_table(stages: List[Tuple[str, str, str, str]]) -> Table:
    table = Table(
        title="Pipeline Summary",
        expand=True,
        box=box.SIMPLE_HEAVY,
        header_style="bold bright_cyan",
    )
    table.add_column("Stage")
    table.add_column("Status")
    table.add_column("Time", justify="right")
    table.add_column("Risk / Notes")

    for stage, status, elapsed, risk in stages:
        badge = risk_badge(risk).plain if risk else ""
        table.add_row(stage, status, elapsed, f"{risk} {badge}")

    return table


def _safe_agent(agent: Any) -> Dict[str, Any]:
    try:
        return make_json_safe(agent)
    except Exception:
        return {"raw": repr(agent)}


# ─────────────────────────────────────────────────────────────────────────────
# PRINTING SECTIONS (AUTO-EXPANDED)
# ─────────────────────────────────────────────────────────────────────────────

def print_red_team(console: Console, agents: List[Any]) -> None:
    console.print(Rule("[bold red]Red Team Findings[/bold red]"))

    for agent in agents:
        a = _safe_agent(agent)
        name = a.get("name", a.get("agent_name", "unknown"))
        parsed = a.get("parsed", {})
        severity = parsed.get("severity", "unknown")
        risks = parsed.get("risks", [])
        constraints = parsed.get("suggested_constraints", [])
        notes = parsed.get("notes", "")

        header = Text(name, style="bold white")
        header.append("  ")
        header.append(risk_badge(severity))
        console.print(Panel.fit(header, border_style="red", box=box.ROUNDED))

        if risks:
            console.print("  [bold]Risks:[/bold]")
            for r in risks:
                console.print(f"   • {r}")

        if constraints:
            console.print("  [bold]Suggested Constraints:[/bold]")
            for c in constraints:
                console.print(f"   • {c}")

        if notes:
            console.print("  [bold]Notes:[/bold] " + notes)

        console.print()


def print_static(console: Console, static_prompt: Any, static_gen: Any) -> None:
    console.print(Rule("[bold cyan]Static Analysis[/bold cyan]"))

    def show(label: str, data: Any):
        if not data:
            return
        a = _safe_agent(data)
        parsed = a.get("parsed", {})
        summary = parsed.get("summary", "")
        risk = parsed.get("overall_risk", "unknown")
        issues = parsed.get("issues", [])

        header = Text(label, style="bold white")
        header.append("  ")
        header.append(risk_badge(risk))
        console.print(Panel.fit(header, border_style="cyan", box=box.ROUNDED))

        if summary:
            console.print("  [bold]Summary:[/bold] " + summary)

        for issue in issues:
            console.print(
                f"   • [{issue.get('tool', 'generic')}] "
                f"{issue.get('message','')} "
                f"({issue.get('rule_id','')})"
            )
        console.print()

    show("Prompt Static Analysis", static_prompt)
    show("Generated Code Static Analysis", static_gen)


def print_attack(console: Console, attack_result: Any) -> None:
    console.print(Rule("[bold magenta]Attack Simulation[/bold magenta]"))

    a = _safe_agent(attack_result)
    parsed = a.get("parsed", {})
    severity = parsed.get("severity", "unknown")
    weak = parsed.get("weak_points", [])

    header = Text("attack_simulation", style="bold white")
    header.append("  ")
    header.append(risk_badge(severity))
    console.print(Panel.fit(header, border_style="magenta", box=box.ROUNDED))

    if weak:
        console.print("  [bold]Weak Points:[/bold]")
        for w in weak:
            console.print(f"   • {w}")
    console.print()


def print_malicious(console: Console, mal: Any) -> None:
    console.print(Rule("[bold yellow]Malicious Intent Agent[/bold yellow]"))
    a = _safe_agent(mal)
    parsed = a.get("parsed", {})
    blocked = parsed.get("malicious_agent_blocked", parsed.get("malicious", False))
    reasons = parsed.get("reasons", [])
    message = parsed.get("block_message", "")

    severity = "critical" if blocked else "low"

    header = Text("malicious_red", style="bold white")
    header.append("  ")
    header.append(risk_badge(severity))
    console.print(Panel.fit(header, border_style="yellow", box=box.ROUNDED))

    console.print(f"  [bold]Status:[/bold] {'BLOCKED' if blocked else 'Allowed'}")
    if message:
        console.print(f"  [bold]Message:[/bold] {message}")

    if reasons:
        console.print("  [bold]Reasons:[/bold]")
        for r in reasons:
            console.print(f"   • {r}")
    console.print()


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE RUNNER WITH REITERATION LOOP
# ─────────────────────────────────────────────────────────────────────────────

def run_pipeline_with_ui(
    console: Console,
    user_prompt: str,
    minimal: bool = False,
    verbose: bool = False,   # kept but unused (auto-expand always)
) -> None:
    _ensure_dirs()
    print_ascii_banner(console, animated=not minimal)
    console.print()

    current_prompt = user_prompt
    iteration = 1

    while True:
        console.print(f"[bold]Iteration {iteration} – Running Pipeline[/bold]")
        console.print(f"[cyan]Prompt:[/cyan] {current_prompt}\n")

        # Run full pipeline
        with console.status("[cyan]Running NestAI pipeline…[/cyan]", spinner="dots"):
            start = time.time()
            result = run_nestai(current_prompt)
            end = time.time()

        result = make_json_safe(result)
        save_last_result(result)

        static_prompt = result.get("static_agent")
        static_generated = result.get("static_generated_agent")
        attack_result = result.get("attack_result")

        # Stage timings
        total_time = end - start
        stages = [
            "Static Analysis",
            "Red Team",
            "Malicious Gate",
            "Blue Team",
            "Controller",
            "Codegen",
            "Attack Simulation",
        ]
        per = max(total_time / max(len(stages), 1), 0.01)
        rows: List[Tuple[str, str, str, str]] = []

        static_risk = ((static_prompt or {}).get("parsed") or {}).get(
            "overall_risk", "medium"
        )
        attack_risk = ((attack_result or {}).get("parsed") or {}).get(
            "severity", "medium"
        )

        stage_risks = {
            "Static Analysis": static_risk,
            "Red Team": "aggregated",
            "Malicious Gate": "-",
            "Blue Team": "-",
            "Controller": "-",
            "Codegen": "-",
            "Attack Simulation": attack_risk,
        }

        for i, st in enumerate(stages):
            rows.append(
                (
                    st,
                    "Done",
                    f"{per * (i + 1):.2f}s",
                    stage_risks.get(st, ""),
                )
            )

        console.print()
        console.print(build_summary_table(rows))
        console.print()

        # Overall risk
        risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        sr = static_risk.lower()
        ar = attack_risk.lower()
        overall = sr if risk_rank.get(sr, 0) >= risk_rank.get(ar, 0) else ar

        console.print(f"Overall risk: {risk_badge(overall)}\n")
        pulsing_high_risk(console, overall)

        # Auto-expand sections
        print_red_team(console, result.get("red_team_agents", []))
        print_static(console, static_prompt, static_generated)
        print_attack(console, attack_result)
        print_malicious(console, result.get("malicious_agent"))

        # Final Secure Prompt
        final_prompt = result.get("final_prompt", "")
        console.print(Rule("[bold bright_cyan]Final Secure Prompt[/bold bright_cyan]"))
        console.print(Panel(final_prompt, border_style="bright_cyan"))
        console.print()

        # If blocked: stop
        if not result.get("allowed", True):
            console.print("[red]Pipeline blocked. No code generated.[/red]")
            return

        # ─────────────────────────────────────────────────────────────
        # ITERATION LOOP
        # ─────────────────────────────────────────────────────────────

        answer = Prompt.ask(
            "[yellow]Do you want to make changes and/or make tradeoffs?[/yellow]",
            choices=["y", "n"],
            default="n",
        )

        if answer == "n":
            # Final iteration → do codegen & preview
            code = result.get("code", "")
            if code.strip():
                path = save_generated_code(code)
                handle_code_preview(console, code, path, minimal=minimal)
            else:
                console.print("[yellow]No code was generated.[/yellow]")
            return

        # User wants to modify prompt
        console.print(
            "\n[cyan]Enter your modifications. "
            "Press ENTER on an empty line to finish.[/cyan]\n"
        )

        new_lines: List[str] = []
        while True:
            try:
                line = input()
            except EOFError:
                break

            if line.strip() == "":
                break

            new_lines.append(line)

        user_edits = "\n".join(new_lines).strip()

        if not user_edits:
            console.print(
                "[yellow]No changes entered. Keeping existing secure prompt.[/yellow]\n"
            )
            # Re-run with same final prompt
            current_prompt = final_prompt or current_prompt
        else:
            console.print(
                "[green]Applying your changes and re-running pipeline…[/green]\n"
            )
            combined = (
                (final_prompt or current_prompt).strip()
                + "\n\n# User modifications:\n"
                + user_edits.strip()
            )
            current_prompt = combined

        iteration += 1


# ─────────────────────────────────────────────────────────────────────────────
# CLI ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="nestai",
        description="NestAI – Secure Code Multi-Agent System",
    )
    parser.add_argument("--minimal", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--theme", choices=["dark", "light"], default=None)
    parser.add_argument("command", nargs="+")
    args = parser.parse_args(argv)

    console = get_console(args.theme)
    cmd = args.command
    sub = cmd[0]

    if sub == "history":
        run_history_command(cmd[1:])
        return

    if sub == "config":
        run_config_command(cmd[1:], console)
        return

    if sub == "report":
        run_report_command(cmd[1:], console)
        return

    # Treat remaining as the user prompt
    user_prompt = " ".join(cmd)
    try:
        run_pipeline_with_ui(
            console=console,
            user_prompt=user_prompt,
            minimal=args.minimal,
            verbose=args.verbose,
        )
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(130)


if __name__ == "__main__":
    main()

