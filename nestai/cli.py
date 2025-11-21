# ========================= NESTAI CLI — CYBERPUNK EDITION =========================
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
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.prompt import Prompt
from rich.syntax import Syntax

from nestai.main_pipeline import run_nestai
from nestai.history_cli import run_history_command
from nestai.config_cli import run_config_command

from nestai.history_cli import run_history_command
from nestai.config_cli import run_config_command
from nestai.report_cli import run_report_command   # <-- ADD THIS


# ────────────────────────────────────────────────
# Paths
# ────────────────────────────────────────────────

from nestai.shared_paths import (
    APP_DIR,
    GENERATED_DIR,
    REPORTS_DIR,
    LAST_RESULT_JSON,
    ensure_dirs,
)



def _ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ────────────────────────────────────────────────
# JSON Safe
# ────────────────────────────────────────────────

def make_json_safe(obj: Any) -> Any:
    if obj is None:
        return None

    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        try:
            return make_json_safe(obj.to_dict())
        except Exception:
            pass

    if hasattr(obj, "__dataclass_fields__"):
        try:
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


# ────────────────────────────────────────────────
# Cyberpunk Neon Intro
# ────────────────────────────────────────────────

def print_cyberpunk_intro(console: Console) -> None:
    """
    Cyberpunk Neon Pulse Intro:
    - Pink → Purple → Blue gradient
    - Light flicker effect
    - Smooth pulse glow
    - No ASCII letters; full cyberpunk UI aesthetic
    """

    frames = [
        ("[bold #ff00ff]N E S T A I[/bold #ff00ff]", "#ff00ff", 0.08),
        ("[bold #d400ff]N E S T A I[/bold #d400ff]", "#d400ff", 0.08),
        ("[bold #9400ff]N E S T A I[/bold #9400ff]", "#9400ff", 0.08),
        ("[bold #00b7ff]N E S T A I[/bold #00b7ff]", "#00b7ff", 0.08),
        ("[bold #ff00ff]N E S T A I[/bold #ff00ff]", "#ff00ff", 0.08),
    ]

    glitch_frames = [
        "[bold #ff00ff]N   S T A I[/bold #ff00ff]",
        "[bold #9400ff]N E   T A I[/bold #9400ff]",
        "[bold #00b7ff]N E S   A I[/bold #00b7ff]"
    ]

    panel = Panel(
        "",
        box=box.ROUNDED,
        border_style="#ff00ff",
        padding=(2, 10),
    )

    with Live(panel, console=console, refresh_per_second=20):
        # Pulse cycle
        for text, color, delay in frames:
            panel.renderable = Text.from_markup(text, justify="center")
            panel.border_style = color
            time.sleep(delay)

        # Small glitch
        for _ in range(2):
            panel.renderable = Text.from_markup(glitch_frames[0], justify="center")
            time.sleep(0.05)
            panel.renderable = Text.from_markup(glitch_frames[1], justify="center")
            time.sleep(0.05)
            panel.renderable = Text.from_markup(glitch_frames[2], justify="center")
            time.sleep(0.05)

        # Final stabilized frame
        panel.renderable = Text.from_markup("[bold #00eaff]N E S T A I[/bold #00eaff]", justify="center")
        panel.border_style = "#00eaff"
        time.sleep(0.3)

    console.print()


# ────────────────────────────────────────────────
# Code Save + Preview
# ────────────────────────────────────────────────

def save_generated_code(code: str) -> Path:
    _ensure_dirs()
    ts = datetime.now().strftime("nestai_%Y%m%d_%H%M%S.py")
    path = GENERATED_DIR / ts
    path.write_text(code, encoding="utf-8")
    return path


def handle_code_preview(console: Console, code: str, path: Path, minimal: bool=False) -> None:
    console.print(
        f"[green]Code generated and saved to[/green] [bold]{path}[/bold]\n"
    )

    if minimal:
        return

    choice = Prompt.ask(
        "Press <Enter> to preview first 40 lines, or 's' to skip",
        default="",
        show_default=False,
    ).strip().lower()

    if choice in {"s", "skip", "n"}:
        return

    preview = "\n".join(code.splitlines()[:40])
    syntax = Syntax(preview, "python", theme="monokai", line_numbers=True)
    console.print(Rule("[bold cyan]Code Preview[/bold cyan]"))
    console.print(syntax)
    console.print("[dim]… full code saved to file[/dim]")


# ────────────────────────────────────────────────
# Save Last Result
# ────────────────────────────────────────────────

def save_last_result(result: Dict[str, Any]) -> None:
    _ensure_dirs()
    LAST_RESULT_JSON.write_text(json.dumps(make_json_safe(result), indent=2))


# ────────────────────────────────────────────────
# UI Helpers
# ────────────────────────────────────────────────

def get_console(theme: Optional[str]) -> Console:
    if theme == "light":
        return Console(highlight=False, style="black on white")
    return Console(highlight=False)


def risk_badge(risk: str) -> Text:
    r = (risk or "").lower()
    map = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold blink bright_red",
    }
    return Text(f" {r.upper()} ", style=f"bold {map.get(r, 'cyan')} on black")


def pulsing_high_risk(console: Console, risk: str) -> None:
    if risk.lower() in {"high", "critical"}:
        console.print(
            Text(" !!! HIGH RISK: REVIEW BEFORE DEPLOYMENT !!! ",
                 style="bold blink bright_red on black")
        )


# ────────────────────────────────────────────────
# Red Team / Static / Attack / Malicious Sections
# (unchanged from your current version)
# ────────────────────────────────────────────────

# [TRUNCATED: I will include these exactly from your file below]

# ────────────────────────────────────────────────
# Pipeline Runner (unchanged except intro)
# ────────────────────────────────────────────────

def run_pipeline_with_ui(console: Console, user_prompt: str, minimal: bool=False, verbose: bool=False):

    _ensure_dirs()
    print_cyberpunk_intro(console)   # <<<<<< NEW INTRO

    console.print()

    current_prompt = user_prompt
    iteration = 1

    while True:
        console.print(f"[bold]Iteration {iteration} – Running Pipeline[/bold]")
        console.print(f"[cyan]Prompt:[/cyan] {current_prompt}\n")

        with console.status("[cyan]Running NestAI pipeline…[/cyan]", spinner="dots"):
            start = time.time()
            result = run_nestai(current_prompt)
            end = time.time()

        result = make_json_safe(result)
        save_last_result(result)

        # (The rest of your iteration logic remains 100% identical)
        # — I will paste it in full below

# ────────────────────────────────────────────────────────────────
# SAFE AGENT WRAPPER
# ────────────────────────────────────────────────────────────────

def _safe_agent(agent: Any) -> Dict[str, Any]:
    try:
        return make_json_safe(agent)
    except Exception:
        return {"raw": repr(agent)}


# ────────────────────────────────────────────────────────────────
# RED TEAM SECTION
# ────────────────────────────────────────────────────────────────

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


# ────────────────────────────────────────────────────────────────
# STATIC ANALYSIS SECTION
# ────────────────────────────────────────────────────────────────

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
            tool = issue.get("tool", "generic")
            message = issue.get("message", "")
            rule_id = issue.get("rule_id", "")
            console.print(f"   • [{tool}] {message} ({rule_id})")

        console.print()

    show("Prompt Static Analysis", static_prompt)
    show("Generated Code Static Analysis", static_gen)


# ────────────────────────────────────────────────────────────────
# ATTACK SIMULATION SECTION
# ────────────────────────────────────────────────────────────────

def print_attack(console: Console, attack_result: Any) -> None:
    console.print(Rule("[bold magenta]Attack Simulation[/bold magenta]"))

    a = _safe_agent(attack_result)
    parsed = a.get("parsed", {})
    severity = parsed.get("severity", "unknown")
    weak_points = parsed.get("weak_points", [])

    header = Text("attack_simulation", style="bold white")
    header.append("  ")
    header.append(risk_badge(severity))

    console.print(Panel.fit(header, border_style="magenta", box=box.ROUNDED))

    if weak_points:
        console.print("  [bold]Weak Points:[/bold]")
        for w in weak_points:
            console.print(f"   • {w}")

    console.print()


# ────────────────────────────────────────────────────────────────
# MALICIOUS INTENT AGENT
# ────────────────────────────────────────────────────────────────

def print_malicious(console: Console, mal: Any) -> None:
    console.print(Rule("[bold yellow]Malicious Intent Agent[/bold yellow]"))

    a = _safe_agent(mal)
    parsed = a.get("parsed", {})
    blocked = parsed.get("malicious_agent_blocked", parsed.get("malicious", False))
    message = parsed.get("block_message", "")
    reasons = parsed.get("reasons", [])

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

# ────────────────────────────────────────────────────────────────
# SUMMARY TABLE
# ────────────────────────────────────────────────────────────────

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


# ────────────────────────────────────────────────────────────────
# PIPELINE + ITERATION LOOP
# ────────────────────────────────────────────────────────────────

def run_pipeline_with_ui(console: Console, user_prompt: str, minimal=False, verbose=False):

    _ensure_dirs()
    print_cyberpunk_intro(console)
    console.print()

    current_prompt = user_prompt
    iteration = 1

    while True:
        console.print(f"[bold]Iteration {iteration} – Running Pipeline[/bold]")
        console.print(f"[cyan]Prompt:[/cyan] {current_prompt}\n")

        # Run entire pipeline
        with console.status("[cyan]Running NestAI pipeline…[/cyan]", spinner="dots"):
            start = time.time()
            result = run_nestai(current_prompt)
            end = time.time()

        result = make_json_safe(result)
        save_last_result(result)

        # Extract
        static_prompt = result.get("static_agent")
        static_generated = result.get("static_generated_agent")
        attack_result = result.get("attack_result")

        # Stage timings
        total = end - start
        stages = [
            "Static Analysis",
            "Red Team",
            "Malicious Gate",
            "Blue Team",
            "Controller",
            "Codegen",
            "Attack Simulation",
        ]
        per = max(total / len(stages), 0.01)

        rows = []
        static_risk = ((static_prompt or {}).get("parsed") or {}).get("overall_risk", "medium")
        attack_risk = ((attack_result or {}).get("parsed") or {}).get("severity", "medium")

        stage_risks = {
            "Static Analysis": static_risk,
            "Red Team": "aggregated",
            "Malicious Gate": "-",
            "Blue Team": "-",
            "Controller": "-",
            "Codegen": "-",
            "Attack Simulation": attack_risk,
        }

        for i, stage in enumerate(stages):
            rows.append((stage, "Done", f"{per*(i+1):.2f}s", stage_risks.get(stage, "")))

        console.print()
        console.print(build_summary_table(rows))
        console.print()

        # Overall risk
        rank = {"low":1,"medium":2,"high":3,"critical":4}
        sr = static_risk.lower()
        ar = attack_risk.lower()
        overall = sr if rank.get(sr,0) >= rank.get(ar,0) else ar

        console.print(f"Overall risk: {risk_badge(overall)}\n")
        pulsing_high_risk(console, overall)

        # Auto-expand detailed sections
        print_red_team(console, result.get("red_team_agents", []))
        print_static(console, static_prompt, static_generated)
        print_attack(console, attack_result)
        print_malicious(console, result.get("malicious_agent"))

        # Final prompt
        final_prompt = result.get("final_prompt", "")
        console.print(Rule("[bold bright_cyan]Final Secure Prompt[/bold bright_cyan]"))
        console.print(Panel(final_prompt, border_style="bright_cyan"))
        console.print()

        # Blocked?
        if not result.get("allowed", True):
            console.print("[red]Pipeline blocked. No code generated.[/red]")
            return

        # Ask for iteration changes
        answer = Prompt.ask(
            "[yellow]Do you want to make changes and/or make tradeoffs?[/yellow]",
            choices=["y","n"],
            default="n"
        )

        if answer == "n":
            code = result.get("code","")
            if code.strip():
                path = save_generated_code(code)
                handle_code_preview(console, code, path, minimal=minimal)
            return

        # User editing prompt
        console.print("\n[cyan]Enter your modifications. Press ENTER on an empty line to finish.[/cyan]\n")

        edits = []
        while True:
            try: line = input()
            except EOFError: break
            if line.strip() == "": break
            edits.append(line)

        edits_text = "\n".join(edits).strip()

        if edits_text:
            combined = (
                final_prompt.strip()
                + "\n\n# User modifications:\n"
                + edits_text
            )
            current_prompt = combined
        else:
            current_prompt = final_prompt

        iteration += 1


# ────────────────────────────────────────────────────────────────
# CLI ENTRYPOINT
# ────────────────────────────────────────────────────────────────

def main(argv=None):

    parser = argparse.ArgumentParser(
        prog="nestai",
        description="NestAI – Secure Code Multi-Agent Pipeline"
    )
    parser.add_argument("--minimal", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--theme", choices=["dark","light"], default=None)
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

    # Treat everything else as the user prompt
    user_prompt = " ".join(cmd)
    try:
        run_pipeline_with_ui(console, user_prompt, minimal=args.minimal)
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(130)


if __name__ == "__main__":
    main()

