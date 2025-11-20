# nestai/cli.py
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from rich.rule import Rule

from nestai.main_pipeline import run_nestai
from nestai.models import make_json_safe


APP_DIR = Path.home() / ".nestai"
GENERATED_DIR = APP_DIR / "generated"
LAST_RESULT_JSON = APP_DIR / "last_result.json"


def _ensure_dirs():
    APP_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)


def save_code(code: str) -> Path:
    _ensure_dirs()
    ts = datetime.now().strftime("generated_%Y%m%d_%H%M%S.py")
    p = GENERATED_DIR / ts
    p.write_text(code)
    return p


def risk_badge(r: str) -> Text:
    r = r.lower()
    colors = {
        "low": "green",
        "medium": "yellow",
        "high": "red",
        "critical": "bold bright_red",
    }
    return Text(f" {r.upper()} ", style=f"bold {colors.get(r, 'magenta')} on black")


# ---------------------- Render Sections -------------------------

def print_red(console: Console, agents: List[Dict[str, Any]]):
    console.print(Rule("[bold red]RED TEAM FINDINGS[/bold red]"))
    for a in agents:
        name = a.get("name")
        parsed = a.get("parsed", {})
        header = Text(name, style="bold white")
        header.append("  ")
        header.append(risk_badge(parsed.get("severity", "medium")))
        console.print(Panel(header, border_style="red"))

        for r in parsed.get("risks", []):
            console.print(f" • {r}")

        for c in parsed.get("suggested_constraints", []):
            console.print(f"   [cyan]Constraint:[/cyan] {c}")

        if parsed.get("notes"):
            console.print(f"[dim]{parsed['notes']}[/dim]")

        console.print()


def print_static(console: Console, static_prompt, static_gen):
    console.print(Rule("[bold cyan]STATIC ANALYSIS[/bold cyan]"))

    def _p(label, d):
        header = Text(label, style="bold white")
        header.append("  ")
        header.append(risk_badge(d.get("parsed", {}).get("overall_risk", "medium")))
        console.print(Panel(header, border_style="cyan"))
        for issue in d.get("parsed", {}).get("issues", []):
            console.print(f" - [{issue.get('tool')}] {issue.get('message')} ({issue.get('rule_id')})")

        console.print()

    if static_prompt:
        _p("Prompt Static Analysis", static_prompt)
    if static_gen:
        _p("Generated Code Static Analysis", static_gen)


def print_attack(console: Console, a: Dict[str, Any]):
    console.print(Rule("[bold magenta]ATTACK SIMULATION[/bold magenta]"))
    header = Text("attack_simulation", style="bold white")
    header.append("  ")
    header.append(risk_badge(a.get("parsed", {}).get("severity", "medium")))
    console.print(Panel(header, border_style="magenta"))

    for w in a.get("parsed", {}).get("weak_points", []):
        console.print(f" - Weak Point: {w}")

    for s in a.get("parsed", {}).get("simulated_attacks", []):
        console.print(f" - Attack Path: {s}")

    console.print()


# ------------------------- Main Runner --------------------------

def run_pipeline(console: Console, user_prompt: str):
    _ensure_dirs()
    console.print(f"[bold]Original Prompt:[/bold] {user_prompt}\n")

    console.print("[cyan]Running pipeline...[/cyan]")
    start = time.time()
    result = make_json_safe(run_nestai(user_prompt))
    end = time.time()

    console.print(f"[green]Pipeline finished in {end - start:.2f}s[/green]")

    # Always auto-expand sections
    print_red(console, result.get("red_team_agents", []))
    print_static(console, result.get("static_agent"), result.get("static_generated_agent"))

    if result.get("attack_result"):
        print_attack(console, result.get("attack_result"))

    # Print final prompt
    console.print(Rule("[bold bright_cyan]FINAL SECURE PROMPT[/bold bright_cyan]"))
    console.print(
        Panel(
            result.get("final_prompt", "[no final prompt]"),
            border_style="bright_cyan"
        )
    )

    # Save code
    code = result.get("code", "")
    if code:
        path = save_code(code)
        console.print(f"[green]Code saved to {path}[/green]")
        console.print(Syntax(code, "python"))


def main():
    parser = argparse.ArgumentParser(prog="nestai")
    parser.add_argument("prompt", nargs="+")
    args = parser.parse_args()

    console = Console()
    prompt = " ".join(args.prompt)
    run_pipeline(console, prompt)


if __name__ == "__main__":
    main()
