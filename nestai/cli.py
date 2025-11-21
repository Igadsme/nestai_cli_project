from __future__ import annotations

import argparse
import json
import sys
import time
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
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from nestai.main_pipeline import run_nestai
from nestai.history_cli import run_history_command
from nestai.config_cli import run_config_command  # keep if you already have it
from nestai.models import make_json_safe

APP_DIR = Path.home() / ".nestai"
GENERATED_DIR = APP_DIR / "generated"
REPORTS_DIR = APP_DIR / "reports"
LAST_RESULT_JSON = APP_DIR / "last_result.json"


def _ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Console helpers
# ---------------------------------------------------------------------------

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
    inner.append("\n")
    inner.append(gradient_title(subtitle))

    panel = Panel(inner, box=box.ROUNDED, padding=(1, 4), border_style="bright_magenta")

    if not animated:
        console.print(panel)
        return

    with Live(panel, console=console, refresh_per_second=10):
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# Risk badge, helpers
# ---------------------------------------------------------------------------

def risk_badge(risk: str) -> Text:
    r = (risk or "").lower()
    base = r.upper() if r else "UNKNOWN"

    if r == "low":
        color = "green"
    elif r == "medium":
        color = "yellow"
    elif r == "high":
        color = "red"
    elif r == "critical":
        color = "bold blink bright_red"
    else:
        color = "cyan"

    return Text(f" {base} ", style=f"bold {color} on black")


def pulsing_high_risk(console: Console, overall_risk: str) -> None:
    if overall_risk.lower() not in {"high", "critical"}:
        return
    text = Text(
        " !!! HIGH RISK: REVIEW BEFORE DEPLOYMENT !!! ",
        style="bold blink bright_red on black",
    )
    console.print(text)


def _safe_agent_dict(agent: Any) -> Dict[str, Any]:
    return make_json_safe(agent)


def build_summary_table(stages: List[Tuple[str, str, str, str]]) -> Table:
    table = Table(
        title="Pipeline Summary",
        box=box.SIMPLE_HEAVY,
        expand=True,
        header_style="bold bright_cyan",
    )
    table.add_column("Stage", style="bold white")
    table.add_column("Status", style="bold green")
    table.add_column("Time", justify="right", style="cyan")
    table.add_column("Risk / Notes", style="magenta")

    for stage, status, elapsed, risk in stages:
        badge = risk_badge(risk).plain if risk else ""
        table.add_row(stage, status, elapsed, f"{risk} {badge}".strip())

    return table


# ---------------------------------------------------------------------------
# Printing sections
# ---------------------------------------------------------------------------

def print_red_team_section(console: Console, red_team_agents: List[Any]) -> None:
    console.print(Rule("[bold red]Red Team Findings[/bold red]"))
    for agent in red_team_agents:
        a = _safe_agent_dict(agent)
        name = a.get("name", a.get("agent_name", "unknown"))
        parsed = a.get("parsed", {}) or {}
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
            console.print("  [bold]Suggested constraints:[/bold]")
            for c in constraints:
                console.print(f"   • {c}")
        if notes:
            console.print("  [bold]Notes:[/bold] " + notes)
        console.print()


def print_blue_team_section(console: Console, blue_team_agents: List[Any]) -> None:
    if not blue_team_agents:
        return
    console.print(Rule("[bold blue]Blue Team Defensive Rewrites[/bold blue]"))
    for agent in blue_team_agents:
        a = _safe_agent_dict(agent)
        name = a.get("name", a.get("agent_name", "unknown"))
        parsed = a.get("parsed", {}) or {}
        rewritten = parsed.get("rewritten_prompt", "")
        constraints = parsed.get("constraints", [])
        notes = parsed.get("notes", "")

        header = Text(name, style="bold white")
        header.append("  [BLUE]")
        console.print(Panel.fit(header, border_style="blue", box=box.ROUNDED))

        if rewritten:
            console.print("  [bold]Rewritten prompt (excerpt):[/bold]")
            console.print("   " + rewritten[:200] + ("..." if len(rewritten) > 200 else ""))

        if constraints:
            console.print("  [bold]Enforced constraints:[/bold]")
            for c in constraints:
                console.print(f"   • {c}")
        if notes:
            console.print("  [bold]Notes:[/bold] " + notes)
        console.print()


def print_static_section(console: Console, static_prompt: Any, static_generated: Any) -> None:
    console.print(Rule("[bold cyan]Static Analysis[/bold cyan]"))

    def _print_one(label: str, data: Any) -> None:
        if not data:
            return
        a = _safe_agent_dict(data)
        parsed = a.get("parsed", {}) or {}
        summary = parsed.get("summary", "")
        risk = parsed.get("overall_risk", "unknown")
        issues = parsed.get("issues", [])

        header = Text(label, style="bold white")
        header.append("  ")
        header.append(risk_badge(risk))
        console.print(Panel.fit(header, border_style="cyan", box=box.ROUNDED))

        if summary:
            console.print(f"  [bold]Summary:[/bold] {summary}")

        for issue in issues:
            tool = issue.get("tool", "generic")
            msg = issue.get("message", "")
            rule_id = issue.get("rule_id", "")
            console.print(f"   • [{tool}] {msg} ({rule_id})")

        console.print()

    _print_one("Prompt Static Analysis", static_prompt)
    _print_one("Generated Code Static Analysis", static_generated)


def print_attack_sim_section(console: Console, attack_result: Any) -> None:
    if not attack_result:
        return
    console.print(Rule("[bold magenta]Attack Simulation[/bold magenta]"))

    a = _safe_agent_dict(attack_result)
    parsed = a.get("parsed", {}) or {}
    risk = parsed.get("severity", "unknown")
    weak_points = parsed.get("weak_points", [])
    sims = parsed.get("simulated_attacks", [])

    header = Text("attack_simulation", style="bold white")
    header.append("  ")
    header.append(risk_badge(risk))
    console.print(Panel.fit(header, border_style="magenta", box=box.ROUNDED))

    if sims:
        console.print("  [bold]Simulated attacks:[/bold]")
        for s in sims:
            console.print(f"   • {s}")

    if weak_points:
        console.print("  [bold]Weak points:[/bold]")
        for w in weak_points:
            console.print(f"   • {w}")
    console.print()


def print_malicious_section(console: Console, malicious_agent: Any) -> None:
    if not malicious_agent:
        return
    console.print(Rule("[bold yellow]Malicious Intent Agent[/bold yellow]"))

    a = _safe_agent_dict(malicious_agent)
    parsed = a.get("parsed", {}) or {}
    blocked = parsed.get("malicious_agent_blocked", parsed.get("malicious", False))
    reasons = parsed.get("reasons", [])
    block_message = parsed.get(
        "block_message",
        "Request considered safe (no malicious intent detected).",
    )

    severity = "critical" if blocked else "low"
    header = Text("malicious_red", style="bold white")
    header.append("  ")
    header.append(risk_badge(severity))
    console.print(Panel.fit(header, border_style="yellow", box=box.ROUNDED))

    console.print(f"  [bold]Status:[/bold] {'BLOCKED' if blocked else 'Allowed'}")
    console.print(f"  [bold]Message:[/bold] {block_message}")
    if reasons:
        console.print("  [bold]Reasons:[/bold]")
        for r in reasons:
            console.print(f"   • {r}")
    console.print()


# ---------------------------------------------------------------------------
# Save result + HTML report
# ---------------------------------------------------------------------------

def save_last_result(result: Dict[str, Any]) -> None:
    _ensure_dirs()
    safe = make_json_safe(result)
    LAST_RESULT_JSON.write_text(json.dumps(safe, indent=2), encoding="utf-8")


def generate_html_report_from_last() -> Optional[Path]:
    if not LAST_RESULT_JSON.exists():
        return None

    data = json.loads(LAST_RESULT_JSON.read_text(encoding="utf-8"))

    ts = datetime.now().strftime("nestai_report_%Y%m%d_%H%M%S.html")
    out = REPORTS_DIR / ts

    html: List[str] = []
    html.append("<!doctype html>")
    html.append("<html><head><meta charset='utf-8'>")
    html.append("<title>NESTAI Secure Coding Report</title>")
    html.append("<style>")
    html.append("body{font-family:sans-serif;background:#050816;color:#f8fafc;padding:20px;}")
    html.append("h1,h2{color:#38bdf8;} table{border-collapse:collapse;width:100%;margin-bottom:20px;}")
    html.append("th,td{border:1px solid #1f2937;padding:8px;} th{background:#111827;}")
    html.append(".badge{padding:2px 6px;border-radius:6px;font-size:0.8rem;}")
    html.append(".low{background:#064e3b;color:#ecfdf5;}")
    html.append(".medium{background:#78350f;color:#ffedd5;}")
    html.append(".high{background:#7f1d1d;color:#fee2e2;}")
    html.append(".critical{background:#b91c1c;color:#fee2e2;}")
    html.append("</style></head><body>")
    html.append("<h1>NESTAI – Secure Coding Report</h1>")
    html.append(f"<p><strong>Original prompt:</strong> {data.get('original_prompt','')}</p>")
    html.append("<h2>Final Secure Prompt</h2>")
    html.append("<pre>" + (data.get("final_prompt") or "") + "</pre>")
    html.append("</body></html>")

    out.write_text("\n".join(html), encoding="utf-8")
    return out


def run_report_command(args: List[str], console: Console) -> None:
    if not args or args[0] != "html":
        console.print("[red]Usage:[/red] nestai report html")
        return
    path = generate_html_report_from_last()
    if not path:
        console.print("[red]No last result found.[/red]")
        return
    console.print(f"[green]HTML report generated:[/green] [bold]{path}[/bold]")


# ---------------------------------------------------------------------------
# Code saving + preview
# ---------------------------------------------------------------------------

def save_generated_code(code: str) -> Path:
    _ensure_dirs()
    ts = datetime.now().strftime("generated_%Y%m%d_%H%M%S.py")
    path = GENERATED_DIR / ts
    path.write_text(code, encoding="utf-8")
    return path


def handle_code_preview(console: Console, code: str, path: Path, minimal: bool = False) -> None:
    console.print(
        f"[green]Code generated and saved to[/green] [bold]{path}[/bold]\n"
        "[cyan]You can open this file in your editor at any time.[/cyan]\n"
    )
    if minimal:
        return

    preview = "\n".join(code.splitlines()[:40])
    syntax = Syntax(preview, "python", theme="monokai", line_numbers=True)
    console.print(Rule("[bold green]Generated Code Preview (first ~40 lines)[/bold green]"))
    console.print(syntax)
    console.print("[dim]… full code available in the saved file above.[/dim]")


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def run_pipeline_with_ui(
    console: Console,
    user_prompt: str,
    minimal: bool = False,
    verbose: bool = False,  # kept for compatibility; we auto-expand anyway
) -> None:
    _ensure_dirs()

    console.print()
    print_ascii_banner(console, animated=not minimal)
    console.print()
    console.print(f"[bold]Original Prompt:[/bold] {user_prompt}\n")

    with console.status("[cyan]Running NestAI secure pipeline…[/cyan]", spinner="dots"):
        start = time.time()
        result_raw: Dict[str, Any] = run_nestai(user_prompt)
        result: Dict[str, Any] = make_json_safe(result_raw)
        end = time.time()

    save_last_result(result)

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

    static_agent = result.get("static_agent")
    static_gen = result.get("static_generated_agent")
    attack_result = result.get("attack_result")

    static_risk = ((static_agent or {}).get("parsed") or {}).get("overall_risk", "medium")
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

    stage_rows: List[Tuple[str, str, str, str]] = []
    for idx, stage in enumerate(stages):
        stage_rows.append(
            (
                stage,
                "Done",
                f"{per * (idx + 1):.2f}s",
                str(stage_risks.get(stage, "")),
            )
        )

    if not minimal:
        progress = Progress(
            SpinnerColumn(style="bright_cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=True,
        )
        with progress:
            t = progress.add_task("[cyan]Finalizing results…", total=len(stages))
            for _ in stages:
                time.sleep(0.08)
                progress.advance(t)

    console.print()
    console.print(build_summary_table(stage_rows))
    console.print()

    risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    sr = static_risk.lower()
    ar = attack_risk.lower()
    worst = sr if risk_rank.get(sr, 0) >= risk_rank.get(ar, 0) else ar
    console.print(f"Overall risk: {risk_badge(worst)}\n")
    pulsing_high_risk(console, worst)

    # Auto-expand all sections (per your request)
    red_team_agents = result.get("red_team_agents", [])
    blue_team_agents = result.get("blue_team_agents", [])

    print_red_team_section(console, red_team_agents)
    print_blue_team_section(console, blue_team_agents)
    print_static_section(console, static_agent, static_gen)
    print_attack_sim_section(console, attack_result)
    print_malicious_section(console, result.get("malicious_agent"))

    # Final secure prompt
    final_prompt = result.get("final_prompt") or ""
    console.print(Rule("[bold bright_cyan]Final Secure Prompt[/bold bright_cyan]"))
    console.print(
        Panel(
            final_prompt or "[dim]No final prompt produced (request may have been blocked).[/dim]",
            border_style="bright_cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    # Code handling
    code = result.get("code") or ""
    if code.strip():
        path = save_generated_code(code)
        handle_code_preview(console, code, path, minimal=minimal)
    else:
        console.print("[yellow]No code was generated for this request.[/yellow]")


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="nestai",
        description="NestAI – Secure Code Multi-Agent System (colorful CLI)",
    )
    parser.add_argument("--minimal", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--theme", choices=["dark", "light"], default=None)
    parser.add_argument("command", nargs="+")
    args = parser.parse_args(argv)

    cmd_parts = args.command
    console = get_console(args.theme)

    sub = cmd_parts[0]

    if sub == "history":
        run_history_command(cmd_parts[1:])
        return

    if sub == "config":
        run_config_command(cmd_parts[1:], console)
        return

    if sub == "report":
        run_report_command(cmd_parts[1:], console)
        return

    user_prompt = " ".join(cmd_parts)
    try:
        run_pipeline_with_ui(console, user_prompt, minimal=args.minimal, verbose=args.verbose)
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(130)


if __name__ == "__main__":
    main()
