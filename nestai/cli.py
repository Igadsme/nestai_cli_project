# nestai/cli.py
from __future__ import annotations

import argparse
import json
import os
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
from rich.table import Table
from rich.text import Text
from rich.rule import Rule
from rich.prompt import Prompt
from rich.syntax import Syntax

from nestai.main_pipeline import run_nestai
from nestai.history_cli import run_history_command
from nestai.config_cli import run_config_command
from nestai.models import make_json_safe

# ---------------------------------------------------------------------------
# Paths / constants
# ---------------------------------------------------------------------------

APP_DIR = Path.home() / ".nestai"
GENERATED_DIR = APP_DIR / "generated"
REPORTS_DIR = APP_DIR / "reports"
LAST_RESULT_JSON = APP_DIR / "last_result.json"


def _ensure_dirs() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    GENERATED_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Console / theme helpers
# ---------------------------------------------------------------------------

def get_console(theme: Optional[str]) -> Console:
    if theme == "light":
        return Console(highlight=False, style="black on white")
    return Console(highlight=False)


def gradient_title(text: str) -> Text:
    colors = ["cyan", "magenta", "blue", "bright_magenta", "bright_cyan"]
    t = Text()
    for i, ch in enumerate(text):
        color = colors[i % len(colors)]
        t.append(ch, style=f"bold {color}")
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

    panel = Panel(
        inner,
        box=box.ROUNDED,
        padding=(1, 4),
        border_style="bright_magenta",
    )

    if not animated:
        console.print(panel)
        return

    with Live(panel, console=console, refresh_per_second=10):
        time.sleep(0.3)


# ---------------------------------------------------------------------------
# Risk helpers / summary table
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
    try:
        return make_json_safe(agent)
    except Exception:
        return {"raw": repr(agent)}


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
# Red / Static / Attack / Malicious printing – AUTO-EXPANDED
# ---------------------------------------------------------------------------

def print_red_team_section(console: Console, red_team_agents: List[Any]) -> None:
    console.print(Rule("[bold red]Red Team Findings[/bold red]"))

    if not red_team_agents:
        console.print("[dim]No red team findings available.[/dim]\n")
        return

    for agent in red_team_agents:
        a = _safe_agent_dict(agent)
        name = a.get("name", a.get("agent_name", "unknown"))
        parsed = a.get("parsed", {}) or {}

        severity = parsed.get("severity", "medium")
        risks = parsed.get("risks", [])
        constraints = parsed.get("suggested_constraints", [])
        notes = parsed.get("notes", "")

        header = Text(name, style="bold white")
        header.append("  ")
        header.append(risk_badge(severity))

        console.print(
            Panel.fit(
                header,
                border_style="red",
                box=box.ROUNDED,
            )
        )

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


def _print_single_static(
    console: Console,
    label: str,
    data: Any,
) -> None:
    if not data:
        console.print(f"[dim]{label}: no data.[/dim]\n")
        return

    a = _safe_agent_dict(data)
    parsed = a.get("parsed", {}) or {}

    summary = parsed.get("summary", "")
    risk = parsed.get("overall_risk", "medium")
    issues = parsed.get("issues", [])

    header = Text(label, style="bold white")
    header.append("  ")
    header.append(risk_badge(risk))

    console.print(
        Panel.fit(
            header,
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    if summary:
        console.print(f"  [bold]Summary:[/bold] {summary}")

    if issues:
        console.print("  [bold]Issues:[/bold]")
        for issue in issues:
            tool = issue.get("tool", "generic")
            msg = issue.get("message", "")
            rule_id = issue.get("rule_id", "")
            severity = issue.get("severity", "")
            console.print(
                f"   • [{tool}] ({severity}) {msg}"
                + (f" [{rule_id}]" if rule_id else "")
            )

    console.print()


def print_static_section(
    console: Console,
    static_prompt: Any,
    static_generated: Any,
) -> None:
    console.print(Rule("[bold cyan]Static Analysis[/bold cyan]"))

    _print_single_static(console, "Prompt Static Analysis", static_prompt)
    _print_single_static(console, "Generated Code Static Analysis", static_generated)


def print_attack_sim_section(console: Console, attack_result: Any) -> None:
    console.print(Rule("[bold magenta]Attack Simulation[/bold magenta]"))

    if not attack_result:
        console.print("[dim]No attack simulation result available.[/dim]\n")
        return

    a = _safe_agent_dict(attack_result)
    parsed = a.get("parsed", {}) or {}

    risk = parsed.get("severity", "medium")
    weak_points = parsed.get("weak_points", [])
    simulated_attacks = parsed.get("simulated_attacks", [])
    notes = parsed.get("notes", "")

    header = Text("attack_simulation", style="bold white")
    header.append("  ")
    header.append(risk_badge(risk))

    console.print(
        Panel.fit(
            header,
            border_style="magenta",
            box=box.ROUNDED,
        )
    )

    if simulated_attacks:
        console.print("  [bold]Simulated attacks:[/bold]")
        for s in simulated_attacks:
            console.print(f"   • {s}")

    if weak_points:
        console.print("  [bold]Weak points:[/bold]")
        for w in weak_points:
            console.print(f"   • {w}")

    if notes:
        console.print("  [bold]Notes:[/bold] " + notes)

    console.print()


def print_malicious_section(console: Console, malicious_agent: Any) -> None:
    console.print(Rule("[bold yellow]Malicious Intent Agent[/bold yellow]"))

    if not malicious_agent:
        console.print("[dim]No malicious intent agent result.[/dim]\n")
        return

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

    console.print(
        Panel.fit(
            header,
            border_style="yellow",
            box=box.ROUNDED,
        )
    )

    console.print(
        f"  [bold]Status:[/bold] {'BLOCKED' if blocked else 'Allowed'}"
    )
    console.print(f"  [bold]Message:[/bold] {block_message}")
    if reasons:
        console.print("  [bold]Reasons:[/bold]")
        for r in reasons:
            console.print(f"   • {r}")
    console.print()


# ---------------------------------------------------------------------------
# Codegen save + preview
# ---------------------------------------------------------------------------

def save_generated_code(code: str) -> Path:
    _ensure_dirs()
    ts = datetime.now().strftime("generated_%Y%m%d_%H%M%S.py")
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
        f"[green]Code saved to[/green] [bold]{path}[/bold]"
    )
    console.print("[cyan]You can open this file any time.[/cyan]\n")

    if minimal:
        return

    choice = Prompt.ask(
        "Press <Enter> to preview first ~40 lines, or 's' to skip",
        default="",
        show_default=False,
    ).strip().lower()

    if choice in {"s", "skip", "n", "no"}:
        console.print("Skipping preview.\n")
        return

    preview = "\n".join(code.splitlines()[:40])
    syntax = Syntax(preview, "python", theme="monokai", line_numbers=True)
    console.print(Rule("[bold green]Code Preview[/bold green]"))
    console.print(syntax)
    console.print("[dim]…full code saved in file above.[/dim]\n")


# ---------------------------------------------------------------------------
# Save last result (JSON-safe)
# ---------------------------------------------------------------------------

def save_last_result(result: Dict[str, Any]) -> None:
    _ensure_dirs()
    safe = make_json_safe(result)
    LAST_RESULT_JSON.write_text(json.dumps(safe, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# HTML dashboard generator
# ---------------------------------------------------------------------------

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
    html.append(
        "<style>"
        "body{font-family:sans-serif;background:#050816;color:#f8fafc;padding:20px;}"
        "h1,h2{color:#38bdf8;}"
        "table{border-collapse:collapse;width:100%;margin-bottom:20px;}"
        "th,td{border:1px solid #1f2937;padding:8px;}"
        "th{background:#111827;}"
        ".badge{padding:2px 6px;border-radius:6px;font-size:0.8rem;}"
        ".low{background:#064e3b;color:#ecfdf5;}"
        ".medium{background:#78350f;color:#ffedd5;}"
        ".high{background:#7f1d1d;color:#fee2e2;}"
        ".critical{background:#b91c1c;color:#fee2e2;}"
        "</style>"
    )
    html.append("</head><body>")

    html.append("<h1>NESTAI – Secure Coding Report</h1>")
    html.append(
        f"<p><strong>Original prompt:</strong> "
        f"{data.get('original_prompt','')}</p>"
    )

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
    console.print(
        f"[green]HTML report generated:[/green] [bold]{path}[/bold]"
    )


# ---------------------------------------------------------------------------
# Pipeline runner – AUTO-EXPAND FINDINGS
# ---------------------------------------------------------------------------

def run_pipeline_with_ui(
    console: Console,
    user_prompt: str,
    minimal: bool = False,
    verbose: bool = False,  # kept for future options
) -> None:
    _ensure_dirs()

    console.print()
    print_ascii_banner(console, animated=not minimal)
    console.print()
    console.print(f"[bold]Original Prompt:[/bold] {user_prompt}\n")

    with console.status(
        "[cyan]Running NestAI secure pipeline…[/cyan]",
        spinner="dots",
    ):
        start = time.time()
        raw_result = run_nestai(user_prompt)
        # Ensure pure JSON-safe shape for downstream / history / report
        result: Dict[str, Any] = make_json_safe(raw_result)
        end = time.time()

    total_time = max(end - start, 0.01)

    # Save JSON-safe result for history / report
    save_last_result(result)

    # ---- Summary table (synthetic per-stage timing) ----
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

    static_risk = ((static_agent or {}).get("parsed") or {}).get(
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
            t = progress.add_task(
                "[cyan]Finalizing results…", total=len(stages)
            )
            for _ in stages:
                time.sleep(0.06)
                progress.advance(t)

    console.print()
    console.print(build_summary_table(stage_rows))
    console.print()

    # Overall risk (worst of static + attack)
    risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    sr = (static_risk or "low").lower()
    ar = (attack_risk or "low").lower()
    worst = sr if risk_rank.get(sr, 0) >= risk_rank.get(ar, 0) else ar

    console.print(f"Overall risk: {risk_badge(worst)}\n")
    pulsing_high_risk(console, worst)

    # ------------------------------------------------------------------
    # AUTO-EXPAND: Red Team, Static, Attack, Malicious — NO PROMPTS
    # ------------------------------------------------------------------
    red_team_agents = result.get("red_team_agents", [])
    malicious_agent = result.get("malicious_agent")

    print_red_team_section(console, red_team_agents)
    print_static_section(console, static_agent, static_gen)
    print_attack_sim_section(console, attack_result)
    print_malicious_section(console, malicious_agent)

    # ------------------------------------------------------------------
    # Final secure prompt
    # ------------------------------------------------------------------
    final_prompt = result.get("final_prompt") or ""
    console.print(
        Rule("[bold bright_cyan]Final Secure Prompt[/bold bright_cyan]")
    )
    console.print(
        Panel(
            final_prompt,
            border_style="bright_cyan",
            box=box.ROUNDED,
        )
    )
    console.print()

    # ------------------------------------------------------------------
    # Codegen handling
    # ------------------------------------------------------------------
    code = result.get("code") or ""
    if isinstance(code, str) and code.strip():
        path = save_generated_code(code)
        handle_code_preview(console, code, path, minimal=minimal)
    else:
        console.print(
            "[yellow]No code was generated for this request.[/yellow]\n"
        )


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="nestai",
        description="NestAI – Secure Code Multi-Agent System (colorful CLI)",
    )
    parser.add_argument(
        "--minimal",
        action="store_true",
        help="Minimal visuals (no animations, fewer prompts).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Reserved for future verbose diagnostics.",
    )
    parser.add_argument(
        "--theme",
        choices=["dark", "light"],
        default=None,
        help="Console theme.",
    )
    parser.add_argument(
        "command",
        nargs="+",
        help="Subcommand (history/config/report) or a free-form prompt.",
    )

    args = parser.parse_args(argv)
    cmd_parts = args.command
    console = get_console(args.theme)

    if not cmd_parts:
        console.print("[red]No command provided.[/red]")
        sys.exit(1)

    sub = cmd_parts[0]

    if sub == "history":
        # History CLI handles its own printing
        run_history_command(cmd_parts[1:])
        return

    if sub == "config":
        run_config_command(cmd_parts[1:], console)
        return

    if sub == "report":
        run_report_command(cmd_parts[1:], console)
        return

    # Treat everything else as a prompt to the secure pipeline
    user_prompt = " ".join(cmd_parts)

    try:
        run_pipeline_with_ui(
            console,
            user_prompt,
            minimal=args.minimal,
            verbose=args.verbose,
        )
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
        sys.exit(130)


if __name__ == "__main__":
    main()
