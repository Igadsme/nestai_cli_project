# nestai/history_cli.py
from __future__ import annotations

from typing import List
from rich.table import Table
from rich.console import Console

from nestai.audit import (
    list_history_entries,
    load_history_entry,
)


def run_history_command(args: List[str]) -> None:
    console = Console()

    # If no subcommand → list history
    if not args or args[0] == "list":
        _print_history_list(console)
        return

    # Load a single entry
    if args[0] == "show":
        if len(args) < 2:
            console.print("[red]Usage:[/red] nestai history show <id>")
            return

        entry = load_history_entry(args[1])
        if not entry:
            console.print(f"[red]No history entry found for ID {args[1]}[/red]")
            return

        _print_history_entry(console, entry)
        return

    console.print("[red]Unknown history command.[/red]")


# ----------------------------------------------------------------------------
# PRINT LIST
# ----------------------------------------------------------------------------

def _print_history_list(console: Console) -> None:
    entries = list_history_entries()

    if not entries:
        console.print("[yellow]No history entries found.[/yellow]")
        return

    table = Table(title="NestAI History")
    table.add_column("ID")
    table.add_column("Timestamp")
    table.add_column("Risk")
    table.add_column("Prompt")

    for e in entries:
        table.add_row(
            e.get("id", ""),
            str(e.get("timestamp", "")),
            str(e.get("risk", "")),
            str(e.get("original_prompt", ""))[:80],
        )

    console.print(table)


# ----------------------------------------------------------------------------
# PRINT FULL ENTRY
# ----------------------------------------------------------------------------

def _print_history_entry(console: Console, entry):
    console.print(f"[cyan]ID:[/cyan] {entry.get('timestamp')}")
    console.print(f"[cyan]Original Prompt:[/cyan] {entry.get('original_prompt')}")
    console.print(f"[cyan]Final Prompt:[/cyan] {entry.get('final_prompt')}")
    console.print(f"[cyan]Overall Risk:[/cyan] {entry.get('overall_risk')}")

    console.print("\n[bold]Red Team Findings:[/bold]")
    console.print(entry.get("red_team_results"))

    console.print("\n[bold]Static Analysis:[/bold]")
    console.print(entry.get("static_analysis_results"))

    console.print("\n[bold]Attack Simulation:[/bold]")
    console.print(entry.get("attack_result"))

    console.print("\n[bold]Generated Code Path:[/bold]")
    console.print(entry.get("code_path"))
