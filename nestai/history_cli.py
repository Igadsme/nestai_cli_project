from __future__ import annotations

from typing import List

from rich.console import Console
from rich.table import Table

from nestai.audit import list_history_entries, load_history_entry


def run_history_command(args: List[str]) -> None:
    console = Console()

    if not args or args[0] == "list":
        _print_history_list(console)
        return

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


def _print_history_entry(console: Console, entry) -> None:
    console.print(f"[cyan]Timestamp:[/cyan] {entry.get('timestamp')}")
    console.print(f"[cyan]Original Prompt:[/cyan] {entry.get('original_prompt')}")
    console.print(f"[cyan]Final Prompt:[/cyan] {entry.get('final_prompt')}")

    controller = entry.get("controller_result") or {}
    console.print(f"[cyan]Blocked:[/cyan] {controller.get('blocked')}")
    console.print(f"[cyan]Reasons:[/cyan] {controller.get('reasons')}")

    console.print("\n[bold]Red Team Results:[/bold]")
    console.print(entry.get("red_team_results"))

    console.print("\n[bold]Blue Team Results:[/bold]")
    console.print(entry.get("blue_team_results"))

    console.print("\n[bold]Static Analysis (Prompt):[/bold]")
    console.print(entry.get("static_prompt_result"))

    console.print("\n[bold]Static Analysis (Generated):[/bold]")
    console.print(entry.get("static_generated_result"))

    console.print("\n[bold]Attack Simulation:[/bold]")
    console.print(entry.get("attack_result"))

    console.print("\n[bold]Code Path:[/bold]")
    console.print(entry.get("code_path"))
