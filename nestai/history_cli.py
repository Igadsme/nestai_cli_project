from __future__ import annotations

import json
from pathlib import Path
from typing import List

from .audit import (
    list_history_entries,
    load_history_entry,
    search_history,
    delete_history_entry,
    load_config,
    AuditPermissionError,
)


BOLD = "\033[1m"
RESET = "\033[0m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"


def print_divider(text: str):
    print(f"\n{BOLD}==== {text} ===={RESET}\n")


def run_history_command(args: List[str]):
    if not args:
        return show_history_list()

    sub = args[0]

    if sub == "view":
        if len(args) < 2:
            print("Usage: nestai history view <index>")
            return
        return show_history_entry(int(args[1]))

    if sub == "search":
        if len(args) < 2:
            print("Usage: nestai history search <keyword>")
            return
        return search_entries(args[1])

    if sub == "delete":
        if len(args) < 2:
            print("Usage: nestai history delete <index>")
            return
        return delete_entry(int(args[1]))

    if sub == "mode":
        if len(args) < 2:
            print("Usage: nestai history mode <individual|enterprise_dev|enterprise_admin>")
            return
        return set_mode(args[1])

    print(f"Unknown history command: {sub}")


def show_history_list():
    entries = list_history_entries()

    print_divider("NestAI History")
    if not entries:
        print("No history entries found.")
        return

    for idx, fp in enumerate(entries, start=1):
        print(f"{CYAN}{idx}. {fp.name}{RESET}")


def show_history_entry(index: int):
    try:
        data = load_history_entry(index)
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")
        return

    print_divider(f"History Entry #{index}")
    print(json.dumps(data, indent=2))


def search_entries(keyword: str):
    results = search_history(keyword)

    print_divider(f"Search Results for '{keyword}'")

    if not results:
        print("No matching history found.")
        return

    for index, fp in results:
        print(f"{YELLOW}{index}. {fp.name}{RESET}")


def delete_entry(index: int):
    try:
        delete_history_entry(index)
        print(f"{RED}Deleted entry #{index}{RESET}")
    except AuditPermissionError as e:
        print(f"{RED}Permission denied: {e}{RESET}")
    except Exception as e:
        print(f"{RED}Error: {e}{RESET}")


def set_mode(mode: str):
    cfg = load_config()
    mode = mode.strip()

    if mode not in ["individual", "enterprise_dev", "enterprise_admin"]:
        print("Invalid mode. Valid: individual, enterprise_dev, enterprise_admin")
        return

    cfg["mode"] = mode
    Path(cfg["mode"])
    with open(Path.home() / ".nestai" / "config.json", "w") as f:
        json.dump(cfg, f, indent=2)

    print(f"Mode updated to: {mode}")
