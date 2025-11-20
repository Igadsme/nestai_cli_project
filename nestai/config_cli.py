from __future__ import annotations
import json
import os
from pathlib import Path
from typing import List

CONFIG_PATH = Path.home() / ".nestai" / "config.json"
CONFIG_DIR = CONFIG_PATH.parent

def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

def load_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_config(data: dict):
    ensure_config_dir()
    with open(CONFIG_PATH, "w") as f:
        json.dump(data, f, indent=4)

def run_config_command(args: List[str]):
    if len(args) == 0:
        print("Usage:")
        print("  nestai config set-key <API_KEY>")
        print("  nestai config show")
        return

    cmd = args[0]

    # ----------------------------------
    # nestai config set-key <key>
    # ----------------------------------
    if cmd == "set-key":
        if len(args) < 2:
            print("Error: Missing API key.")
            print("Usage: nestai config set-key <API_KEY>")
            return

        key = args[1].strip()

        config = load_config()
        config["openai_api_key"] = key
        save_config(config)

        print(f"Saved OpenAI API key to {CONFIG_PATH}")
        return

    # ----------------------------------
    # nestai config show
    # ----------------------------------
    if cmd == "show":
        config = load_config()
        if not config:
            print("No config found.")
            return

        print("Current NestAI configuration:")
        for k, v in config.items():
            masked = v[:6] + "..." if "key" in k.lower() else v
            print(f"  {k}: {masked}")
        return

    print(f"Unknown config command: {cmd}")
