# main_pipeline.py
from __future__ import annotations
from typing import Dict, Any

from nestai.controller import Controller


def run_nestai(user_prompt: str) -> Dict[str, Any]:
    """
    New Architecture A — main entrypoint used by CLI.
    """
    controller = Controller()
    return controller.run_full_pipeline(user_prompt)
