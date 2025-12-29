"""Checks.

A check is a pure function from a Harness to a list of Findings. No
I/O, no network, no model. That constraint is what makes every check
testable against a fixture, and it is not negotiable -- a check that
needs to call something belongs in `ahaudit.probe`.
"""
from __future__ import annotations

from typing import Callable

from ahaudit.findings import Finding
from ahaudit.model import Harness

Check = Callable[[Harness], list[Finding]]

REGISTRY: dict[str, Check] = {}
TITLES: dict[str, str] = {}


def register(check_id: str, title: str):
    def deco(fn: Check) -> Check:
        if check_id in REGISTRY:
            raise ValueError(f"duplicate check id {check_id}")
        REGISTRY[check_id] = fn
        TITLES[check_id] = title
        return fn
    return deco


def run_all(harness: Harness, only: list[str] | None = None
            ) -> list[Finding]:
    findings: list[Finding] = []
    for check_id, fn in sorted(REGISTRY.items()):
        if only and check_id not in only:
            continue
        findings += fn(harness)
    return findings


def load_builtins() -> None:
    from ahaudit.checks import (approval, attribution,  # noqa: F401
                                budget, composition, concurrency,
                                contexts, definitions, delegation,
                                egress, namespace, trace)
