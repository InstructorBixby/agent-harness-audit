"""Probes: checks that need something real.

Everything in `ahaudit.checks` is a pure function of the declared
manifest, which means every finding there is only as good as the
declaration. Probes read an artefact -- a trace file, a tools/list dump
-- and produce `observed` findings, which are the ones worth arguing
about.

Still no network and still no model. A probe takes a file.
"""
from __future__ import annotations

from typing import Callable

from ahaudit.findings import Finding
from ahaudit.model import Harness

Probe = Callable[[Harness, dict], list[Finding]]

REGISTRY: dict[str, Probe] = {}


def register(probe_id: str):
    def deco(fn: Probe) -> Probe:
        REGISTRY[probe_id] = fn
        return fn
    return deco


def run_all(harness: Harness, artefacts: dict) -> list[Finding]:
    out: list[Finding] = []
    for _, fn in sorted(REGISTRY.items()):
        out += fn(harness, artefacts)
    return out


def load_builtins() -> None:
    from ahaudit.probe import trace  # noqa: F401
