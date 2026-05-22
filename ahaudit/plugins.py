"""Out-of-tree checks and probes.

A client's harness has properties this tool does not model, and the
people who know them are not going to send me a pull request. So the
check registry is open:

    [project.entry-points."ahaudit.checks"]
    ACME-001 = "ahaudit_acme:check_tenant_header"

Loading is loud. A check that fails to import prints a warning and is
skipped, and the skip appears in the report notes -- a silently missing
check produces a clean result that never ran.
"""
from __future__ import annotations

import warnings
from importlib.metadata import entry_points

from ahaudit.checks import REGISTRY, TITLES

GROUP = "ahaudit.checks"
PROBE_GROUP = "ahaudit.probes"


def discover(group: str = GROUP) -> dict:
    found: dict = {}
    try:
        eps = entry_points(group=group)
    except TypeError:        # pragma: no cover
        eps = entry_points().get(group, [])
    for ep in eps:
        try:
            found[ep.name] = ep.load()
        except Exception as exc:  # noqa: BLE001 -- reported
            warnings.warn(
                f"check plugin {ep.name!r} failed to load: "
                f"{type(exc).__name__}: {exc}", stacklevel=2)
    return found


def install() -> list[str]:
    """Register discovered checks. Returns the ids installed."""
    installed = []
    for name, fn in discover().items():
        if name in REGISTRY:
            warnings.warn(
                f"check plugin {name!r} collides with a built-in "
                f"check id and was not installed", stacklevel=2)
            continue
        REGISTRY[name] = fn
        TITLES[name] = getattr(fn, "title", name)
        installed.append(name)
    return sorted(installed)


def install_probes() -> list[str]:
    from ahaudit.probe import REGISTRY as PROBES

    installed = []
    for name, fn in discover(PROBE_GROUP).items():
        PROBES[name] = fn
        installed.append(name)
    return sorted(installed)
