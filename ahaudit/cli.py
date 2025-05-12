"""Command line entry point."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ahaudit import manifest, report
from ahaudit.checks import REGISTRY, load_builtins, run_all
from ahaudit.findings import Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ahaudit")
    ap.add_argument("manifest", nargs="?", help="harness manifest yaml")
    ap.add_argument("--check", action="append", default=[],
                    metavar="ID", help="only run these checks")
    ap.add_argument("--list-checks", action="store_true")
    ap.add_argument("--markdown", metavar="PATH",
                    help="also write a markdown report")
    ap.add_argument("--quiet", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    load_builtins()
    args = build_parser().parse_args(argv)

    if args.list_checks:
        from ahaudit.checks import TITLES
        for cid in sorted(REGISTRY):
            print(f"{cid}  {TITLES[cid]}")
        return EXIT_OK

    if not args.manifest:
        print("a manifest path is required", file=sys.stderr)
        return EXIT_USAGE

    unknown = [c for c in args.check if c not in REGISTRY]
    if unknown:
        print(f"unknown check(s): {', '.join(unknown)}",
              file=sys.stderr)
        return EXIT_USAGE

    try:
        harness = manifest.load(args.manifest)
    except manifest.ManifestError as exc:
        print(f"manifest: {exc}", file=sys.stderr)
        return EXIT_USAGE

    findings = run_all(harness, args.check or None)

    if args.markdown:
        Path(args.markdown).write_text(
            report.markdown(harness, findings), encoding="utf-8")

    if not args.quiet:
        print(report.text_summary(harness, findings))

    worst = max((f.severity.rank for f in findings), default=-1)
    return EXIT_FINDINGS if worst >= Severity.MEDIUM.rank else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
