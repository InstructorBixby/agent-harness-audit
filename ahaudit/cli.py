"""Command line entry point."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ahaudit import (introspect, manifest, plugins, policy, probe,
                     report, sarif, serialise)
from ahaudit.baseline import Baseline
from ahaudit.checks import REGISTRY, TITLES, load_builtins, run_all
from ahaudit.findings import Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ahaudit")
    ap.add_argument("manifest", nargs="?", help="harness manifest yaml")
    ap.add_argument("--check", action="append", default=[],
                    metavar="ID")
    ap.add_argument("--list-checks", action="store_true")
    ap.add_argument("--no-plugins", action="store_true",
                    help="skip out-of-tree checks")
    ap.add_argument("--tools-list", metavar="PATH")
    ap.add_argument("--tools-server", default="unknown")
    ap.add_argument("--trace", metavar="PATH")
    ap.add_argument("--policy", metavar="PATH")
    ap.add_argument("--baseline", metavar="PATH")
    ap.add_argument("--write-baseline", metavar="PATH")
    ap.add_argument("--markdown", metavar="PATH")
    ap.add_argument("--json", metavar="PATH")
    ap.add_argument("--sarif", metavar="PATH")
    ap.add_argument("--fail-on", default="medium",
                    choices=[s.value for s in Severity])
    ap.add_argument("--quiet", action="store_true")
    return ap


def main(argv: list[str] | None = None) -> int:
    load_builtins()
    probe.load_builtins()
    args = build_parser().parse_args(argv)

    notes: list[str] = []
    if not args.no_plugins:
        installed = plugins.install() + plugins.install_probes()
        if installed:
            notes.append("out-of-tree checks installed: "
                         + ", ".join(installed))

    if args.list_checks:
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
        pol = policy.load(args.policy) if args.policy else policy.Policy()
    except (manifest.ManifestError, policy.PolicyError) as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE

    notes += pol.notes()
    artefacts: dict = {}

    if args.tools_list:
        try:
            observed = introspect.load(args.tools_list,
                                       server=args.tools_server)
        except (OSError, ValueError) as exc:
            print(f"tools-list: {exc}", file=sys.stderr)
            return EXIT_USAGE
        harness.definitions, diff_notes = introspect.merge(
            harness.definitions, observed)
        notes += diff_notes

    if args.trace:
        try:
            artefacts["trace"] = json.loads(
                Path(args.trace).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"trace: {exc}", file=sys.stderr)
            return EXIT_USAGE

    findings = run_all(harness, args.check or None)
    findings += probe.run_all(harness, artefacts)
    findings = pol.apply(findings)

    if args.write_baseline:
        Baseline.from_findings(findings).save(args.write_baseline)

    failing = findings
    if args.baseline and Path(args.baseline).exists():
        base = Baseline.load(args.baseline)
        failing, known = base.split(findings)
        notes.append(f"{len(known)} finding(s) accepted by the "
                     f"baseline")
        notes += [f"baselined but no longer present: {t}"
                  for t in base.stale(findings)]

    if args.markdown:
        Path(args.markdown).write_text(
            report.markdown(harness, findings, notes=notes),
            encoding="utf-8")
    if args.json:
        text = serialise.dumps(harness, findings)
        if args.json == "-":
            print(text)
        else:
            Path(args.json).write_text(text, encoding="utf-8")
    if args.sarif:
        Path(args.sarif).write_text(
            sarif.dumps(findings, manifest_path=args.manifest),
            encoding="utf-8")

    if not args.quiet and args.json != "-":
        for n in notes:
            print(f"note: {n}", file=sys.stderr)
        print(report.text_summary(harness, findings))

    floor = Severity(args.fail_on).rank
    worst = max((f.severity.rank for f in failing), default=-1)
    return EXIT_FINDINGS if worst >= floor else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
