# Changelog

Keep a Changelog format, semver versions.

## [0.2.0]

### Added
- AHA-006 (composition): read-then-send and write-then-execute
  pairs available in one context. Each call authorised, the
  composition not.
- AHA-007 (egress): external-network tools not declared as
  egress, and the quiet ones -- search, telemetry, logging, error
  reporting, link unfurling -- that are never on the list when I
  ask which tools can send data out.
- AHA-008 (budgets): unbounded loops, per-delegate budgets that
  multiply under fan-out, and denials the loop can retry past.
- JSON output (`--json`) against a published schema, with
  `schema_version`, and `--fail-on` to pick the exit threshold.
- `confidence` on every finding: declared, observed, or inferred.
  A manifest is somebody's description of their own system and
  the output should not pretend otherwise.
- `samples/weak-02-delegation`, whose authorisation path is
  deliberately correct so the findings are all about what a child
  inherits.
- `docs/threat-model.md`, `docs/findings-schema.md`.

### Fixed
- The model dataclasses are slotted. A mistyped field name used to
  add an attribute silently, leaving the real field false and the
  check reporting a finding that was not there.

## [0.1.0]

First version that produces a report I would put in front of a
client.

### Added
- A declared model of a harness: tools and capabilities,
  principals, contexts and their sources, the authorisation path,
  delegation rules, trace fields, approval, budgets.
- YAML manifest loader with error messages written for whoever is
  filling the manifest in.
- Checks AHA-001 (attribution), AHA-002 (context composition),
  AHA-003 (delegation), AHA-004 (trace), AHA-005 (approval).
- Findings carry a check id, severity, a one-sentence structural
  claim, evidence pointing back at the model, remediation, and
  cross-references into the llm-redteam-notes taxonomy.
- `ahaudit` console script; text summary and markdown report.
- `samples/weak-01-ambient`: a deliberately weak harness with both
  a manifest and a runnable inert stub, plus its committed report.
