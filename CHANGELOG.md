# Changelog

Keep a Changelog format, semver versions.

## [1.1.1]

### Added
- AHA-014 (argument surface): free-text string, object or array
  parameters on tools that can write, execute or send data out.
  Cheap to review and usually closed with 'this was always meant
  to be an id'.
- `samples/weak-04-coding`, the most realistic of the samples: a
  correct authorisation path and a five-step chain through
  everything else.

### Fixed
- Inventory ordering was ambiguous for tools with equal reach, so
  reordering a manifest changed a committed sample report.

## [1.1.0]

### Added
- Out-of-tree checks and probes via entry points, with `AHA-*`
  reserved. A plugin that fails to import warns, is skipped, and
  the skip appears in the report notes -- a silently missing
  check produces a clean result that never ran.
- `--sarif`, `--no-plugins`.
- `docs/plugins.md`, `docs/stability.md`.

## [1.0.0]

No new features.

The model has not changed shape in months, the check interface
has not changed since 0.2, the findings schema has consumers, and
the check ids are quoted in other people's tickets. See
`docs/stability.md` for what that now promises and what it
deliberately does not.

### Added
- SARIF 2.1.0 output, so a pipeline that already ingests it shows
  these findings without anyone building anything.

### Fixed
- Findings with the same check and severity sorted unstably, so
  the same manifest produced different reports on different runs
  and the committed sample reports churned.

## [0.5.0]

### Added
- `ahaudit.probe`: checks that read an artefact rather than the
  declaration, producing `observed` findings. Still no network and
  no model -- a probe takes a file.
- `--trace`: compare what the manifest says the trace records
  against what a real trace contains. The two disagree often
  enough that asking for one trace is now the first thing I do,
  and a manifest that overstates the trace makes every other
  finding less reliable.
- `docs/manifest.md`.

## [0.4.0]

### Added
- AHA-012 (provenance available to authorisation, not just as a
  label in the prompt) and AHA-013 (tool results and error
  strings re-entering a context that holds capability).
- Severity policy (`--policy`): overrides and disabled checks,   with a mandatory reason for a disable. An override is recorded
  in the finding; a tool whose severities can be edited
  invisibly is a tool whose output means nothing.
- Baselines (`--baseline`, `--write-baseline`), fingerprinted on
  the structure rather than the title, so rewording a finding
  does not un-baseline it. Stale baseline entries are reported.
- The blast-radius inventory in the markdown report: every tool,
  its identity, its reach, which untrusted contexts expose it,
  and a blank column for the narrowest version that still works.
- `docs/methodology.md`, `docs/ci.md`.

## [0.3.0]

### Added
- Tool definitions as a first-class part of the model: where a
  definition came from, whether the approved set is pinned, when
  it is re-read, how approval is scoped, and whether the approval
  UI shows the text that reaches the model.
- AHA-009 (definition pinning) and AHA-010 (namespace collisions,
  confusable names, descriptions claiming to supersede a sibling).
- `ahaudit.introspect`: parse a tools/list dump and diff it
  against the declared definitions. Findings from it are
  `observed` rather than `declared`.
- `--tools-list` / `--tools-server`.
- AHA-011 (concurrency): workspace, browser profile, memory store
  and cache shared between concurrent runs, and caches with no
  principal in the key.
- `samples/weak-03-server`, whose declared structure is sound and
  whose context text is written by somebody else.
- Taxonomy cross-reference appendix in the markdown report.

### Changed
- The manifest rejects unknown keys. A misspelled section that is
  silently ignored produces a clean report about a harness nobody
  described, which is worse than an error.
- Definition digests are computed over a canonical serialisation
  with sorted keys, so two hosts listing the same tools in a
  different order produce the same hash.

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
