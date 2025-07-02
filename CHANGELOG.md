# Changelog

Keep a Changelog format, semver versions.

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
