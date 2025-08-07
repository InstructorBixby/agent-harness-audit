# Findings schema

`ahaudit/schema/finding.schema.json`, JSON Schema 2020-12.

A document is the result of one audit: the harness name, what produced
it, and a list of findings. One file per audit, so two audits diff
cleanly.

## why a schema at all

These end up in reports, in tickets and occasionally in somebody's
dashboard, and I have transcribed findings by hand enough times to
want the machine-readable version to be the primary one. The markdown
report is generated from the same objects.

## the fields that matter

| field | why it exists |
|---|---|
| `check` | stable id. Quoted in reports; never reused. |
| `claim` | one sentence, no hedging. If it cannot be stated as a claim, the check is not ready. |
| `evidence` | the part of the manifest it came from, so a reader can argue with it rather than with me. |
| `taxonomy` | ids from llm-redteam-notes, so a structural finding and a measured rate land in a report as one argument. |
| `confidence` | `declared` from the manifest, `observed` from introspection or a real trace, `inferred` from a heuristic. |

`confidence` is the field that keeps the tool honest. A `declared`
finding says the manifest says so, and the manifest is somebody's
description of their own system. An `observed` finding says the tool
looked. Reporting those as the same thing would be exactly the
over-claiming this tool exists to avoid.

## compatibility

`schema_version` is `"1"`. Adding an optional property is a minor
change. Removing one, renaming one, or changing what a value means is a
new version, and the version is in every document so a consumer can
tell.
