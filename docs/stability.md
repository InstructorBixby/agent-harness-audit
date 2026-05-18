# Stability

From 1.0, these break only in a major version:

- **check ids.** `AHA-001` means what it means forever. New checks get
  new ids; a retired check keeps its id and stops firing.
- **the findings JSON schema** at `schema_version: "1"`. Optional
  properties may be added. Anything else is a new version, and the
  version is in every document.
- **manifest field names and enum values.** A renamed field keeps a
  reading shim for a major version, and the shim warns.
- **exit codes** 0, 1, 2.
- **`Finding`, `Severity`, and the check signature** `(Harness) ->
  list[Finding]`, for out-of-tree checks.

Explicitly not stable:

- **severities.** They are advisory, they move as I see more harnesses,
  and `--policy` exists so a severity change does not break a gate.
  Pin with a policy file if a build depends on one.
- **finding titles and claim wording.** This is why baselines are
  fingerprinted on structure rather than on the title.
- **the markdown report's layout.**
- **anything under `ahaudit.probe`** until the artefact formats settle.

## why 1.0 now

No new features in this release. The model has not changed shape in
months, the check interface has not changed since 0.2, the findings
schema has consumers, and the ids are quoted in other people's
tickets. Semver only means something if the numbers start making
promises.
