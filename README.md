# agent-harness-audit

Audits a tool-calling agent harness for confused-deputy and
privilege-boundary problems. It reads the harness; it does not probe
the model.

Every other tool in this space -- including mine -- tests whether the
model can be talked into something. This one asks whether the system
was entitled to do what it did. Those are different questions, and the
second one has an answer that does not decay:

- which principal is a call authorised as, and when?
- does any context hold untrusted content, private data and a way out?
- what does a sub-agent inherit?
- are tool definitions pinned after somebody approved them?
- can the trace reconstruct a decision after the fact?

## install

    pip install -e ".[dev]"

## use

    ahaudit --list-checks
    ahaudit harness.yaml
    ahaudit harness.yaml --markdown report.md --json findings.json

    # compare the declaration against something real
    ahaudit harness.yaml --tools-list tools.json --tools-server vendor
    ahaudit harness.yaml --trace one-task.json

    # in a pipeline: fail on new findings only
    ahaudit harness.yaml --policy .audit/policy.yaml \
        --baseline .audit/baseline.json --fail-on high

Exit status: `0` nothing at or above `--fail-on`, `1` otherwise, `2`
bad usage, a bad manifest or a bad policy.

## checks

    AHA-001  tool calls not attributed to the requesting principal
    AHA-002  untrusted content and privileged tools in one context
    AHA-003  sub-agents inherit authority without attenuation
    AHA-004  trace cannot reconstruct a decision
    AHA-005  approval is not a control
    AHA-006  tool pairs compose into an unauthorised capability
    AHA-007  egress paths not accounted for
    AHA-008  unbounded loop or non-terminal denial
    AHA-009  tool definitions not pinned after approval
    AHA-010  tool namespace collisions and shadowing
    AHA-011  state shared between concurrent runs
    AHA-012  provenance not available to authorisation
    AHA-013  tool results re-enter the context unmarked

Each is a pure function from the model to findings -- no I/O, no
network, no model -- which is what makes them testable against
fixtures. See `docs/checks.md` for how a check earns an id.

## confidence

Every finding says where it came from: `declared` (the manifest says
so), `observed` (the tool read a tools/list dump or a real trace), or
`inferred` (a heuristic, e.g. a tool named like an egress path). A
manifest is somebody's description of their own system and the output
does not pretend otherwise.

## the manifest

One YAML file describing the authority model. Somebody has to write it
down, and that is the point rather than the cost: on every engagement
so far, filling it in has produced findings before the tool ran.
`docs/manifest.md` is the reference; `samples/` has complete examples.

## use it with promptfuzz

A `promptfuzz` run says untrusted content reaches a context at a
measured rate. This says what that context can do. Reported together
they are one argument; reported separately they are two findings, and
the second gets closed as "we tuned the prompt".

## docs

| file | what |
|---|---|
| `docs/threat-model.md` | the assumption the tool is built on |
| `docs/methodology.md` | how to run one of these, and in what order to read the output |
| `docs/manifest.md` | every field |
| `docs/checks.md` | the catalogue, severities, confidence |
| `docs/findings-schema.md` | the JSON output |
| `docs/ci.md` | gating on new findings |
| `NOTES.md` | why it is shaped like this |
