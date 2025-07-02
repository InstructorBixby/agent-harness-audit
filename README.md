# agent-harness-audit

Audits a tool-calling agent harness for confused-deputy and
privilege-boundary problems. It reads the harness rather than probing
the model.

Every other tool in this space -- mine included -- tests whether the
model can be talked into something. This one asks whether the system
was entitled to do what it did:

- which principal is a tool call attributed to, at execution time?
- does an authorisation check sit between intent and execution, and
  what is its subject?
- can a tool result influence a later privileged call?
- what does a sub-agent inherit?
- can the trace reconstruct a decision after the fact?

Those are facts about code and configuration. They need no denominator
and they survive a model update.

## install

    pip install -e ".[dev]"

## use

    ahaudit --list-checks
    ahaudit samples/weak-01-ambient/harness.yaml
    ahaudit path/to/harness.yaml --markdown report.md

Exit status: `0` nothing at medium or above, `1` otherwise, `2` bad
usage or a bad manifest.

## the manifest

A declaration of the harness's authority model: tools and what they
reach, contexts and what text lands in them, who a call is authorised
as and when, what delegation passes down, what the trace records.

Somebody has to write that down, and that is the point rather than the
cost. On every engagement so far, the act of filling it in has produced
findings before the tool ran, because nobody had written the authority
model down anywhere.

See `docs/manifest.md` for the fields and
`samples/weak-01-ambient/harness.yaml` for a complete example.

## checks

    AHA-001  tool calls not attributed to the requesting principal
    AHA-002  untrusted content and privileged tools in one context
    AHA-003  sub-agents inherit authority without attenuation
    AHA-004  trace cannot reconstruct a decision
    AHA-005  approval is not a control

Each check is a pure function from the model to a list of findings --
no I/O, no network, no model -- which is what makes them testable
against fixtures.

## samples

`samples/` holds deliberately-vulnerable harnesses, each wrong in a
named way, with a manifest and a runnable inert stub. `reports/` holds
their generated reports, committed so the output format shows up in a
diff.
