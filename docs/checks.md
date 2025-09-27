# Checks

Ids are stable and never reused. Each check is a pure function from the
harness model to findings.

| id | asks |
|---|---|
| AHA-001 | which principal is a call authorised as, and when |
| AHA-002 | does a context hold untrusted content and capability |
| AHA-003 | what does a sub-agent inherit |
| AHA-004 | can the trace reconstruct a decision |
| AHA-005 | is approval a control or a dialog |
| AHA-006 | do two authorised tools compose into something unauthorised |
| AHA-007 | which paths can move bytes outward |
| AHA-008 | is the loop bounded, and is a denial terminal |

## how a check earns its id

1. The question has an answer that does not depend on sampling. If the
   honest answer is "sometimes", it belongs in promptfuzz, not here.
2. The finding names a component and a fix. "The model might be
   confused" is not a finding.
3. It fires on at least one sample harness and stays silent on the
   `good` fixture. A check that cannot describe a sound system is a
   check that is reporting its own defaults.
4. The claim can be written in one sentence without hedging.

## severities

Advisory, and the tool says so. It cannot know what a tool reaches in
the client's world; `send_email` to a fixed internal address and
`send_email` to an arbitrary recipient are the same manifest entry
unless the manifest says otherwise.

The ordering is still useful, and the defaults follow one rule: a
finding is `critical` when the structure removes a boundary entirely
(no authorisation, model-supplied subject, all three properties in one
context), `high` when a boundary exists and is evaluated against the
wrong subject or at the wrong time, `medium` when a control is absent
but its absence is survivable, `low` for a gap that costs evidence
rather than safety, `info` for something worth stating in a report.

## confidence

| value | means |
|---|---|
| `declared` | the manifest says so |
| `observed` | the tool looked at something real: introspection, a trace |
| `inferred` | a heuristic, e.g. a tool named like an egress path |

An `inferred` finding is a question for the reader, not a conclusion,
and the report says so.
