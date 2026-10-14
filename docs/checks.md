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
| AHA-009 | are tool definitions pinned after approval |
| AHA-010 | do two sources of tools share a namespace |
| AHA-011 | what do concurrent runs share |
| AHA-012 | is provenance available to authorisation, or only to the prompt |
| AHA-013 | do tool results and errors re-enter a context with capability |
| AHA-014 | how wide is a tool's argument surface |
| AHA-015 | can model output reach state the harness reads back |

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
the client's world; `send_email` to one fixed internal address and
`send_email` to an arbitrary recipient are the same manifest entry
unless the manifest says otherwise.

The ordering is still useful, and the defaults follow one rule: a
finding is `critical` when the structure removes a boundary entirely
(no authorisation, model-supplied subject, all three properties in one
context), `high` when a boundary exists and is evaluated against the
wrong subject or at the wrong time, `medium` when a control is absent
but its absence is survivable, `low` for a gap that costs evidence
rather than safety, `info` for something worth stating in a report.

Override with `--policy`; an override is recorded in the finding.

## confidence

| value | means |
|---|---|
| `declared` | the manifest says so |
| `observed` | the tool looked at something real: a tools/list dump, a trace |
| `inferred` | a heuristic, e.g. a tool named like an egress path |

An `inferred` finding is a question for the reader, not a conclusion,
and the report says so.
