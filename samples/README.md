# samples

Deliberately-vulnerable harnesses. Each one is wrong in a specific,
named way, with a manifest that declares it honestly and -- where it
adds anything -- a runnable stub that actually behaves that way.

Both halves matter. The manifest is what the checks read, so it is how
the checks get tested. The stub is how I check the manifest is not
lying: a tool whose fixtures are hand-written to make its own checks
fire is a tool that proves nothing.

| sample | what is wrong with it |
|---|---|
| `weak-01-ambient` | one service credential, model-supplied tenant, session-scoped authority, no provenance in the trace |
| `weak-02-delegation` | sound parent, children inherit tools, credentials, context and approval state; per-child budgets |

`weak-02` is the one worth showing an architect. The parent context
reads no untrusted content and the authorisation path is correct, so
the diagram looks right, and the sub-agent that reads web pages holds
every tool the parent holds plus the approval the user already granted.

Run a sample's stub where there is one, then audit its manifest:

    python samples/weak-01-ambient/harness.py --task "summarise notes"
    ahaudit samples/weak-01-ambient/harness.yaml
    ahaudit samples/weak-02-delegation/harness.yaml --markdown out.md
