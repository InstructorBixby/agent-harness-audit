# samples

Deliberately-vulnerable harnesses. Each one is wrong in a specific,
named way, with a manifest that declares it honestly and -- where it
adds anything -- a runnable stub that behaves that way.

Both halves matter. The manifest is what the checks read, so it is how
the checks get tested. The stub is how I check the manifest is not
lying: a tool whose fixtures are hand-written to make its own checks
fire is a tool that proves nothing.

| sample | what is wrong with it |
|---|---|
| `weak-01-ambient` | one service credential, model-supplied tenant, session-scoped authority, no provenance in the trace |
| `weak-02-delegation` | sound parent, children inherit tools, credentials, context and approval state; per-child budgets |
| `weak-03-server` | sound harness, unpinned third-party tool definitions, re-read silently, approval scoped to the server |
| `weak-04-coding` | correct authorisation path, and everything else composes: shared workspace, writable rules file, open egress, 35 approvals an hour |

The last three are the ones worth showing an architect, because the
checks that read the declared structure are happy with large parts of
them. `weak-02`'s boundary is re-granted at the delegation boundary;
`weak-03`'s context text is written by somebody else; `weak-04` has no
vulnerability in any component and a five-step chain through it.

    python samples/weak-01-ambient/harness.py --task "summarise notes"
    ahaudit samples/weak-01-ambient/harness.yaml
    ahaudit samples/weak-02-delegation/harness.yaml --markdown out.md
    ahaudit samples/weak-03-server/harness.yaml \
      --tools-list samples/weak-03-server/tools-list.json \
      --tools-server acme-crm
    ahaudit samples/weak-04-coding/harness.yaml

Generated reports live in `reports/` and are committed, so a change in
the output format shows up in a diff rather than in a client's inbox.
