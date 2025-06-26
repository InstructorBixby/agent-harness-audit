# samples

Deliberately-vulnerable harnesses. Each one is wrong in a specific,
named way, with a manifest that declares it honestly and a runnable
stub that actually behaves that way.

Both halves matter. The manifest is what the checks read, so it is how
the checks get tested. The stub is how I check the manifest is not
lying -- a tool whose fixtures are hand-written to make its own checks
fire is a tool that proves nothing.

| sample | what is wrong with it |
|---|---|
| `weak-01-ambient` | one service credential, authority granted per session, no trace |

Run a sample's stub, then audit its manifest:

    python samples/weak-01-ambient/harness.py --task "summarise notes.md"
    ahaudit samples/weak-01-ambient/harness.yaml
