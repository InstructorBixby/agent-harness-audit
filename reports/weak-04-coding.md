# Harness audit: weak-04-coding

| severity | count |
|---|---|
| critical | 2 |
| high | 4 |
| medium | 5 |
| low | 2 |
| info | 0 |

The most realistic of the samples, and the one I would hand to someone
who thinks their coding assistant is fine because the authorisation
path is correct. It is correct. Everything else composes.

## the two critical ones

**AHA-002**, context `agent`: assembled from the rules file, the
repository, the issue text and tool results -- all third-party
writable -- while holding `read_file`, `write_file`, `run_command` and
`web_search`, and holding private data. All three properties, one
context.

**AHA-006**, write-then-execute: `write_file` and `run_command` in the
same context. Two authorised calls, arbitrary code execution. The
workspace is also where the rules file lives, which makes it
write-then-persist as well.

## the chain worth putting in the report

1. A pull request from anyone adds a comment to a vendored dependency.
2. The task "run the tests" reads it. (`IPI-006`)
3. `write_file` edits the rules file the harness reads for its own
   configuration. (`OUT-008`, `OUT-005`)
4. The workspace is shared across runs, so the next run -- possibly
   another developer's -- reads it. (`AHA-011`, `AG-008`)
5. `run_command` has egress, so step three is optional.

No vulnerability in any component.

## the rest, briefly

- **AHA-005**: the approval dialog is model-written, and an ordinary
  session produces about 35 prompts. Both halves of the fatigue
  problem at once.
- **AHA-003**: children inherit tools, credentials and approval state,
  and have their own budgets.
- **AHA-008**: no call or token budget, and a denial does not halt.
- **AHA-004 / AHA-012**: no provenance and no executed arguments in the
  trace, so none of the above is reconstructable afterwards.
- **AHA-014**: `run_command.command` and `write_file.path` are free
  strings.
- **AHA-001**: silent. The authorisation path is right.

## remediation, in the order I would do it

1. No network from the execution sandbox. Removes the egress leg of
   AHA-002 and most of the chain's final step.
2. Harness configuration outside the workspace, not writable by the
   loop. Kills step three.
3. Per-run workspace. Kills step four.
4. Render the approval from the structured call, and gate far fewer
   things.
5. Provenance and arguments in the trace, so the next incident is
   investigable.

None of that is about the model.
