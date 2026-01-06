# Running a harness audit

## the four artefacts

Ask for these in the kickoff, not on day three:

1. **context assembly** -- the function that builds what the model
   sees. Everything in AHA-002 and AHA-004 is answered here.
2. **the tool registry** -- definitions, where they come from, what
   each implementation authenticates as.
3. **the authorisation path for one call** -- follow a single tool call
   from the model's output to the side effect, and write down every
   check it passes and what each check's subject is.
4. **one real trace** of an ordinary task.

With those, the manifest takes an afternoon and most of the findings
fall out of filling it in rather than out of running the tool.

## filling in the manifest

Do it with the engineer who owns the harness, in one sitting, screen
shared. The questions that produce findings are the ones where they
have to stop and check:

- "what does this tool authenticate as?"
- "when is that evaluated?"
- "what does a child get?"
- "does the trace record the arguments?"

Write down what they say, not what the architecture diagram says. Where
they are not sure, mark it and come back -- an honest `unknown` in the
manifest is more useful than a guess, and the checks treat the
pessimistic default as the answer, which tends to prompt the lookup.

## then run it

    ahaudit harness.yaml --markdown report.md --json findings.json

And if a tool list is available:

    ahaudit harness.yaml --tools-list tools.json --tools-server vendor

## reading the output

Order of attention, which is not severity order:

1. **AHA-001.** If authorisation has the wrong subject, fix that first
   and most of the rest becomes bounded.
2. **AHA-002 per context.** Which context holds all three properties.
3. **AHA-003 and AHA-011.** Boundaries that exist and are re-granted
   somewhere nobody looks.
4. **AHA-004.** Not a vulnerability; the reason you can or cannot
   investigate the others after an incident.
5. Everything else.

## what to pair it with

A `promptfuzz` run against the same deployment. The rate says the
trigger exists and is reachable; this says what the trigger reaches.
Reported together they are one argument: *untrusted content reaches
this context at a measured rate of X, and from that context these
actions are authorised*.

Reported separately they are two findings the client can close
individually, and the second one gets closed as "we tuned the prompt".

## what to write when the harness is sound

Say what was checked and what a clean result means. Every `declared`
finding is a question about the manifest, so a clean declared result
means the description is sound -- not that the implementation matches
the description. If you read the code, say so; if you did not, say
that instead.
