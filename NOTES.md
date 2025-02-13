# Design notes

## what this is not

Not a fuzzer. Not a benchmark. It sends nothing at a model and has no
opinion about injection rates -- that is what promptfuzz is for, and
the two are complementary: a rate tells you the trigger exists, this
tells you what the trigger reaches.

## the input

A *manifest*: a declaration of the harness's structure. Tools and their
capabilities, principals, contexts and what flows into them, the
authorisation path, delegation rules, the trace schema.

Someone has to write that manifest, and that is a feature rather than
an inconvenience. Half the findings I have reported in this area were
discovered by the client while answering my questions, because nobody
had written the authority model down anywhere and writing it down made
the gap obvious. A tool that makes the declaration mandatory gets that
effect for free.

Where introspection is possible -- a server exposing a tool list, a
harness with a config file -- the manifest gets populated from it, and
the declared and observed versions get compared. A mismatch is itself
a finding.

## the output

Findings against a schema. Each one: a check id, a severity, the
structural claim, the evidence, and the remediation. Machine-readable,
because these end up in reports and in tickets and I am not
transcribing them by hand again.

## the shape of a check

A check is a pure function from a model of the harness to a list of
findings. No I/O, no network, no model. That makes every check
testable against a fixture, which is the only way a tool like this
stays trustworthy as it grows.
