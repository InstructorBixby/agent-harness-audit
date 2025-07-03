# Threat model

## the adversary

Someone who can place text where the harness will read it. Not
necessarily a user of the system: a document in a corpus, a page the
harness fetches, an email, a ticket comment, a tool result, a tool
*definition* from a server the operator did not write.

They cannot change the harness's code, its configuration, or its
credentials. They get text, and they get to retry.

## the assumption that makes this tool worth writing

**The injection succeeds.** Not sometimes -- assume it succeeds. Every
defence that tries to recognise hostile text has a false-negative rate
against an adversary who iterates, and a rate is not a boundary. So
this tool asks no questions at all about whether text will fool the
model. It asks what the model can cause once it has been fooled.

That assumption is also what makes the findings durable. A measured
injection rate is a fact about one endpoint on one day. "This tool call
is authorised as a service identity" stays true until someone changes
the code.

## the three properties

The composition that matters, per context: data the requesting
principal could not otherwise obtain; content an adversary can write;
and a capability that can move bytes outward. Each is ordinary. All
three in one context is an exfiltration pipeline with no vulnerability
in any component, which is why AHA-002 is reported per context and why
its remediation is "remove one".

Simon Willison's framing of this as the lethal trifecta is the version
to use in a conversation -- it is a triage question a non-specialist
can answer:
https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/

## what a sound harness looks like

Not "one that resists injection". One where the injection is boring:

- every action authorised against the requesting principal, at the
  moment of execution, in the data layer rather than in the prompt
- untrusted content and privileged capability not in one context
- delegation attenuates
- provenance available to the harness's own decisions, not only as a
  label in the prompt
- budgets bounded, denials terminal
- a trace from which a decision can be reconstructed

Beurer-Kellner et al., "Design Patterns for Securing LLM Agents against
Prompt Injections", arXiv:2506.08837, is the best catalogue of
architectures that achieve this by construction. Read sideways it is an
audit checklist: identify the pattern a harness claims, then check
whether it holds the constraint. A claimed pattern that cost no
capability is not being used.

## out of scope

- whether the model can be made to say something objectionable. The
  provider's problem.
- injection rates. `promptfuzz` measures those, and the two tools are
  meant to be used together: a rate says the trigger exists, this says
  what the trigger reaches.
- conventional vulnerabilities in tool implementations. Worth finding,
  found with ordinary tools; this one only notes that a tool's
  arguments are an untrusted input surface.
