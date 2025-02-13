# agent-harness-audit

Audits a tool-calling agent harness for confused-deputy and
privilege-boundary problems.

Every tool I have for this space -- mine included -- tests whether the
*model* can be talked into something. None of them test whether the
*system* was entitled to do what it did. Those are different questions
and the second one has a stable answer:

- which principal is a tool call attributed to, at execution time?
- does an authorisation check sit between the model's intent and the
  call, and what is its subject?
- can a tool result influence a later privileged call?
- what does a sub-agent inherit?
- are tool definitions pinned after the operator approved them?
- can the trace reconstruct a decision after the fact?

Those are facts about code and configuration. They do not need a
denominator, they survive a model update, and they are answerable in an
afternoon from four artefacts: the context-assembly code, the tool
registry, the authorisation path for one call, and one real trace.

Early. Right now it is a data model and an argument.
