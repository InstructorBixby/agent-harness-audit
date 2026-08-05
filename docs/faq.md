# FAQ

**Why do I have to write a manifest? Can't it read my code?**

For some harnesses it could, badly, for one framework at a time, and
the answer would rot with every release. More importantly, the manifest
is where the value is: on every engagement so far, filling it in has
produced findings before the tool ran, because nobody had written the
authority model down anywhere. A tool that quietly inferred it would
skip the useful part.

**The manifest is my description of my own system. Isn't that
circular?**

Yes, and that is exactly what `confidence: declared` means. Every such
finding is a question about the declaration. Use `--tools-list` and
`--trace` to get `observed` findings, and read the code for the rest --
`docs/methodology.md` lists the four artefacts that answer most of it.

**No findings. Are we fine?**

You have a sound description. Whether the implementation matches it is
a different question, and the report says so in those words. The
fastest check on that is `--trace`: ask for one trace of an ordinary
task and see whether it contains what the manifest claims.

**Our severities are wrong for us.**

They probably are -- the tool cannot know what a tool reaches in your
world. Use `--policy`. Overrides are recorded in the finding, and a
disabled check needs a reason that prints on every run.

**Why no injection payloads?**

Because the assumption is that the injection succeeds. Measuring
whether it does is `promptfuzz`'s job, and the two together are one
argument: untrusted content reaches this context at rate X, and from
this context these actions are authorised.

**Can I run it against a running harness?**

No, and deliberately. Probes take files. Connecting an audit tool to a
client's infrastructure is a conversation I do not want to have, and a
tools/list dump plus one trace is a one-line request.

**Does it support my framework?**

It does not know what a framework is. It reads a manifest. That is why
it still works on the harness somebody built in-house, which is most of
them.

**A check is wrong about my harness.**

Good -- the evidence field exists so you can say which part of the
model it read and why that is not what your system does. If the model
cannot express your system, that is the bug and I want to hear which
part.
