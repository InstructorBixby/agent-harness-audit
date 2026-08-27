# The bar

What has to be true before a check or a model field goes in. Written
down because the answer keeps drifting between engagements.

## adding a check

Read `docs/checks.md` first -- there is a bar, and it is mostly about
whether the question has an answer that does not depend on sampling.
Then:

1. A new id. Never reuse one; they are quoted in reports and
   baselines that have already gone out.
2. A pure function of the harness model. No I/O, no network, no model.
3. A test that it fires on a fixture **and** a test that it stays
   silent on the `good` fixture. The second one is the important one: a
   check that cannot describe a sound harness is a check reporting its
   own defaults.
4. A sample harness that exhibits it, or a note in the commit on
   which existing sample does.
5. Taxonomy ids in `taxonomy` where the class exists in
   llm-redteam-notes.
6. A row in `docs/checks.md`.

## adding a model field

The highest bar in the repo. Every field is a question somebody has to
answer about their harness, and a field nobody can answer makes the
manifest longer and the tool worse. So: name the finding it enables,
and the engineer on the other side who can answer it in one sitting.

Defaults are pessimistic. An unspecified field describes the dangerous
case.

## what gets rejected

- a check that needs to call a model. The whole premise is that the
  injection succeeds; a tool that asks a model whether something is
  dangerous has reintroduced the problem into its own oracle.
- a check that reaches the network. Probes take files.
- severities tuned for one client's risk appetite. That is `--policy`.
- findings phrased as "the model might". Name the component and the
  fix.
- a sample harness without a manifest, or a manifest that describes
  something the sample does not do.

## style

ruff, pinned in `constraints-dev.txt`. Tests next to the behaviour
they describe, in the same commit.
