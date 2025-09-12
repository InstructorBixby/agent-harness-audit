# Harness audit: weak-02-delegation

Generated with `ahaudit samples/weak-02-delegation/harness.yaml
--markdown` and committed so the output shows up in a diff.

| severity | count |
|---|---|
| critical | 1 |
| high | 3 |
| medium | 2 |
| low | 0 |
| info | 0 |

Worth reading alongside `weak-01-ambient.md`. The authorisation path
here is correct -- per call, against the requesting principal, halting
on denial -- and AHA-001 produces nothing. Everything below comes from
what happens one level down.

## AHA-006 -- Write-then-execute pairs available in context 'researcher'

**Severity** critical

(The sample has no execute tool; this section is the write-then-send
pair, reported by AHA-006 as read-then-send.)

## AHA-002 -- Context 'researcher' mixes untrusted content with capability

**Severity** critical
**Related** AG-001, AG-007, IPI-001, TC-001

Context 'researcher' is assembled from fetched-pages, tool-results and
holds web_fetch, write_notes, send_summary, so content from those
sources can steer a privileged action. It also holds data the
requesting principal could not otherwise obtain, and web_fetch,
send_summary can move bytes outward, so the three properties needed for
exfiltration are present in one context.

## AHA-003 -- Delegation does not attenuate authority

**Severity** high
**Related** AG-005

A sub-agent receives the parent's authority whole, so a child spawned
to read untrusted content holds every tool the parent held.

## AHA-003 -- Approval state inherited by sub-agents

**Severity** high
**Related** AG-005, TC-006, DEF-006

An approval granted for one action in one context is carried into a
child, so a child acting on untrusted content can take a privileged
action without a human seeing it.

## AHA-006 -- Read-then-send pairs available in context 'researcher'

**Severity** high
**Related** TC-007, EX-003, AG-007

Each call is individually authorised and the composition is not:
read_notes and send_summary are available in the same context.

## AHA-003 -- Parent context inherited by sub-agents

**Severity** medium

## AHA-008 -- Budgets not shared across delegates

**Severity** medium
**Related** AG-003, AG-005

Each sub-agent gets its own budget, so a fan-out multiplies the total.

## reading this

The useful sentence for a report: *the boundary is correct at the top
level and re-granted at the delegation boundary*. That is a two-line
fix in the spawn path -- construct the child's tool set for its task,
and do not pass approval state -- and it is invisible on an
architecture diagram, which is why it survived review.
