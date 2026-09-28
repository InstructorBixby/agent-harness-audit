# Harness audit: weak-01-ambient

Generated with `ahaudit samples/weak-01-ambient/harness.yaml
--markdown` and committed so the output format is reviewable in a diff.
Regenerated after the checks added since the first version; a drifted
sample report is how a tool's output quietly stops matching its
documentation.

| severity | count |
|---|---|
| critical | 2 |
| high | 6 |
| medium | 4 |
| low | 2 |
| info | 0 |

## AHA-001 -- Authorisation subject supplied by the model

**Severity** critical
**Confidence** declared
**Related** TC-009, OUT-007

The principal or tenant the check evaluates is an argument the model
chose, so the access-control boundary is the model's argument
selection.

### remediation

Never accept the subject from model output. Take it from the
authenticated request.

## AHA-002 -- Context 'assistant' mixes untrusted content with capability

**Severity** critical
**Related** AG-001, AG-007, IPI-001, TC-001

All three properties in one context: ticket history and fetched pages
are third-party writable, the context holds private data, and
`send_email` and `fetch_url` can move bytes outward.

## AHA-001 -- Authority granted per session, spent per action

**Severity** high
**Related** AG-001

## AHA-006 -- Read-then-send pairs available in context 'assistant'

**Severity** high
**Related** TC-007, EX-003, AG-007

`lookup_customer` with `send_email`, and `lookup_customer` with
`fetch_url`. Each call authorised; the composition is not.

## AHA-008 -- Authorisation denial does not halt the loop

**Severity** high
**Related** AG-001, AG-003, DEF-012

## AHA-012 -- Context provenance is not recorded

**Severity** high
**Related** DEF-007, DEF-012, AG-001

## AHA-004 -- Trace omits context provenance

**Severity** high

## AHA-004 -- Trace omits executed arguments

**Severity** high

## AHA-013 -- Tool results re-enter context 'assistant' alongside capability

**Severity** high
**Related** IPI-011, AG-001, TC-001

## AHA-005 -- No approval step for consequential tools

**Severity** medium

## AHA-008 -- Loop is not bounded

**Severity** medium
**Related** AG-003

No limit on steps, tool calls or tokens.

## AHA-004 -- Trace omits authz decision

**Severity** medium

## AHA-004 -- Trace omits agent identity

**Severity** medium

## AHA-007 -- External-network tools not declared as egress

**Severity** low
**Confidence** inferred

## AHA-004 -- Trace omits proposed action

**Severity** low

## the sentence for the report

*Every user's data is reachable by every user, because the tenant the
query filters on is a value the model chose.* That is AHA-001, it needs
no injection to demonstrate, and it is the first thing to fix. The rest
bounds what happens afterwards.
