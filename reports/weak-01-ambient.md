# Harness audit: weak-01-ambient

Generated with `ahaudit samples/weak-01-ambient/harness.yaml --markdown`
and committed so the output format is reviewable in a diff. Regenerate
it when a check changes; a drifted sample report is how a tool's output
quietly stops matching its documentation.

| severity | count |
|---|---|
| critical | 2 |
| high | 2 |
| medium | 1 |
| low | 2 |
| info | 0 |

## AHA-001 -- Authorisation subject supplied by the model

**Severity** critical
**Confidence** declared
**Related** TC-009, OUT-007

The principal or tenant the check evaluates is an argument the model
chose, so the access-control boundary is the model's argument
selection.

### evidence

```
authorisation:
  subject: model-supplied
```

### remediation

Never accept the subject from model output. Take it from the
authenticated request.

## AHA-002 -- Context 'assistant' mixes untrusted content with capability

**Severity** critical
**Confidence** declared
**Related** AG-001, AG-007, IPI-001, TC-001

Context 'assistant' is assembled from ticket-history, fetched-pages,
tool-results and holds send_email, fetch_url, so content from those
sources can steer a privileged action. It also holds data the
requesting principal could not otherwise obtain, and send_email,
fetch_url can move bytes outward, so the three properties needed for
exfiltration are present in one context.

### remediation

Split the context, or remove one of the three properties from it.
Removing egress is usually cheapest.

## AHA-001 -- Authority granted per session, spent per action

**Severity** high

Entitlement is evaluated per-session, so an unbounded number of later
actions run on one decision made before any content was read.

## AHA-004 -- Trace omits context provenance

**Severity** high

The provenance of the context items that influenced a call is not
recorded, so an incident cannot be attributed to the content that
caused it.

## AHA-004 -- Trace omits executed arguments

**Severity** high

Executed arguments are not recorded, so a call that carried data
outward cannot be distinguished from a benign one, and an exfiltration
finding is unprovable after the fact.

## AHA-005 -- No approval step for consequential tools

**Severity** medium

Tools that write, execute or send data outward are invoked with no
human in the loop.

## AHA-004 -- Trace omits authz decision

**Severity** medium

The authorisation decision is not recorded, so there is no evidence
that a control engaged, or that it did not.

## AHA-004 -- Trace omits agent identity

**Severity** medium

Actions are not attributed to the agent that took them, so sub-agent
behaviour is indistinguishable from the parent's.
