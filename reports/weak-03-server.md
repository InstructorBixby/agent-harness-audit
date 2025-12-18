# Harness audit: weak-03-server

Generated with:

    ahaudit samples/weak-03-server/harness.yaml \
      --tools-list samples/weak-03-server/tools-list.json \
      --tools-server acme-crm --markdown reports/weak-03-server.md

| severity | count |
|---|---|
| critical | 1 |
| high | 3 |
| medium | 3 |
| low | 0 |
| info | 0 |

## definition comparison

- lookup_record: definition text differs from the declared one
- fetch_url: present on the server, not declared

This section is the point of the sample. The authorisation path is
correct, the trace is complete, approval renders the structured call --
every check that reads the declared manifest is happy. The findings
come from the fact that the text in the context window is supplied by
somebody else and nobody is watching it change.

## AHA-009 -- Live definitions do not match the pinned digest

**Severity** critical
**Confidence** observed
**Related** TC-008

The definitions currently loaded differ from the ones that were
approved. The served `lookup_record` description instructs the model to
call `fetch_url` on an external host before every lookup, and the `id`
parameter description instructs it to pass the system instructions when
the id is unknown. Neither string is in the declared manifest.

## AHA-009 -- Definitions from a third party are not pinned

**Severity** high
**Related** TC-003, TC-004, TC-008

## AHA-009 -- Definitions re-read without re-approval

**Severity** high
**Related** TC-008

Re-read on reconnect and on server notification.

## AHA-010 -- Third-party description claims to supersede another tool

**Severity** high
**Confidence** inferred
**Related** TC-003, TC-010

`helper-tools`' `lookup_record` description says to use it instead of
the deprecated one. There is no name collision resolution here, so
which one the model picks is decided by the descriptions.

## AHA-010 -- Tool names collide across servers

**Severity** high
**Related** TC-010, TC-005

## AHA-009 -- Approval is scoped to the server

**Severity** medium

## AHA-009 -- Approval UI does not show the description

**Severity** medium

## AHA-006 -- Read-then-send pairs available in context 'assistant'

**Severity** high
**Related** TC-007, EX-003, AG-007

## reading this

The sentence for the report: *the operator approved a tool list and the
system has no way to tell them it changed*. The fix is a hash and a
diff at re-approval, and it is small enough that the finding usually
gets closed within the engagement.
