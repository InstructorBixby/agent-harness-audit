# Writing a check

Your harness has properties this tool does not model, and you know them
and I do not. Ship a package:

    [project.entry-points."ahaudit.checks"]
    ACME-001 = "ahaudit_acme:tenant_header_check"

where the callable takes a `Harness` and returns a list of `Finding`.
Set a `title` attribute on it for `--list-checks`.

## the rules

- **pure.** No I/O, no network, no model. If it needs an artefact, it
  is a probe (`ahaudit.probes`), which takes a parsed file.
- **never raises.** A check that throws takes the whole audit with it.
- **one claim per finding,** stated without hedging.
- **evidence points back at the model** so a reader can argue with the
  finding rather than with you.
- **your own id prefix.** `AHA-*` is reserved; a collision with a
  built-in is refused with a warning.
- **fires on a fixture and stays silent on a sound one.** Write both.
  A check that cannot describe a sound harness is a check reporting its
  own defaults.

## severity

Pick from the rule in `docs/checks.md` and expect people to override
it with `--policy`. Do not encode client-specific risk appetite in the
severity; that is what the policy file is for.

## taxonomy ids

If your finding maps onto a class in llm-redteam-notes, put the id in
`taxonomy`. It is how a structural finding and a measured rate end up
as one argument in a report.
