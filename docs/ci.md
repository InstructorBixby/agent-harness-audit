# Using this as a gate

The useful gate fails on *new* structural findings, not on the backlog.
A gate that is red on day one is off by day eight.

    harness-audit:
      image: python:3.12
      rules:
        - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      before_script:
        - pip install uv
        - uv pip install --system
            "git+https://git.c01n31.net/c01n31pan1c/agent-harness-audit@v0.3.0"
      script:
        - |
          ahaudit harness.yaml \
            --policy .audit/policy.yaml \
            --baseline .audit/baseline.json \
            --fail-on high \
            --markdown audit.md --json audit.json
      artifacts:
        when: always
        paths:
          - audit.md
          - audit.json

## keeping the manifest honest

The gate's real value is not the checks. It is that the manifest sits
in the repo next to the harness, so a change that adds a tool or
changes the spawn path has to update it, and a reviewer sees the
authority model change in the diff.

Which means the one rule worth enforcing: **the manifest is reviewed
like code**. A change that touches the tool registry and not the
manifest is incomplete.

## the baseline

Generate it once, commit it, and shrink it deliberately:

    ahaudit harness.yaml --write-baseline .audit/baseline.json

`baselined but no longer present` in the output means either something
was fixed -- update the baseline -- or a check regressed. Both want a
look.

## the policy

Severity overrides and disabled checks, with a mandatory reason for
each disable, committed next to the baseline. A disabled check prints
its reason in every run, which is the only way I have found to stop
"temporarily off" becoming permanent.
