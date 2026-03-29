# The manifest

One YAML file describing the harness's authority model. Unknown keys
are an error: a misspelled section that is silently ignored produces a
clean report about a harness nobody described.

All defaults are pessimistic. An unspecified authority model is the
dangerous one, so leaving a section out describes the dangerous case
rather than a convenient one.

    harness:
      name: <string>
      notes: |
        free text -- what this harness is, who uses it, anything the
        fields cannot carry

      principals:
        - name: alice
          kind: user | service | operator

      tools:
        - name: send_email
          runs_as: <identity the implementation authenticates as>
          requires_approval: true | false
          capabilities:
            - name: smtp
              reach: none | local-read | local-write |
                      internal-network | external-network | execute
              egress: true | false
              sensitive_read: true | false

      contexts:
        - name: assistant
          holds_private_data: true | false
          tools: [send_email]
          sources:
            - name: ticket-history
              trust: system | principal | tenant | retrieved |
                     external | tool-result | tool-definition
              third_party_writable: true | false

      authorisation:
        subject: requesting-principal | session | service-identity |
                 model-supplied | none
        timing: per-call | per-session | at-startup | never
        halts_on_denial: true | false
        enforced_by: "name the function"

      delegation:
        enabled: true | false
        inherits_tools / inherits_credentials / inherits_context /
        inherits_approvals / attenuates / shares_budget

      trace:
        records_proposed_action / records_context_provenance /
        records_authz_decision / records_executed_arguments /
        records_result / records_agent_identity

      approval:
        enabled / renders_structured_call / model_can_skip
        prompts_per_session: <int>

      budget:
        steps / tool_calls / tokens: <int or omitted>
        shared_across_delegates: true | false

      concurrency:
        workspace / browser_profile / memory_store / cache
        cache_keyed_by_principal: true | false

      definitions:
        pinned_digest: <hex or null>
        reread_on_reconnect / reread_on_notification
        namespaced_by_server
        approval_scope: server | tool | definition
        shows_description_at_approval
        tools:
          - name: lookup_record
            server: acme-crm
            source: operator | first-party | third-party | registry |
                    user-installed
            description: "..."
            parameters: {...}

## the fields that carry the most weight

| field | why |
|---|---|
| `authorisation.subject` | the whole of AHA-001. One line of code to answer. |
| `authorisation.timing` | session-scoped authority with per-action decisions is the AG group in one field. |
| `contexts[].sources[].trust` | decides every composition finding. |
| `tools[].egress` | the leg of the trifecta that is cheapest to remove. |
| `delegation.*` | a boundary re-granted one level down. |
| `trace.records_context_provenance` | whether an incident is reconstructable. |

## filling it in honestly

Where nobody knows, leave it out and mark it in `notes`. The checks
then report the pessimistic case, which is both correct and the fastest
way to get somebody to go and look.

Where the answer is "it depends on the context", split the context.
That is what contexts are for, and a harness with one context that
holds everything is itself the finding.
