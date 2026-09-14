# Milestone 04: Risk and intent matching

## Objective

Load the structured Intent Contract and evaluate destructive actions, cloud mismatch, environment mismatch where evidence is explicit, and private-storage intent.

## Scope

- YAML and JSON Intent Contract loader
- schema and semantic validation
- destructive-change rule
- allowed-cloud rule
- explicit environment-evidence rule
- integration with `STORAGE_PUBLIC`
- aggregate decision logic
- `infraproof check` command

## Safety semantics

- A destructive action forbidden by intent is `BLOCK`.
- A plan affecting a disallowed cloud is `BLOCK`.
- A provable environment mismatch is `BLOCK`.
- Weak environment hints are reported without claiming a mismatch.
- Private exposure plus unknown public-access evidence is `UNKNOWN`.
- Operational errors remain distinct from verification decisions.

## Acceptance criteria

- The documented CLI flow works entirely offline.
- JSON output conforms to Evidence Bundle Version 1.
- Markdown represents the same decision and findings.
- Exit statuses match the contract.
- Each rule has positive, negative, unknown, and malformed-boundary tests where applicable.
- No natural-language model or cloud API is used.
