# Milestone 02: Terraform plan parser

## Objective

Parse sanitized Terraform/OpenTofu plan JSON into a provider-neutral raw change representation while preserving action, unknown, absent, and sensitive states.

## Scope

- JSON boundary validation
- supported format-version check
- resource address, type, provider, actions, before/after extraction
- unknown and sensitive metadata propagation
- plan SHA-256 digest
- safe diagnostics
- CLI `inspect` output for development

## Non-goals

- cloud semantic mapping
- public-access decisions
- intent matching
- policy execution

## Required fixtures

- create, update, delete, replace, and no-op
- nested modules
- provider aliases
- unknown after values
- nested sensitive values
- absent fields
- malformed JSON
- unsupported major format version
- minimal representative OpenTofu plan fixture

## Acceptance criteria

- Parser never logs or returns a sensitive raw value.
- Replace is preserved as ordered delete/create actions.
- Unknown, absent, redacted, false, and zero remain distinguishable.
- Unsupported resources are retained as opaque changes.
- Input errors contain safe field context.
- `go test ./...` and `go vet ./...` pass.
