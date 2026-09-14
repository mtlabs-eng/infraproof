# Milestone 01: Evidence Bundle foundation

## Objective

Create a minimal Go module that models, validates, serializes, and renders a versioned Evidence Bundle without any Terraform or cloud-specific behavior.

## Scope

- Go module and CLI entry point
- Typed Evidence Bundle model
- Contract validation
- Canonical deterministic JSON
- Deterministic Markdown renderer
- Exit-code mapping function
- Unit and golden tests

## Non-goals

- Terraform parsing
- Intent parsing
- Provider mappers
- Policy evaluation
- MCP
- Network calls
- Cloud SDKs

## Required behavior

1. Represent every Version 1 field defined in `docs/EVIDENCE-BUNDLE.md`.
2. Validate bundle invariants before rendering.
3. Reject `BLOCK` without an evidenced finding whose disposition is `BLOCK`.
4. Reject `WARN` without a warning finding, and reject `UNKNOWN` without a required unknown.
5. Reject `PASS` containing blocking/warning findings or required unknowns.
6. Sort findings, evidence, and unknowns deterministically.
7. Render canonical JSON without timestamps or nondeterministic values.
8. Render concise Markdown from the same model.
9. Map decisions to the documented exit codes without terminating inside library code.
10. Prevent a value marked redacted from carrying or rendering a raw value.

## Tests written first

- valid bundle for each decision
- invalid `BLOCK` without evidence
- invalid `WARN` without a warning finding
- invalid `UNKNOWN` without a required unknown
- invalid `PASS` with a material finding
- redacted observed fact containing a value is rejected
- deterministic finding ordering
- deterministic evidence ordering
- JSON golden fixture
- Markdown golden fixture
- exit-code table test
- invalid schema version

## Acceptance criteria

- `go test ./...` passes.
- `go vet ./...` passes.
- Repeated rendering produces byte-identical output.
- Golden output contains no current time, random ID, local path, or raw sensitive value.
- Public types have focused documentation.
- No package imports Terraform, cloud, MCP, GitHub, or LLM dependencies.

## Definition of done

The repository can construct a sample Evidence Bundle in a test and render stable JSON and Markdown matching reviewed golden files. No analysis command is claimed to work yet.
