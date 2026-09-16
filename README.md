# InfraProof

InfraProof verifies whether a Terraform or OpenTofu change matches declared intent and organizational policy before the change reaches a cloud environment.

The initial product is an offline CLI. It consumes a structured intent contract and Terraform plan JSON, normalizes changes from AWS, Azure, and GCP, applies deterministic rules, and emits a versioned Evidence Bundle as JSON or Markdown.

## Initial boundaries

- No cloud credentials
- No `apply` or `destroy`
- No hosted control plane
- No dashboard
- No natural-language intent parsing in the first release
- Object storage is the first multi-cloud vertical

## Documents

- [Product definition](docs/PRODUCT.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Evidence Bundle](docs/EVIDENCE-BUNDLE.md)
- [Intent Contract](docs/INTENT-CONTRACT.md)
- [Milestones](docs/milestones/)
- [Claude Code handoff](docs/CLAUDE-CODE-HANDOFF.md)

## Status

Two milestones are implemented.

**Evidence Bundle** — modelled, validated, ordered canonically, and rendered as stable JSON and
Markdown, with an exit-code contract.

**Plan parser** — Terraform and OpenTofu plan JSON is parsed into a provider-neutral change
representation that keeps absent, null, false, zero, unknown, and sensitive values distinguishable.
Values the plan marks sensitive are discarded while reading, so nothing downstream holds one.

Intent loading, provider mappers, and policy evaluation are not implemented, so the `check` command
below is not yet available.

```sh
go test ./...
go vet ./...
go run ./cmd/infraproof --version
go run ./cmd/infraproof inspect --plan internal/terraformplan/testdata/nested-sensitive.json
```

`inspect` is a development aid: it reports addresses, actions, and which fields are unknown or
redacted, and reaches no verdict.

## Planned user experience

```sh
infraproof check \
  --intent intent.yaml \
  --plan tfplan.json \
  --format markdown
```

The command exits successfully for `PASS`, uses a distinct non-zero status for `WARN`, `BLOCK`, invalid input, and internal failure, and always supports machine-readable JSON output. This command is not registered yet; the exit-code contract it will use is implemented and tested.
