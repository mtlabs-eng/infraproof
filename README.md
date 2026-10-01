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
- [Using it from a coding agent](docs/MCP.md)
- [Verifying a change on a pull request](docs/PULL-REQUESTS.md)
- [Threat model: the MCP adapter](docs/THREAT-MODEL-MCP.md)
- [Milestones](docs/milestones/)
- [Claude Code handoff](docs/CLAUDE-CODE-HANDOFF.md)

## Status

Six milestones are implemented.

**Evidence Bundle** — modelled, validated, ordered canonically, and rendered as stable JSON and
Markdown, with an exit-code contract.

**Plan parser** — Terraform and OpenTofu plan JSON is parsed into a provider-neutral change
representation that keeps absent, null, false, zero, unknown, and sensitive values distinguishable.
Values the plan marks sensitive are discarded while reading, so nothing downstream holds one.

**Multi-cloud object storage** — AWS, Azure and GCP mappers normalize public exposure into one
model, and a single rule reads it. The rule names no cloud; adding one is a new mapper and an entry
in the registry.

Public access is a correlation problem in every cloud, and the control that decides it often sits
outside the plan — an account-level block on AWS, an organization policy behind GCP's inherited
default. Where that is so, the answer is `UNKNOWN` and the missing control is named. That is the
common case, not an edge one, and reporting `PASS` there would be a guess.

**A result is about the plan, not about the infrastructure.** `PASS` means no plan-provable public
exposure was found among the resource types this build understands — not that nothing is public. See
[what a result means](docs/PRODUCT.md#what-a-result-means).

```sh
go test ./...
go vet ./...
go run ./cmd/infraproof --version
```

## Verifying a change

```sh
go run ./cmd/infraproof check \
  --intent examples/intent.json \
  --plan examples/tfplan.json \
  --format markdown
```

Every file is read locally. The command reaches no network, needs no cloud account, and never
applies anything.

### Saying where

A finding names `aws_s3_bucket_acl.assets["prod"]`; you wrote `main.tf`. Add the configuration
directory and it also says which file and line:

```sh
go run ./cmd/infraproof check \
  --intent examples/intent.json \
  --plan examples/tfplan.json \
  --config examples/infra \
  --format markdown
```

A plan carries no source positions at all, so the line is found in the `.tf` files — and nothing ties
a plan to the files that produced it. So a line is reported only when the declaration found there is
the one the plan names, by kind, type and name, in the directory that plan's own module calls resolve
to. A declaration renamed, moved or deleted since the plan was made carries no line rather than the
nearest one, because a line that is merely plausible sends you to the wrong code with the tool's
authority behind it.

There is no default directory: guessing it would be a guess, and a wrong guess is wrong lines.
Without the flag nothing is read and no output changes. Nothing a location says can change a verdict,
and no content from a configuration file appears anywhere in the output — a location is a path and a
line.

| Exit | Meaning |
| --- | --- |
| 0 | `PASS` — every supported check ran and found nothing |
| 2 | `WARN` — the change needs a human decision |
| 3 | `BLOCK` — deterministic evidence of a violation |
| 4 | `UNKNOWN` — evidence required for a safe conclusion was unavailable |
| 10 | invalid input or usage — not a verdict |
| 11 | internal failure — not a verdict |

## On a pull request

```sh
go install github.com/mtlabs-eng/infraproof/cmd/infraproof@v0.2.0
infraproof check --intent infra/intent.json --plan tfplan.json --format review
```

A short verdict shaped for a diff view, carrying a marker so one comment is updated rather than
repeated. InfraProof writes it; your own CI posts it, with your own token. See
[docs/PULL-REQUESTS.md](docs/PULL-REQUESTS.md) and the workflow in
[docs/examples/infraproof-workflow.yml](docs/examples/infraproof-workflow.yml).

## From a coding agent

```sh
go run ./cmd/infraproof mcp --root .
```

The same verification over the Model Context Protocol, on standard input and output. The server
reads only files inside the roots it is given, and there is no default root. See
[docs/MCP.md](docs/MCP.md) for the two tools and the Claude Code configuration, and
[docs/THREAT-MODEL-MCP.md](docs/THREAT-MODEL-MCP.md) for what it defends against and what it does
not.

An operational failure is never a decision: a missing file or a malformed contract exits 10 and
prints no report, because a verdict reached from inputs that could not be read would be a verdict
about nothing.

The intent contract must be JSON. The format is documented in
[docs/INTENT-CONTRACT.md](docs/INTENT-CONTRACT.md); YAML is deferred, and a YAML file is refused by
name rather than failing as a syntax error.

A constraint the contract states and this build does not evaluate is reported as an unknown rather
than passed over, so a restriction enforced by nothing never sits silently beside a `PASS`. The same
applies to coverage: a resource no rule judged, and a declaration the plan gave nothing to apply to,
are both recorded. A `PASS` means everything was checked, not that nothing objected.

```sh
go run ./cmd/infraproof inspect --plan internal/terraformplan/testdata/nested-sensitive.json
```

`inspect` is a development aid: it reports addresses, actions, and which fields are unknown or
redacted, and reaches no verdict.

## License

Apache License 2.0. See [LICENSE](LICENSE).
