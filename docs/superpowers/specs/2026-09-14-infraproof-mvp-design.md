# InfraProof MVP design

## Status

Approved product direction; implementation awaits review of this written specification.

## Objective

Build an offline-first, provider-neutral verifier for Terraform and OpenTofu changes across AWS, Azure, and GCP. The verifier compares a human-confirmed structured intent with plan JSON, evaluates deterministic policies, and emits a traceable Evidence Bundle. It never applies infrastructure.

## Product boundary

The MVP is a Go CLI with JSON and Markdown output. It accepts local intent and plan files, requires no cloud account, and performs no network or cloud mutation. Object storage is the first cross-cloud vertical. Generation, natural-language intent parsing, live-state access, hosted services, dashboards, and deployment are explicitly deferred.

The detailed product requirements are normative in:

- `docs/PRODUCT.md`
- `docs/EVIDENCE-BUNDLE.md`
- `docs/INTENT-CONTRACT.md`

## Architecture

```text
Intent YAML/JSON ───────┐
                       ├─> Ingest -> Normalize -> Graph -> Policy -> Decision -> Evidence
Terraform plan JSON ───┘
```

Terraform-specific ingestion preserves actions and the distinction between known, unknown, absent, and redacted values. Provider mappers translate only supported semantics into a common model and retain provenance. Universal deterministic rules operate on that model. Unsupported or incomplete semantics remain explicit and can cause `UNKNOWN`.

The full component, dependency, error, sensitive-data, and testing design is normative in `docs/ARCHITECTURE.md`.

## Decision semantics

- `BLOCK` requires at least one deterministically evidenced blocking finding.
- `WARN` requires human judgment but no blocking finding.
- `UNKNOWN` means evidence required for a safe conclusion is unavailable.
- `PASS` means all required supported checks completed without warning or blocking findings.

Severity and enforcement disposition are separate fields. This prevents impact labels from silently becoming policy decisions.

## Delivery sequence

1. Evidence Bundle types, invariants, canonical JSON, Markdown, and exit mapping.
2. Safe Terraform/OpenTofu plan parsing and value-state preservation.
3. AWS, Azure, and GCP object-storage mapping plus one universal public-access rule.
4. structured intent loading, destructive/cloud/environment checks, and the complete `check` command.
5. MCP adapter only after the core interface and security behavior stabilize.

Each milestone is independently specified in `docs/milestones/`. Claude Code must plan and implement one milestone at a time, with tests written before implementation and a fresh-session independent review.

## Acceptance boundary

The MVP is accepted when equivalent public-storage changes across all three clouds produce the same stable rule with provider-specific evidence; destructive changes and explicit intent mismatches are identified; sensitive and unknown facts cannot be accidentally presented as safe; output is deterministic and versioned; and the entire test suite runs without cloud credentials.

## Handoff

`CLAUDE.md` is the permanent engineering and safety contract. `docs/CLAUDE-CODE-HANDOFF.md` contains the exact planning, implementation, and independent-review prompts.
