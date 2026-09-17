# InfraProof product definition

## Problem

Coding agents can create infrastructure code faster than platform teams can review it. Existing linters, policy engines, and Terraform runners validate valuable fragments of a change, but they do not consistently compare the original request, the proposed plan, organizational constraints, and the limits of available evidence.

A syntactically valid and policy-compliant configuration can still be wrong: it can target production instead of staging, expose a supposedly private service, replace a stateful resource, or alter a shared dependency outside the requested scope.

## Product promise

InfraProof independently verifies agent-generated Terraform and OpenTofu changes before deployment. It reports whether the proposed change matches declared intent, identifies material risk, and supports each conclusion with reproducible evidence.

## Primary users

- Platform engineers reviewing infrastructure pull requests
- Developers using Claude Code, Codex, Cursor, or another coding agent
- SRE and cloud-security teams defining deployment guardrails

## Initial workflow

1. A human or agent creates Terraform code.
2. The user's environment creates a saved plan and converts it to JSON.
3. The user supplies a structured intent contract and the plan JSON to InfraProof.
4. InfraProof parses and normalizes the plan.
5. Deterministic rules evaluate intent, risk, and supported cloud semantics.
6. InfraProof emits an Evidence Bundle and a decision.
7. A human, agent, or CI system uses the result without InfraProof applying infrastructure.

## Decisions

- `PASS`: all required checks were performed and no blocking or warning findings remain.
- `WARN`: the change is understood but requires an explicit human decision.
- `BLOCK`: deterministic evidence proves that the change violates a blocking rule or declared intent.
- `UNKNOWN`: required evidence is absent, ambiguous, sensitive-only, or unsupported.

`UNKNOWN` is not equivalent to `PASS`. Policy decides whether CI treats it as warning or failure.

## MVP scope

- Go CLI
- Terraform/OpenTofu plan JSON ingestion
- Structured YAML/JSON intent contract
- Versioned normalized change graph
- AWS, Azure, and GCP provider mappers
- Object-storage public-access detection as the first vertical slice
- Generic destructive-change and environment-mismatch rules
- JSON and Markdown Evidence Bundle output
- Fixture-driven tests with no cloud accounts

## What a result means

InfraProof reports what a plan proves, not what is true about the infrastructure.

A `PASS` means no plan-provable public exposure was found among the resource
types this build understands. It is not a statement that nothing is public.
Exposure routes outside the current model are not examined: Azure static
websites and network rules, GCP IAM conditions and legacy ACLs, AWS inline
bucket `acl`, `policy` and `grant` arguments, and any control applied outside
the plan.

Where the plan does not determine exposure, InfraProof answers `UNKNOWN`, and
`UNKNOWN` is not `PASS`. It is the honest answer in more cases than a reader may
expect, because a Terraform plan records which values take part in an expression
and never how they are combined — so a control that reaches one instance of a
repeated resource cannot be attributed to a particular one. Naming the instance
in the configuration, rather than deriving it, is what makes such a plan
answerable.

## Explicit non-goals

- Generating Terraform code
- Parsing natural-language intent
- Executing plans
- Reading live cloud state
- Replacing HCP Terraform, Spacelift, env0, Firefly, or an internal developer platform
- Claiming complete coverage of every resource in any cloud
- Automatically learning blocking policies
- Providing runtime assurance after deployment

## Product success criteria

The MVP succeeds when it can:

1. evaluate equivalent public-storage scenarios across AWS, Azure, and GCP through one common rule;
2. identify destructive Terraform actions without cloud access;
3. distinguish false, true, absent, sensitive, and unknown facts;
4. trace every finding to source plan data;
5. return `UNKNOWN` instead of overstating certainty;
6. produce stable JSON suitable for CI and readable Markdown suitable for review;
7. pass all tests using local fixtures and mocked providers only.

## Future direction

After the verifier proves useful, expand in this order:

1. additional storage semantics and organizational policies;
2. databases, IAM, networking, and managed Kubernetes;
3. MCP adapter and pull-request integrations;
4. optional natural-language-to-intent conversion with human confirmation;
5. optional customer-side live-state collectors;
6. remediation and generation only after independent verification is trusted.
