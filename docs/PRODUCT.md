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
- Public-ingress detection as the second: security groups, network security groups
  and firewalls, through one rule that names no cloud
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

For network exposure the claim is narrower still, and deliberately so. A finding
says the change **permits ingress from any address**, not that anything becomes
reachable: reachability needs the attachment — an instance, a subnet, an
association — which is usually in another resource, another module, or already
exists. Asserting reachability would make most real plans `UNKNOWN`; the limit is
reported beside the finding instead. And one more asymmetry runs through this
family: a grant can be proven from part of a rule set, while closure cannot, so a
security group whose rules live in separate resources is `UNKNOWN` rather than
closed. Closure is never *fully* provable either — the providers advise against
mixing inline rules with separate rule resources and do not prevent it — so a
proven closure carries a non-required unknown saying a rule declared elsewhere
could admit more.

Where the plan does not determine exposure, InfraProof answers `UNKNOWN`, and
`UNKNOWN` is not `PASS`. It is the honest answer in more cases than a reader may
expect, because a Terraform plan records which values take part in an expression
and never how they are combined — so a control that reaches one instance of a
repeated resource cannot be attributed to a particular one. Naming the instance
in the configuration, rather than deriving it, is what makes such a plan
answerable.

This applies to resources repeated in their own right. A resource that is not
repeated inside a module that is takes its instance from the module, and every
resource in that module instance shares it, so nothing has to be chosen and
nothing has to change: the common module-per-bucket pattern stays answerable.

A `PASS` also means every change in the plan was examined, not merely that
nothing examined raised an objection. A data source is read rather than
changed, so it is not part of that guarantee — and a resource whose mode says
it is read while its actions say otherwise is not believed to be one.

What a data source says is never evidence about another resource, in either
direction. (This entered the product during review of milestone 04, for the
reason recorded in `docs/milestones/04-risk-and-intent.md`.) It describes state as it already is, which is not what the change
will do, so it can neither prove that exposure is prevented nor prove that it
is granted. This is the single largest determinant of what this tool will
conclude about a plan that contains one, so it is not silent about it: where a
read would have answered a question, the answer is `UNKNOWN` and the report
names what was withheld and why. A plan whose only account, policy or block is
read rather than managed is a plan this tool cannot settle, and saying so is
the honest answer rather than a limitation to work around. A
resource this build normalized but has no rule for is reported, and prevents a
`PASS`, because the alternative is a verdict that reads as "checked and fine"
when it means "not checked". The same holds for a resource no mapper
understood at all, and for a declaration in the contract that the plan gave
nothing to apply to.

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

Where the product grows after the verifier proves useful, in rough order of
dependence rather than of scheduling:

1. additional storage semantics and organizational policies;
2. databases, IAM, networking, and managed Kubernetes;
3. MCP adapter and pull-request integrations;
4. optional natural-language-to-intent conversion with human confirmation;
5. optional customer-side live-state collectors;
6. remediation and generation only after independent verification is trusted.

The order work is actually done in is the milestone files under
`docs/milestones/`, each of which states its own prerequisites. The two
disagreed: this list put the MCP adapter behind two layers of resource
semantics, while milestone 05 made it the next piece of work with milestones 01
through 04 as its prerequisite. The milestone files govern, and this list says
what the product becomes rather than in which order it is built.
