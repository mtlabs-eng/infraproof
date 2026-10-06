# InfraProof architecture

## System context

InfraProof is a local, read-only analysis pipeline.

```text
Intent YAML/JSON ───────┐
                       ├─> Ingest -> Normalize -> Graph -> Policy -> Decision -> Evidence
Terraform plan JSON ───┘
```

No component in the MVP authenticates to or mutates AWS, Azure, GCP, Terraform Cloud, a source-code host, or an LLM service.

## Components

### CLI

Owns argument parsing, file access, output selection, exit codes, and user-facing errors. It contains no policy or provider semantics.

Initial command:

```text
infraproof check --intent <path> --plan <path> [--format json|markdown]
```

### Intent loader

Loads and validates a versioned Intent Contract. It rejects invalid structure and preserves omitted values as unspecified rather than inventing defaults. This build reads JSON only; see `docs/INTENT-CONTRACT.md` for why YAML is deferred.

### Terraform plan loader

Loads the documented Terraform plan JSON representation. It validates supported format versions and extracts:

- provider configuration references;
- resource addresses and types;
- change actions;
- before and after values;
- unknown-value metadata;
- sensitive-value metadata;
- configuration references needed for dependency edges.

A reference is not a relation. Correlation admits one only where a mapper declares the relation whole — the type that claims, the argument carrying the claim, and the type claimed — so a mention, an ordering dependency, or an interpolation of another resource's name cannot become a governance edge. A mapper that declares relations and declares none from a type has said that type makes no claims, and every reference it writes is a mention. A mapper that understands a type and declares no relations at all has said nothing, and its references are admitted, because narrowing what is not understood drops correlations this build cannot reason about either way. Silence and a statement are different answers.

The loader must not render raw sensitive values in diagnostics.

### Provider mappers

Mappers translate supported provider-specific resources into normalized resources and capabilities. The initial mappers are:

- `registry.terraform.io/hashicorp/aws`
- `registry.terraform.io/hashicorp/azurerm`
- `registry.terraform.io/hashicorp/google`

Each mapper declares which resource types and capability fields it supports. Unsupported resources remain in the graph as opaque resources; they are not discarded.

### Normalized change graph

The graph contains:

- resource identity and provider;
- resource family and cloud;
- proposed actions;
- normalized capabilities;
- provenance for each normalized fact;
- dependency edges when supported;
- unknown and sensitive markers.

A normalized fact is not merely a value. It contains value state and provenance:

```text
Fact<T> = Known(T) | Unknown | Absent | Redacted
```

`Absent` means the source field was not present. It must not automatically be interpreted as a safe provider default.

### Policy engine

Evaluates pure deterministic rules over the Intent Contract and normalized graph. A rule returns zero or more findings. Initial rules are compiled Go code with stable identifiers; external policy languages are deferred.

Rules are split into:

- universal rules over normalized capabilities;
- provider-specific rules for semantics that cannot be safely normalized.

### Decision engine

Aggregates findings and required verification coverage. Default precedence:

```text
BLOCK > UNKNOWN > WARN > PASS
```

This is subject to explicit policy configuration in a later milestone. Invalid input and internal failure are operational errors, not decisions.

### Evidence renderer

Produces the versioned Evidence Bundle. JSON is canonical. Markdown is a deterministic rendering of the same in-memory result.

## Initial normalized resource model

```text
ResourceChange
  address
  provider_address
  cloud: aws | azure | gcp | unknown
  family: object_storage | unknown
  actions: create | read | update | delete | no_op
  capabilities
  dependencies

ObjectStorageCapabilities
  public_access: Fact<bool>
  encryption_at_rest: Fact<bool>
  deletion_protection: Fact<bool>
```

Only `public_access` is required in the first vertical slice. The remaining fields reserve product concepts, not an instruction to implement them early.

## First provider mappings

The exact Terraform schema varies by provider version, so mappings must be fixture-backed and version-aware where semantics differ.

- AWS: S3 bucket plus related public-access-policy resources
- Azure: Storage Account public network and blob-container access semantics
- GCP: Cloud Storage bucket IAM/public-access-prevention semantics

Some public-access conclusions require correlating multiple Terraform resources. A mapper may emit partial facts and graph edges; the universal rule evaluates the combined result. If required evidence is missing, the result is `UNKNOWN`, not safe.

## Sensitive data handling

- Inputs are local files.
- Raw plans are never copied into output.
- Evidence uses resource addresses, field paths, action types, and redacted summaries.
- Fields identified by Terraform as sensitive remain `Redacted`.
- Diagnostics must mention the field path without including its value.
- Tests must include nested sensitive values and error paths.

## Error model

Operational failures are separate from verification decisions:

- invalid CLI usage;
- unreadable input;
- invalid intent;
- invalid JSON;
- unsupported plan format major version;
- internal invariant violation.

An unsupported resource or missing semantic fact is normally `UNKNOWN`, not an operational error.

## Package boundaries

Planned Go packages:

```text
cmd/infraproof
internal/intent
internal/terraformplan
internal/tfconfig
internal/model
internal/providers/aws
internal/providers/azure
internal/providers/gcp
internal/policy
internal/decision
internal/evidence
internal/render
```

Ordering lives in the mapper, not in the rule. Two of the three clouds resolve ingress through an ordered set with deny rules and priorities, and they disagree about the ordering itself: GCP gives a deny precedence over an allow of equal priority, Azure forbids the tie, AWS has neither. A rule that knew any of that would be a rule that has to change when a fourth cloud arrives. By the time a rule reads a capability, the answer is about the set.

Provider packages may depend on `model`. The policy engine depends on `model` and intent types. Core packages must not import provider packages, CLI packages, MCP code, or LLM clients.

`internal/tfconfig` reads Terraform configuration to say where a declaration is written. It is the only package that reads a `.tf` file, it reads nothing outside the directory the caller supplies, and neither `policy` nor `model` may import it: a rule that could reach the filesystem would be a rule whose verdict changed when a file moved. It depends on `terraformplan` for the identity of each declaration, because deriving one from an address text would be a second grammar almost the same as the first.

## Testing strategy

- Where this build restates another tool's grammar, a test asks that tool. `internal/tfconfig` reads HCL, and four independent reviews of the milestone that added it found one class of defect and almost nothing else: the lexer disagreeing with Terraform. Each found it by hand-building cases nobody had thought of, and each time that work died with the reviewer. `TestScanAgreesWithTerraform` runs `terraform validate` over a corpus and requires this build to read every file Terraform accepts, at the right line — so the question survives the reviewer who thought to ask it. It skips when `terraform` is absent.
- Unit tests for parsing, normalization, rules, decisions, and rendering
- Golden tests for stable JSON and Markdown output
- Contract tests that run equivalent scenarios through all three provider mappers
- Fuzz tests for untrusted JSON boundary parsing after the parser is stable
- Fixtures that include safe, unsafe, unknown, absent, and sensitive variants
- Optional Terraform mock-provider generation of fixtures; committed sanitized JSON remains the deterministic test input

No MVP test requires a cloud account.
