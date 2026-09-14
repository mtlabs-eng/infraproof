# Milestone 03: Multi-cloud object storage

## Objective

Prove the provider-neutral design by detecting provable public object storage across AWS, Azure, and GCP using one universal policy rule.

## Scope

- AWS, Azure, and GCP mapper interfaces and implementations
- normalized object-storage resource model
- fact provenance
- graph correlation for related access-control resources
- universal `STORAGE_PUBLIC` rule
- safe, public, unknown, absent, and redacted fixtures per cloud

## Initial resource families

Fixture research must identify the exact resource types and provider versions used. At minimum, cover the standard bucket/storage-account resource and the related access-control mechanism needed to prove public access for each cloud.

Do not assume that one boolean fully represents public exposure. If public access depends on a policy, IAM member, ACL, container, or account-level setting missing from the plan, return `UNKNOWN`.

## Acceptance criteria

- Equivalent public scenarios in all three clouds produce `STORAGE_PUBLIC`.
- Equivalent private scenarios do not produce a public finding when sufficient evidence is present.
- Missing required related resources produces `UNKNOWN`.
- Every normalized fact records provider-specific provenance.
- The universal rule imports no provider-specific package.
- Adding a mapper does not require changing the universal rule.
- Cross-cloud contract tests and all existing tests pass.
