# Intent Contract

## Purpose

The initial Intent Contract is structured YAML or JSON confirmed by a human. It records what a change is allowed and expected to do. Natural-language extraction is deliberately outside the MVP.

## Version 1 example

```yaml
schema_version: "1.0"
change_id: add-private-staging-assets
environment: staging
allowed_clouds:
  - aws
destructive_changes: forbidden
resources:
  - family: object_storage
    exposure: private
    purpose: application-assets
constraints:
  allowed_regions:
    - eu-west-1
  required_tags:
    owner: checkout
```

## MVP fields

- `schema_version`: required contract version.
- `change_id`: required human-readable identifier; not authorization.
- `environment`: required target environment.
- `allowed_clouds`: non-empty set containing `aws`, `azure`, or `gcp`.
- `destructive_changes`: required, `forbidden` or `allowed_with_warning`.
- `resources`: one or more desired resource capabilities.
- `constraints`: optional explicit restrictions.

Initial resource intent:

```text
family: object_storage
exposure: private | public | unspecified
purpose: optional string
```

`unspecified` is explicit uncertainty. An omitted required field is an invalid contract.

## Matching rules

- A plan affecting a cloud outside `allowed_clouds` is a blocking mismatch.
- A provably public object-storage resource contradicting `exposure: private` is blocking.
- An unknown exposure for a required private resource produces `UNKNOWN`.
- A destructive action with `destructive_changes: forbidden` is blocking.
- Environment matching initially uses explicit normalized tags, provider aliases, module paths, or configured mappings. Filename guessing alone is not sufficient evidence for blocking.
- Extra resources are reported; whether they block is deferred until resource cardinality and scope are specified.

## Trust boundary

The contract expresses declared intent, not truth. InfraProof records its digest and evaluates consistency, but authentication, approval identity, and cryptographic authorization are future concerns.
