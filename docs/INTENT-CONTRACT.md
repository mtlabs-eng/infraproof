# Intent Contract

## Purpose

The Intent Contract is a structured document confirmed by a human. It records what a change is allowed and expected to do. Natural-language extraction is deliberately outside the MVP.

## Format

**This build reads JSON only.** YAML is the intended authoring format and remains the direction, but Go has no YAML reader in its standard library, and this project declares no external dependencies. Adding one would put third-party parsing code on a file the user controls, which is the surface the offline-first design exists to avoid. YAML is therefore deferred to its own milestone rather than bought on credit, and a YAML file handed to `check` is refused by name rather than failing as a JSON syntax error.

The example below is written in YAML because it is the clearer form to read. `examples/intent.json` is the same contract in the format this build accepts.

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

`unspecified` is explicit uncertainty: the author considered exposure and declined to commit, and no exposure rule is applied. An omitted required field is an invalid contract — a contract that did not say what it permits is not read as permitting anything.

A resource entry carries no address, and resource cardinality is deferred below. An entry therefore constrains **every** resource of its family in the plan. That is the only reading which does not require the cardinality this contract cannot yet express, and it fails safe: adding a resource to a plan does not escape a declared intent.

An entry is also a requirement to be exercised, not only a constraint to be satisfied. A contract carries a `change_id` and is written for one change, so a declaration the change gives nothing to apply to is a requirement the run could not verify, and it produces `UNKNOWN` rather than `PASS` — a constraint satisfied by an empty set was checked against nothing. An author who means to leave the question open writes `exposure: unspecified`, which asks for nothing and is never reported as unexercised.

## Matching rules

- A plan affecting a cloud outside `allowed_clouds` is a blocking mismatch.
- A provably public object-storage resource contradicting `exposure: private` is blocking.
- An unknown exposure for a required private resource produces `UNKNOWN`.
- A destructive action with `destructive_changes: forbidden` is blocking.
- Environment matching uses an explicit declaration only: a tag or label whose key is `environment`, matched without regard to case, read from `tags` on AWS and Azure and `labels` on GCP. A module path, a provider alias, a workspace name and a file name are all guesses about a name, and none is sufficient evidence for blocking. A resource carrying no readable declaration is reported as evidence the run did not have, never as a disagreement.
- Extra resources are reported; whether they block is deferred until resource cardinality and scope are specified.

## What this build does not evaluate

`constraints` is loaded and validated but no rule reads it. Every constraint present in a contract is reported as a non-required unknown naming the field, so a restriction the contract states and nothing enforces cannot sit silently beside a `PASS`.

## Trust boundary

The contract expresses declared intent, not truth. InfraProof records its digest and evaluates consistency, but authentication, approval identity, and cryptographic authorization are future concerns.
