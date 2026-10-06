# Intent Contract

## Purpose

The Intent Contract is a structured document confirmed by a human. It records what a change is allowed and expected to do. Natural-language extraction is deliberately outside the MVP.

## Format

**This build reads JSON only.** YAML is the intended authoring format and remains the direction, but Go has no YAML reader in its standard library, and this project declares no external dependencies. Adding one would put third-party parsing code on a file the user controls, which is the surface the offline-first design exists to avoid. YAML is therefore deferred to its own milestone rather than bought on credit, and a YAML file handed to `check` is refused by name rather than failing as a JSON syntax error.

The example below is written in YAML because it is the clearer form to read. `examples/intent.json` is the same contract in the format this build accepts.

## Version 1 example

```yaml
schema_version: "1.1"
change_id: add-private-staging-assets
environment: staging
allowed_clouds:
  - aws
destructive_changes: forbidden
resources:
  - family: object_storage
    exposure: private
    purpose: application-assets
  - family: network
    public_ports: ["443"]
    purpose: public web tier
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

Resource intent, per family. **Each family declares what its own rule reads, and only that.**

```text
family: object_storage
exposure: private | public | unspecified
purpose: optional string
```

```text
family: network
public_ports: ["443", "80", "8000-8100"]   # ports that may be reachable from any address
purpose: optional string
```

An entry carrying the other family's field is refused rather than ignored. `exposure: private` beside a port that may be public states two things that can contradict each other, and deciding which one wins is worse than refusing the pair — a reader would otherwise believe the one that was ignored.

`public_ports` takes single ports and inclusive ranges. A port outside 0–65535, a range that runs backwards, and anything that is not a port number are all invalid contracts: a declaration nobody can read is one its author fixes, where one quietly emptied permits nothing while appearing to permit something.

Two further refusals exist so that one declaration has one spelling. A port written with a leading zero — `"00443"` — is refused, for the reason a version component is: two documents that are not byte-identical would declare the same thing, which a digest over the declaration cannot see. And a declaration that names the same port twice, or whose ranges overlap or meet, is refused as a repeated family and a repeated cloud already are — `["443", "443"]` is a mistake in a statement of intent rather than a statement, and it rendered an expected fact reading `443, 443`.

What a declaration permits is the **union** of its ranges. `["80", "81"]` has declared `80-81`, and a change opening `tcp/80-81` satisfies it; this was once read one range at a time, which reported a violation whose claim was untrue of every port involved. A gap is still a gap: `["1-10", "12-30"]` has not declared 11.

Presence is not length. `public_ports: []` is the most restrictive thing the field can say — no port may be reachable from any address — and an omitted entry is the absence of a statement, under which public ingress needs a human rather than being permitted or forbidden. Silence is not permission.

`unspecified` is explicit uncertainty: the author considered exposure and declined to commit, and no exposure rule is applied. An omitted required field is an invalid contract — a contract that did not say what it permits is not read as permitting anything.

A resource entry carries no address, and resource cardinality is deferred below. An entry therefore constrains **every** resource of its family in the plan. That is the only reading which does not require the cardinality this contract cannot yet express, and it fails safe: adding a resource to a plan does not escape a declared intent.

An entry is also a requirement to be exercised, not only a constraint to be satisfied. A contract carries a `change_id` and is written for one change, so a declaration the change gives nothing to apply to is a requirement the run could not verify, and it produces `UNKNOWN` rather than `PASS` — a constraint satisfied by an empty set was checked against nothing. An author who means to leave the question open writes `exposure: unspecified`, which asks for nothing and is never reported as unexercised.

## Matching rules

- A plan affecting a cloud outside `allowed_clouds` is a blocking mismatch.
- A provably public object-storage resource contradicting `exposure: private` is blocking.
- An unknown exposure for a required private resource produces `UNKNOWN`.
- A change permitting ingress from any address on a port `public_ports` does not cover is blocking. The claim is about the change, not about reachability: whether anything becomes reachable depends on an attachment that is usually not in the plan, and that limit is reported beside the finding rather than folded into it.
- A change permitting such ingress where the contract declares no `network` entry needs a human, because silence is not permission.
- A change permitting ingress on a protocol with no ports — ICMP, or a spelling this build does not recognize — needs a human too. A port list can neither permit nor forbid it, and this build will not decide on its own that ping from the internet is a violation.
- An ingress rule set the plan does not contain in full produces `UNKNOWN`. A grant can be proven from part of a set; closure cannot.
- A destructive action with `destructive_changes: forbidden` is blocking.
- Environment matching uses an explicit declaration only: a tag or label whose key is `environment`, matched without regard to case, read from `tags` on AWS and Azure and `labels` on GCP. A module path, a provider alias, a workspace name and a file name are all guesses about a name, and none is sufficient evidence for blocking. A resource carrying no readable declaration is reported as evidence the run did not have, never as a disagreement.
- Extra resources are reported; whether they block is deferred until resource cardinality and scope are specified.

## Compatibility

The major version is the boundary. `public_ports` and the `network` family arrived in `1.1`; a `1.0` contract is still read, because a minor addition cannot change what an earlier contract meant. A later major version is refused rather than read partially, since it may redefine a field this build believes it understands.

Both directions are read, including the awkward one. A `1.0` contract that carries `public_ports` is accepted and the field takes effect, even though the document claims to predate it. The version says which fields a reader may expect, not which ones are forbidden, and the field is an explicit statement by an author: refusing it would refuse intent on a technicality, and silently dropping it would be worse — the contract would then permit less than what was written, with nothing said about it.

## What this build does not evaluate

`constraints` is loaded and validated but no rule reads it. Every constraint present in a contract is reported as a non-required unknown naming the field, so a restriction the contract states and nothing enforces cannot sit silently beside a `PASS`.

## Trust boundary

The contract expresses declared intent, not truth. InfraProof records its digest and evaluates consistency, but authentication, approval identity, and cryptographic authorization are future concerns.
