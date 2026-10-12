# Milestone 10: verification method

## Objective

Give every finding the verification method `CLAUDE.md` requires of trustworthy
output, as a statement of **how each fact the verdict rests on was established**
-- and stop presenting a value the provider defaulted, a value read from a table,
or a value interpreted from a policy document as though the plan had stated it.

## Why this, and why now

`CLAUDE.md` lists a verification method among the things every finding must
include. No finding has ever carried one: milestone 09 recorded it as a
limitation that predates every family, and deferred it to a milestone that
decides what the values are. This is that milestone.

It is not a cosmetic field. Measured at `3b50544`, a mapper that applies a
provider default to an argument nobody wrote cites exactly the attribute path it
would cite had the author written the value -- AWS `publicly_accessible`, GCP
`settings.ip_configuration.ipv4_enabled` -- and GCP's defaulted `direction` is
not cited at all. A reader of a `BLOCK` resting on a default cannot tell it from
one resting on a stated value. The only provenance that survives to the policy
layer today is one boolean, `DatabaseCapabilities.PortInferred`, and it reaches
the bundle only as an unknown.

## Product decisions taken before implementation

- **The method describes provenance, not technique.** A per-rule technique name
  (`address-range-sweep`) would be constant per rule and say nothing about how
  strong the proof behind *this* finding is. A pointer into the bundle-level
  `verification[]` would read `terraform_plan` on every finding. What a reader
  needs is whether the verdict rests on something the plan states, something
  the provider defaults, or something this build inferred.
- **A finding carries a list of steps, one per fact.** A database verdict rests
  on an endpoint switch, an admission and a port, and those can have three
  different provenances. Reducing them to the weakest would require fixing an
  order of strength in a public format; a deduplicated set of methods would not
  say which applies to what. A list of `{fact, method}` is exact, and a consumer
  can compute the weakest link itself.
- **The field is named `verification_steps`.** It is a list, and the bundle
  already has a top-level `verification[]` that describes input coverage, not
  findings. `EVIDENCE-BUNDLE.md` ties the name to the "verification method" of
  `CLAUDE.md`.
- **The method is closed and versioned:**

  | method | means |
  | --- | --- |
  | `plan-stated-value` | the value is stated in the plan |
  | `provider-default` | the argument is unwritten, and the value is the provider's documented default |
  | `policy-document-interpreted` | the value results from this build's reading of a JSON policy document |
  | `reference-resolved` | the fact joins two resources through configuration references |
  | `documented-table` | the value comes from a closed, documented table in this build |
  | `plan-action` | the value is the classification of the plan's actions |
  | `intent-comparison` | the fact is the comparison with the intent contract |

  `policy-document-interpreted` is kept apart from `plan-stated-value` on
  purpose. A hand-written model of another layer's grammar is where this build
  has repeatedly failed in the direction that hides a grant, and a reader should
  be able to see when a verdict rests on one.
- **The method is never load-bearing.** No decision, disposition or exit code
  depends on it -- the same rule `location` follows. Letting provenance change a
  verdict is a policy change, and policy configuration is a later milestone.
- **The method lives on the fact, and the mapper must state it.**
  `model.Known(v, sources...)` becomes `model.Known(v, method, sources...)`;
  there is no constructor without a method, so the compiler lists every site a
  mapper has to decide. The zero value of the method is invalid, so a `KNOWN`
  fact nobody gave a method fails validation rather than reading as
  `plan-stated-value` -- a default of "stated" would be exactly the defect this
  milestone exists to remove. Only `KNOWN` facts carry a method; the other states
  have no value to have established.
- **The policy adds the steps only it knows:** the comparison with the contract,
  the classification of actions, and the hop from a database to the gate that
  decided its admission. It never recomputes a method a fact already carries.
- **A fact derived from several inputs takes the method of the one that is not
  stated.** A GCP rule whose `source_ranges` are stated and whose `direction` is
  defaulted is `provider-default`: the verdict is only as strong as its weakest
  input, and naming that input is the point. Every site measured at `3b50544`
  mixes at most one input that is not stated. A site that would mix two is a
  finding the plan must report, not something to settle by inventing an order
  of strength in a public format.
- **A disjunctive grant takes the method of the proof the mapper cites.** AWS
  storage settles on the first unblocked granting channel, the ACL before the
  policy; GCP storage on any granting binding. A grant proven by a stated value
  is `plan-stated-value` even when an interpreted policy document also grants,
  because the stated proof is the one the finding cites.
- **`PortInferred` stays.** Measured while planning: Azure's port comes from a
  table keyed on the resource type, so its method is `documented-table`, and the
  Azure mapper documents that port as certain rather than a default -- which is
  why `PortInferred` is false there. The method says where a value came from;
  `PortInferred` says whether the deployment could differ from it. Folding one
  into the other would make `DATABASE_PORT_INFERRED` claim an Azure port is a
  default. `DATABASE_PORT_INFERRED` keeps reading `PortInferred`.

## Shape

```json
"verification_steps": [
  { "fact": "database.public_endpoint", "method": "plan-stated-value" },
  { "fact": "database.admitted_by",     "method": "reference-resolved" },
  { "fact": "database.port",            "method": "documented-table" },
  { "fact": "contract.database.exposure", "method": "intent-comparison" }
]
```

A step carries a fact path and a method, and no value -- the same discipline as
an evidence reference. A step's `fact` is a capability path for a plan fact and
`contract.<family>.<field>` for the comparison with the contract.

| rule | steps |
| --- | --- |
| `STORAGE_PUBLIC` | `object_storage.public_access` with the fact's method; the contract comparison |
| `NETWORK_PUBLIC_INGRESS` | `network.public_ingress` with the fact's method; the contract comparison |
| `DATABASE_PUBLIC_REACHABLE` | `database.public_endpoint` with the fact's method; `database.admitted_by` with the mapper's method, or `reference-resolved` plus the gate's `network.public_ingress` method when a gate decided; `database.port` with the fact's method when the port entered the verdict; the contract comparison |
| `DESTRUCTIVE_CHANGE` | `change.destructive` with `plan-action`; the contract comparison |
| `CLOUD_NOT_ALLOWED` | `resource.cloud` with `plan-stated-value`, from `provider_name`; the contract comparison |
| `ENVIRONMENT_MISMATCH` | `resource.environment` with the fact's method; the contract comparison |

The contract comparison is emitted on every finding, including one where the
contract declares nothing: silence is read, and is what made the finding a
`WARN`.

## Scope

- Evidence Bundle `1.3`: `verification_steps` on `Finding`, its validation, its
  canonical order, and the JSON and Markdown renderers. The pull-request review
  renderer is unchanged.
- `model.Fact[T]` gains the method; `model.Known` requires it.
- Every mapper in the three families and three clouds states a method on every
  `KNOWN` fact. The sites measured as not `plan-stated-value`:
  - AWS database: the defaulted `publicly_accessible` is `provider-default`; the
    engine-derived port is `documented-table`.
  - GCP database: the defaulted `ipv4_enabled` is `provider-default`; the
    `database_version`-derived port is `documented-table`.
  - GCP network: a rule whose `direction` is defaulted is `provider-default`.
    Its citation is unchanged: `direction` is still not cited, because adding
    evidence would change bundles that criterion 8 holds fixed.
  - Azure database: the port derived from the resource type is
    `documented-table`.
  - AWS and GCP storage: a grant found by reading a policy document is
    `policy-document-interpreted`.
  Measured while planning: AWS unwritten `ingress` only suppresses an unread
  set. `Known(false)` requires the set to be stated and `Known(true)` rests on a
  stated separate rule, so the default never decides a KNOWN fact and every AWS
  network fact is `plan-stated-value`.
- `EVIDENCE-BUNDLE.md`, `docs/examples/evidence-bundle.json`, `ARCHITECTURE.md`
  and `PRODUCT.md` where they describe a finding.

## Safety semantics

- A bundle declaring `1.3` or later carries at least one step on every finding.
- A bundle declaring `1.2` or earlier is valid without the field; one that
  carries it must carry it well-formed, whatever version it declares -- the rule
  `intent_digest` already follows.
- A step's `fact` is non-empty and a single line; its `method` is in the closed
  set. Anything else is invalid input, not a verdict.
- Steps are ordered by `fact`, then `method`, and the field takes part in the
  total order of findings.
- A step carries no value, so no sensitive value can travel through one.

## Acceptance criteria

1. Every finding of every rule carries at least one step, every method is in the
   closed set, and a test asserts it over all committed baselines rather than a
   sample.
2. A bundle declaring `1.3` with a finding carrying no step is rejected; so is an
   unknown method, an empty or multi-line `fact`, and a `1.2` bundle carrying the
   field malformed. A `1.2` bundle without the field is accepted.
3. For the two provider defaults that can produce a finding -- GCP
   `ipv4_enabled` and GCP `direction` -- a pair of fixtures, the argument written
   and the argument unwritten, produces findings that differ in the method of
   that step and **nowhere else**.
   The AWS `publicly_accessible` default resolves to `Known(false)` and can
   never produce a finding; a mapper test asserts its method on the fact instead.
4. On AWS, where the port can enter a verdict, an engine-derived port is
   `documented-table` and a stated port is `plan-stated-value`, in the step. On
   Azure and GCP the port reaches no decision (a milestone 09 limitation), so a
   mapper test asserts `documented-table` on the fact.
5. A storage grant found by interpreting a policy document is
   `policy-document-interpreted` on AWS and GCP.
6. An AWS database admitted through an open security group carries
   `reference-resolved` and the gate's own method.
7. A `KNOWN` fact with no method cannot be constructed, and one with the zero
   method fails validation.
8. No verdict changes. The 226 baselines recorded at `3b50544` are not
   re-recorded: the baseline test removes `verification_steps` and restores
   `schema_version: "1.2"` before comparing, so every one of them still matches
   byte for byte -- `DATABASE_PORT_INFERRED` included. The plan fixtures with no
   baseline are compared by building binaries at `3b50544` and at the end of
   this milestone, as milestone 09 did.
9. Replacing any one `provider-default`, `documented-table` or
   `policy-document-interpreted` assignment with `plan-stated-value` breaks at
   least one test, measured by hand and recorded here.
10. The universal rules import no provider-specific package, and the method
    reaches no decision, disposition or exit code.

## Explicitly out of scope

- Extending the actionable half of `CORRELATION_UNRESOLVED` to the network and
  database families. It changes all three capabilities and milestone 09 judged it
  worth its own milestone.
- A mechanical guard against a rule reading `NormalizedResource.Removed` on a
  family that never sets it.
- Citing the AWS `vpc_security_group_ids` attribute through which a database
  reached its gate. That is missing evidence, not a missing method, and stays a
  limitation.
- Verification steps on unknowns. `CLAUDE.md` requires a method of findings; an
  unknown is a statement that a method could not be completed.
- Any policy that reads the method: blocking only on stated values, treating a
  default as a warning, or configuring `UNKNOWN`.
- Re-recording the baselines, or an automatic recording flag. They stay the
  milestone 09 verdict baseline, and criterion 8 compares against them as they
  are.

## Prerequisites

Milestones 01, 03, 08 and 09. The plan should report, as milestone 09 did, any
shared machinery this milestone turns out to need changed beyond `model.Fact`
and the mappers' call sites.
