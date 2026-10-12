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
  different provenances. A deduplicated set of methods would not say which
  applies to what. A list of `{fact, method}` is exact, and a consumer can
  compute the weakest link itself. *Amended:* this bullet also argued that
  reducing several methods to the weakest would require fixing an order of
  strength in a public format. The adversarial review fixed one anyway, for the
  inputs of a single fact (`EVIDENCE-BUNDLE.md`, `declared.Weakest`); the steps
  of a finding stay one per fact.
- **The field is named `verification_steps`.** It is a list, and the bundle
  already has a top-level `verification[]` that describes input coverage, not
  findings. `EVIDENCE-BUNDLE.md` ties the name to the "verification method" of
  `CLAUDE.md`.
- **The method is closed and versioned:**

  | method | means |
  | --- | --- |
  | `plan-stated-value` | the plan's configuration records that the author wrote the argument with a value, decided at the place the verdict reads (a map key, a whole rule set): any write on a new object; any write the plan does not contradict where the update moves the value there; where the update keeps the value there, only a constant written there that the planned value is shown to equal -- `null`, and an attribute a block does not write, match only an empty value (null, `[]`, `{}`, `""`, `false`). Never by default. The policy also assigns it to `resource.cloud`, from `provider_name` |
  | `provider-default` | the configuration records the argument as unwritten, or written as `null`, and the value is not carried from prior state: the provider's documented default, on a new object or where the plan moves the value to it |
  | `prior-state` | the change keeps an existing object and, at the place the verdict reads, the plan keeps the value it had while the configuration records it unwritten or written as `null`, or the configuration records a constant the planned value is not, moved or not (`lifecycle { ignore_changes }`; a provider that canonicalizes a constant also lands here, understated) |
  | `configuration-unrecorded` | the plan does not record whether the author wrote the argument with a value; or, on an update or no-op that keeps the value at the place the verdict reads, the plan cannot show the write is it: an expression the plan does not evaluate -- a reference, a variable, a function -- an attribute of a repeated block, or a constant compared with a value the plan withholds as sensitive or does not know |
  | `policy-document-interpreted` | the value results from this build's reading of a JSON policy document |
  | `reference-resolved` | the value is obtainable only by resolving a reference: the security groups a database reaches through `vpc_security_group_ids` |
  | `documented-table` | the value comes from a closed, documented table in this build |
  | `plan-action` | the value is the classification of the plan's actions |
  | `intent-comparison` | the fact is the comparison with the intent contract |

  `prior-state` and `configuration-unrecorded` were added by the adversarial
  review (decision D1, see the amendment below); 1.3 was unreleased, so the
  schema version stays `1.3`. The fourth review's fix wave sharpened the first
  four rows to what the table above says: carried is decided by comparing
  `before` with `after`, a `null` write is no write, and `provider-default` is
  a value not carried rather than strictly a value on a new object, because an
  update that plans an unwritten argument back to its default is neither of the
  other two. The third fix wave narrowed `plan-stated-value` and widened
  `configuration-unrecorded` by the user's decision recorded in the amendment
  "user decision on unevaluated writes" below, and the fifth review's fix wave
decided all four at the place the verdict reads (amendment "adversarial
review, round 5"). `reference-resolved` was narrowed by decision
  D2: a grant written on its own ACL, IAM or firewall-rule resource is stated,
  and the reference that joins it to a bucket or a server only locates where
  it applies.

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
  input, and naming that input is the point. *Amended by the adversarial
  review:* the claim that every site mixes at most one non-stated input was
  false (an unrecorded allow beside a defaulted direction, a carried prevention
  beside a binding), so the order is now fixed and documented in
  `EVIDENCE-BUNDLE.md` and `declared.Weakest`: `configuration-unrecorded`, then
  `prior-state`, then `provider-default`, then any method this build derived,
  then `plan-stated-value`. A grant that rests on an interpreted policy
  document keeps `policy-document-interpreted` beside a defaulted gate, as
  before, on AWS and now GCP alike.
- **A disjunctive grant takes the method of the proof the mapper cites.** AWS
  storage settles on the first unblocked granting channel, the ACL before the
  policy, and cites that channel alone; GCP storage cites every binding and
  takes the best granting one, and so do an AWS security group and an Azure
  NSG among the rules that open something. The fourth review read
  `EVIDENCE-BUNDLE.md`'s "the best of its proofs" as contradicted by AWS
  storage; the code was kept, because taking the policy's method while citing
  the ACL's sources would name a proof the finding does not cite, and the
  document now says which proof each cloud cites. A grant proven by a stated value
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
`contract.<field>` or `contract.<family>.<field>` for the comparison with the
contract; both shapes are emitted (`contract.environment`,
`contract.object_storage.exposure`).

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
  network fact is `plan-stated-value`. *False, found by the adversarial review:*
  `ingress` is Optional and Computed, so an update carries an inline set nobody
  wrote from state, and `Known(true)` rested on it as stated. The fix wave below
  lists every site as built.
- `EVIDENCE-BUNDLE.md`, `docs/examples/evidence-bundle.json`, `ARCHITECTURE.md`
  and `PRODUCT.md` where they describe a finding.

The list above is the scope as planned. The adversarial review's fix waves
superseded it site by site -- GCP `ipv4_enabled` and `direction`, for one, are
no longer simply `provider-default` -- and "Limitations as built" below is what
the code does.

## Safety semantics

- A bundle declaring `1.3` or later carries at least one step on every finding.
- A bundle declaring `1.2` or earlier is valid without the field; one that
  carries it must carry it well-formed, whatever version it declares -- the rule
  `intent_digest` already follows.
- A step's `fact` is non-empty and a single line; its `method` is in the closed
  set. Anything else is invalid input, not a verdict.
- Added by the adversarial review: a step's `fact` is dotted lower-case
  segments; no fact is established twice in one finding; and from `1.3` every
  finding carries the comparison with the contract, a `contract.` fact
  established by `intent-comparison`.
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
3. For the two provider defaults that were known to produce a finding when
   this was written -- GCP `ipv4_enabled` and GCP `direction` -- a pair of
   fixtures, the argument written and the argument unwritten, produces findings
   that differ in the method of that step and **nowhere else**. *Amended:* the
   defaults measured since are wider -- firewall `priority`, the S3 block
   flags, GCP `public_access_prevention`, Azure `public_network_access_enabled`,
   `allow_nested_items_to_be_public` and `container_access_type` -- and each is
   pinned by a mapper test and, where a finding shows it, a policy test; the two
   pairs above are the ones measured as true pairs (see the amendment).
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
7. A `KNOWN` fact with no method cannot be constructed through `model.Known`,
   and one with the zero method fails validation. *Amended:* `Fact.State` is
   exported, so a struct literal can still build one; nothing in the shipped
   code does, and validation at the bundle boundary refuses the step it would
   produce. A fake `Known(false)` builds no finding and so no step.
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
- The milestone 09 GCP defect where an unresolvable `dynamic "ip_configuration"`
  is read as `Known(true)` by the provider's default. It is a value defect, and
  this milestone changes no value. The method now says
  `configuration-unrecorded` there, which at least stops calling it a default.
- MCP `explain_finding` emitting a finding without validating its bundle. It
  predates this milestone; `analyze_change` validates through the renderer.
- An Aurora instance in a child module whose `cluster_identifier` comes from a
  module variable (`cluster = aws_rds_cluster.c.id` passed in) answers
  `UNKNOWN AWS_DATABASE_CLUSTER_NOT_IN_PLAN` rather than the root module's
  `WARN`: the cluster join does not follow a module variable. Found by the
  fourth review; it is milestone 09 correlation behaviour, conservative, and no
  method is involved.

## Prerequisites

Milestones 01, 03, 08 and 09. The plan should report, as milestone 09 did, any
shared machinery this milestone turns out to need changed beyond `model.Fact`
and the mappers' call sites.

## Limitations as built

Written from what the tests measure at the end of the milestone, after the
fifth review's fix wave.

- **The method follows what the configuration records, compared with the
  prior state, not the `after` value alone.** Real plans showed that a provider
  writes the default of an unwritten Optional argument into `after` as a known
  value, that Terraform carries an existing value over on an update, and that
  under `lifecycle { ignore_changes }` -- which the plan's configuration does
  not record -- it carries the prior value even of an argument the
  configuration writes. One mechanism, `declared.Argument`, decides every
  mapper's method, at the place the verdict reads -- the environment at its
  tag or label key, a network grant at the rule set or block list:
  `configuration-unrecorded` where the plan does not record the writing, and
  where the change keeps the object, `before` and `after` agree there, and the
  write is an expression the plan does not evaluate or a constant it cannot
  compare; `prior-state` where the change keeps the object and either `before`
  and `after` agree there while the configuration records the argument as
  unwritten or as `null`, or a written constant is contradicted there, moved
  or not; otherwise `plan-stated-value` for a written value and
  `provider-default` for an unwritten one. The value itself is read exactly as
  in milestone 09.
- **A block is never recorded as unwritten.** Terraform does not record a
  `dynamic` block, so an absent block -- AWS inline `ingress`, Azure
  `security_rule`, GCP `ip_configuration` and `authorized_networks`, a firewall's
  `allow` -- is `configuration-unrecorded`, and so is every attribute inside it.
  That includes an inline set carried from state, which reads unrecorded rather
  than `prior-state`: the plan of a dynamic block that writes the same rules is
  identical, so the plan cannot tell the two apart. It also includes GCP
  instances that write `settings` and no `ip_configuration`, whose public IP is
  milestone 09's default value; the method no longer calls that a default.
- **An entry with no expressions is read as a body that writes no attribute.**
  Terraform 1.14 records an empty body, a body of only dynamic blocks and a body
  of only a lifecycle block the same way: an entry with no `expressions`. No
  dynamic block writes an attribute, so a top-level attribute of such an entry
  is unwritten, and an empty `aws_s3_account_public_access_block` is
  `provider-default` like one that writes an unrelated flag. A sanitizer that
  strips `expressions` produces the same shape, and its attributes read as
  unwritten too; no verdict reads this, only the method does.
- **`prior-state` is decided by comparing `before` with `after`, not by the
  schema.** An update or no-op that keeps the object, and a value equal on
  both sides at the place the verdict reads. The comparison is made while
  parsing, on the plan's own `before` and `after` before any sensitive mark
  applies, and keeps only its answer: a sensitive tag beside the environment
  no longer makes a kept map look moved. A value not yet known is never
  carried. Where a provider's default equals
  what the object already had -- a firewall priority of 1000 left unwritten --
  the value is both, and the method says `prior-state`. An unwritten argument
  the update moves is `provider-default`: Terraform planned it back to the
  default (the AWS block flags an update resets, measured).
- **A value the configuration does not record as written is never stated.** An
  argument recorded as unwritten, holding a value that is not its documented
  default and not carried from prior state, is `configuration-unrecorded`. No
  real plan has shown the shape; the hand-written fixtures whose configuration
  lists only references do, and read that way. Applied where the default is
  known: AWS rule addresses, the bucket ACL and the block flags' proof of
  prevention, Azure `container_access_type` and separate NSG rule sources, GCP
  `source_ranges` and `disabled`, and the environment tags. The Azure account
  gate's default is not measured here, so it takes only what the configuration
  records.
- **An argument written as `null` reads as unwritten, as far as the plan
  records it.** A literal `null`, and variables whose value the plan records as
  `null` -- a root variable in `variables`, a module variable through its call
  or its default -- read as unwritten, because Terraform treats them so. An
  argument written only from variables the plan does not resolve reads
  `configuration-unrecorded`, and so does a `null` passed to a module variable
  that has a default, because the plan does not record `nullable`. Two shapes
  are read by their variables rather than evaluated: an expression that makes
  `null` out of variables that are not -- `var.on ? var.x : null` -- reads as
  written, and one that makes a value out of variables that are all `null` --
  `coalesce(var.x, "private")` -- reads as unwritten, which is never stated. An
  expression that also draws on a resource or a local reads as written, as it
  did. A module input `null` for an attribute of an `object()` variable
  declared `optional(T, default)` reads as `null`, unwritten, while Terraform
  applies the default (found by the fifth review, by reasoning; not planned):
  the method then says `provider-default` or `configuration-unrecorded` for a
  value the module's author wrote, which understates it and never states one.
- **On an update that keeps a value, only a constant write is stated.** The
  plan records a constant's value: a constant the carried value is reads
  `plan-stated-value`, and one it is not reads `prior-state` (`ignore_changes`
  kept the state). A write by reference, variable or function records no value
  -- `lower(var.x)` is recorded exactly as `var.x`, a function of constants as
  `{}` -- so where `after` equals `before` at the argument it reads
  `configuration-unrecorded`, with `ignore_changes` or without it. This is the
  user's conservative rule (see the amendment below), and its accepted cost: a
  referenced value written legitimately that an update does not change is no
  longer stated (measured: `real-reference-write-unchanged`). Block syntax is
  decided by everything written in the block, at every depth: all constants are
  compared with the planned blocks one for one, every planned attribute the
  block does not write compared as written as nothing -- `plan-stated-value`
  or `prior-state` as above -- and a block with anything else inside reads
  `configuration-unrecorded`. An attribute written in a repeated block, and a
  block inside a repeated block, have no one expression to compare, so
  carried they read `configuration-unrecorded`; the mapper sites read whole
  blocks, never those paths. Each is decided at the place the verdict reads: a
  map written as a constant is compared key by key, and a key it does not
  write is written as nothing. A constant the plan contradicts there is
  `prior-state` on any update, moved or not, and one compared with a value the
  plan withholds or does not know is `configuration-unrecorded`. A write the
  plan moves, and does not contradict, is stated without a comparison: `ignore_changes` keeps a value, so a value the plan
  moves is the configuration's, but the plan does not show that `after` is
  what the expression evaluates to (a provider that normalizes or computes the
  value would read stated). A static block beside a `dynamic` one of the same
  type, on a create, still reads stated; on an update, the planned set is not
  the written one and it reads `prior-state`. The comparison takes Terraform's
  encoding: an attribute written as blocks records every attribute, `null`
  where nothing was written, and Terraform plans an attribute nobody wrote as
  an empty value, so `null` -- and an attribute a block in block syntax does
  not write -- matches only `null`, `[]`, `{}`, `""` or `false`; a non-empty
  documented default there reads `prior-state`, never stated. A list is
  compared as a set, greedily, so a set it fails to pair reads `prior-state`,
  never stated. A provider that canonicalizes a constant reads `prior-state`,
  never stated, and the fifth review found it on real no-op plans: GCP
  `allow { protocol = "TCP" }` and AWS `protocol = "TCP"` and `protocol = "6"`
  against a state holding `tcp` (pinned on `real-labels-partial-ignore` and
  `real-tags-sensitive-ignored`). This build does not normalize them: a
  case-insensitive protocol and the AWS protocol numbers are provider
  behaviour, the comparison lives in the provider-independent plan reader, and
  understating is the direction this milestone accepts.
- **A grant on an interpreted document keeps the document's method.** On AWS a
  policy-document grant through a block flag nobody wrote, and on GCP a
  `policy_data` grant beside a `public_access_prevention` nobody wrote, rest on
  two inputs that are not stated. The method stays
  `policy-document-interpreted` and the defaulted gate does not show. This used
  to say the AWS channel was the one such site; the review found the GCP one.
  Every other mix of non-stated inputs takes the documented order.
- **GCP `public_access_prevention` written but not yet known reads as
  stated.** A grant beside it is still `Known(true)`, as in milestone 09, which
  treats an unknown prevention as not enforced. The method records that the
  author wrote the argument, not that the plan knows its value; the verdict's
  reading of an unknown prevention is the milestone 09 behaviour the contract
  review recorded as outside this milestone.
- **An Azure NSG grant takes the method of the rules that still open
  something, not of the denies it survived.** The fourth review found it took
  every allow from any address, including one a deny cancelled whole; it now
  takes the best of the rules whose ranges survive. GCP's firewall counts the
  inputs of every deny it applied or skipped; the Azure resolve does not report
  which deny it weighed.
- **A GCP firewall's own `disabled` carries no method.** A verdict on an
  enabled firewall rests on `disabled` being `false`, which the provider
  defaults when it is unwritten, and `disabled` is not cited as evidence. A
  deny skipped because it is disabled does rest the verdict on its `disabled`,
  as one skipped because it is egress, narrower in source, at a higher priority
  or on another network rests it on that input.
- **The hand-written fixtures from before this milestone under-state what they
  write, and cannot be corrected.** Their configurations list only the
  arguments that carry a reference, such as `bucket` or `network`. Correcting
  one changes its plan digest, which the frozen milestone 09 baselines record,
  so they stay as they are, and their findings read `configuration-unrecorded`
  -- what the plan records. Where a test asserts a stated value, it reads a
  variant whose `configuration` writes it (`sg-public-rule-written`,
  `private-flags-written`, `nsg-separate-open-written`, the GCP
  `-prevention-written` variants). The fixtures added for this milestone, which
  have no baseline, record the arguments their `after` carries.
- **A plan with no `configuration` section is `configuration-unrecorded`.** It
  read `plan-stated-value` until the review. An absent or unknown value in such
  a plan gets no default, as in milestone 09.
- **The policy assigns four methods of its own.** It adds the contract
  comparison (`intent-comparison`), the action classification (`plan-action`),
  the hop from a database to the gate that decided its admission
  (`reference-resolved`), and the cloud claim. `Resource.Cloud` is not a `Fact`
  and carries no method, so `CLOUD_NOT_ALLOWED` assigns `resource.cloud` as
  `plan-stated-value` in the rule, from `provider_name` read through this
  build's provider-name table. Every other step takes the fact's own method
  unchanged.
- **The AWS `vpc_security_group_ids` hop is a step but not a citation.** The
  `database.admitted_by` step says `reference-resolved`, and the evidence cites
  the gate's own sources. The attribute through which the database reached that
  gate is still not cited, as the scope said.
- **Unknowns carry no steps.** `verification_steps` exists on `Finding` only.
- **`CORRELATION_UNRESOLVED` still reaches object storage only**, as in
  milestone 09.
- **GCP `direction` is still not cited as evidence.** A defaulted direction shows
  only in the method. Citing it would change bundles that criterion 8 holds
  fixed.
- **A GCP firewall whose own direction or priority is defaulted labels its
  verdict `provider-default` even when the verdict does not rest on it.** A
  firewall's own priority matters only against a deny, yet a defaulted one
  marks the verdict even when no deny was compared. The same happens when a
  deny with a defaulted direction or priority is applied and subtracts nothing.
  This over-attributes the default. It never hides one, and no verdict depends
  on it.
- **A database admission settled `false` through gates is labelled
  `reference-resolved`, even when the mapper's own fact was known `false`.** It
  never reaches a bundle. A known `false` admission produces no finding and no
  step, so the method of that branch is unobservable (see criterion 9 below).
- **The exhaustive test reaches four of the six rules.** `TestEveryFindingSaysHowItKnows`
  runs every plan fixture under the one shipped contract, which produces
  `STORAGE_PUBLIC`, `NETWORK_PUBLIC_INGRESS`, `DATABASE_PUBLIC_REACHABLE` and
  `DESTRUCTIVE_CHANGE`. `CLOUD_NOT_ALLOWED` is pinned at unit level by
  `TestEveryGenericRuleSaysHowItKnows`, and `ENVIRONMENT_MISMATCH` through the
  mapper on a real plan by `TestAnEnvironmentReadFromAPlanSaysHowItKnows`. It
  now fails on a fixture it cannot verify rather than skipping it.
- **The method decides nothing.** As specified, no decision, disposition or exit
  code reads it. Criterion 8 below measures that no verdict changed.

## Criterion 8, measured

The 226 baselines recorded at `3b50544` still match byte for byte under
`TestEveryFixtureProducesItsBaselineBundle`. The test removes
`verification_steps` and restores `schema_version: "1.2"` before it compares.
No baseline was re-recorded.

For the plan fixtures, binaries were built at `3b50544` and at the end of this
milestone. Both binaries ran
`check --intent internal/verify/testdata/baseline/intent.json --plan <fixture> --format json`
on every plan under `internal/providers/*/testdata` and
`internal/providers/testdata`. The *after* output was normalised by setting
`schema_version` to `"1.2"` and dropping `verification_steps` from each finding.

| | count |
| --- | --- |
| plan fixtures compared | 216 |
| identical after normalisation, same exit code and stderr | 216 |
| differing | 0 |
| exit codes (before = after) | 182 × `4`, 21 × `3`, 13 × `0`; none `10` or `11` |
| fixtures added during milestone 10, so absent at `3b50544` | 15 |

Re-measured after the final review's fixes, which added nine fixtures and
edited only the `configuration` block of five more:

| | count |
| --- | --- |
| plan fixtures compared | 225 |
| identical after normalisation, same exit code and stderr | 225 |
| differing | 0 |
| exit codes (before = after) | 189 × `4`, 23 × `3`, 13 × `0`; none `10` or `11` |

The nine added are AWS `public-acl-flags-written` and
`public-acl-account-flags-defaulted`, and GCP `fw-priority-written`,
`fw-priority-omitted`, `fw-priority-unwritten`,
`fw-deny-above-priority-unwritten`, `fw-denied-lower-priority-unwritten`,
`fw-public-priority-written` and `fw-public-direction-computed`. The five edited
are AWS `public-acl-and-policy`, which now writes its block flags, and GCP's four
`-direction-` fixtures, which now write `priority`.

Every fixture that existed at `3b50544` also has a baseline. When this was
first written, the 15 new ones were the only plan fixtures here with no
baseline, and the *before* binary reads each of them identically too. *Wrong
by the time it was committed, found by the adversarial review:* with the final
review's nine, 24 provider fixtures had no baseline. The 15 of the first pass
were:

- AWS: `public-acl-and-policy`.
- Azure: `private-account-forbids-written`,
  `private-container-unwritten-gate-written`,
  `private-container-written-gate-unwritten`, `public-blob-container-defaulted`,
  `public-blob-gate-defaulted`, `public-blob-written`, `sql-switch-defaulted`.
- GCP: `fw-denied-lower-direction-omitted`, `fw-deny-above-direction-omitted`,
  `fw-public-direction-omitted`, `fw-public-direction-written`,
  `public-iam-policy-data`, `public-member-and-policy-data`,
  `real-databases-ipv4-unwritten`.

### Re-measured after the adversarial review's fix wave

The fix wave added 17 provider fixtures, all without a baseline: fourteen real
plans (`real-rds-unwritten-update` and `-create`, `real-sg-ingress-from-state`,
`real-acl-account-block-empty` and `-one-flag`, `real-sql-ip-configuration-from-state`,
`real-sql-dynamic-settings`, `real-sql-dynamic-authorized-networks`,
`real-bucket-prevention-pair` and `-from-state`, `real-firewall-dynamic-allow`,
`real-firewall-direction-from-state`, `real-sql-ipv4-written` and `-unwritten`),
and three variants of GCP grant fixtures that write `public_access_prevention`. It edited only the `configuration` block of
the eleven GCP firewall fixtures from this milestone, which have no baseline.
No baseline and no fixture that has one was touched: `git diff 3b50544 --
internal/verify/testdata/baseline` is empty, and 226 baselines still match
under `TestEveryFixtureProducesItsBaselineBundle`.

Binaries were built from `git archive 3b50544` and from the fix wave's head,
and both ran `check --format json` on every plan JSON in the tree -- provider
fixtures, `terraformplan` and `tfconfig` fixtures and `docs/research` -- under
the shipped contract and three more that exercise all six rules
(`scratchpad/intents/`: all-private, all-public, silent). The *after* output was
normalised as above.

| | count |
| --- | --- |
| plans × contracts compared | 273 × 4 = 1092 |
| identical after normalisation, same exit code and stderr | 1092 |
| differing | 0 |
| provider fixtures | 242, of which 41 have no baseline |
| exit codes, shipped contract (before = after) | 228 × `4`, 30 × `3`, 13 × `0`, 2 × `10` |

The two `10`s are malformed-input fixtures and were `10` before. Steps observed
across the 1092 runs, by method, on plan facts: `plan-stated-value` 1180,
`provider-default` 124, `configuration-unrecorded` 123, `prior-state` 20,
`documented-table` 72, `policy-document-interpreted` 8, `reference-resolved` 92.

## Criterion 9, measured

Each assignment was mutated by hand, one at a time. The suite ran with
`go test ./internal/...`, and the file was restored with `git checkout`. In the
table, "stated" means the assignment was replaced with `model.MethodStated`, and
"false" means a `defaulted` input was forced to `false`. A forced value is
written `x || true` or `x && false` where the plain constant would leave a
variable unused and stop the package compiling.

First pass: 36 mutations, and five broke nothing:

- AWS `publicly_accessible` in the unknown-and-unwritten branch;
- GCP `ipv4_enabled` in the default branch;
- the GCP `statedGrant` binding arm;
- the Azure grant whose gate alone was defaulted;
- the Azure account with no container.

Three mutations, the Azure account and both `byPort` forms, were first written
in a form that did not compile. A compile failure proves nothing, so they were
re-measured in a form that compiles, and only the Azure account survived. Each of the five got a test, in the package that owns the
site:

- `TestAComputedSwitchNobodyWroteIsTheProvidersDefault` (aws);
- `TestAnAbsentIPv4SwitchIsTheProvidersDefault` and `TestABindingGrantIsStated`
  (gcp);
- the `public-blob-gate-defaulted` case of
  `TestStorageAccessSettingsFollowTheConfiguration`, and
  `TestAnAccountAloneTakesItsGatesMethod` (azure).

The re-measure is below. The final review then found two sites that still
presented a default as stated: the AWS block flags and the GCP firewall
`priority`. Their rows were measured the same way after the fix, and so were
the rows of every other site in `aws/aws.go` and `gcp/network.go`. The GCP
direction's known and unknown unwritten rows had stopped breaking anything.
`fw-public` and `real-firewalls` also leave `priority` unwritten, so the
priority now made their verdicts `provider-default` without the direction.
Two fixtures that write `priority`, `fw-public-priority-written` and
`fw-public-direction-computed`, make each row break a test again. The rows for
other files were not re-run. Only tests were added since, so each still breaks
at least what it lists, and possibly more.

| site | mutation | broke |
| --- | --- | --- |
| `aws/database.go` `publicly_accessible`, absent and unwritten | stated | aws: `TestAnUnwrittenSwitchIsTheProvidersDefault` |
| `aws/database.go` `publicly_accessible`, known and unwritten | stated | aws: `TestAKnownSwitchNobodyWroteIsTheProvidersDefault` |
| `aws/database.go` `publicly_accessible`, unknown and unwritten | stated | aws: `TestAComputedSwitchNobodyWroteIsTheProvidersDefault` |
| `aws/database.go` engine-derived port | stated | aws: `TestAnEngineDerivedPortIsFromTheTable`; policy: `TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate` |
| `aws/aws.go` policy channel | stated | aws: `TestAPolicyGrantIsInterpreted`, `TestAPolicyGrantThroughDefaultedFlagsStaysInterpreted`; policy: `TestAPolicyDocumentGrantIsInterpretedInTheStep` |
| `aws/aws.go` ACL channel through a defaulted flag | stated | aws: `TestAnACLGrantThroughDefaultedBucketFlagsIsTheProvidersDefault`, `TestAnACLGrantThroughDefaultedAccountFlagsIsTheProvidersDefault`; policy: `TestTheBlockFlagDefaultChangesTheACLStep` |
| `aws/aws.go` ACL channel, bucket block `defaulted` | false | aws: `TestAnACLGrantThroughDefaultedBucketFlagsIsTheProvidersDefault`; policy: `TestTheBlockFlagDefaultChangesTheACLStep` |
| `aws/aws.go` ACL channel, account block `defaulted` | false | aws: `TestAnACLGrantThroughDefaultedAccountFlagsIsTheProvidersDefault` |
| `aws/aws.go` `blockedBy` known `false` and unwritten | false | aws: `TestAnACLGrantThroughDefaultedBucketFlagsIsTheProvidersDefault`, `TestAnACLGrantThroughDefaultedAccountFlagsIsTheProvidersDefault`; policy: `TestTheBlockFlagDefaultChangesTheACLStep` |
| `aws/aws.go` policy channel discards `defaulted` | `provider-default` | aws: `TestAPolicyGrantIsInterpreted`, `TestAPolicyGrantThroughDefaultedFlagsStaysInterpreted`; policy: `TestAPolicyDocumentGrantIsInterpretedInTheStep` |
| `gcp/database.go` `ipv4_enabled`, known and unwritten | stated | gcp: `TestAnUnwrittenIPv4SwitchIsTheProvidersDefault`; policy: `TestTheIPv4DefaultChangesOneStepAndNothingElse` |
| `gcp/database.go` `ipv4_enabled`, default branch | stated | gcp: `TestAnAbsentIPv4SwitchIsTheProvidersDefault` |
| `gcp/database.go` version-derived port | stated | gcp: `TestAVersionDerivedPortIsFromTheTable` |
| `gcp/network.go` firewall method | stated | gcp: `TestAKnownDirectionNobodyWroteIsTheProvidersDefault`, `TestAnOmittedDirectionIsTheProvidersDefault`, `TestAnUnknownUnwrittenDirectionIsTheProvidersDefault`, `TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault`, `TestAnOmittedPriorityIsTheProvidersDefault`, `TestAKnownPriorityNobodyWroteIsTheProvidersDefault`, `TestADenySkippedOnADefaultedPriorityIsTheProvidersDefault`, `TestADenyAppliedOnADefaultedPriorityIsTheProvidersDefault`; policy: `TestTheDirectionDefaultChangesOneStepAndNothingElse` |
| `gcp/network.go` deny direction (`defaulted \|\| deny.directionDefaulted`) | drop `\|\| deny.directionDefaulted` | gcp: `TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault` |
| `gcp/network.go` direction absent | false | gcp: `TestAnOmittedDirectionIsTheProvidersDefault`, `TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault`; policy: `TestTheDirectionDefaultChangesOneStepAndNothingElse` |
| `gcp/network.go` direction known and unwritten | false | gcp: `TestAKnownDirectionNobodyWroteIsTheDefaultWithAWrittenPriority` |
| `gcp/network.go` direction unknown and unwritten | false | gcp: `TestAnUnknownUnwrittenDirectionIsTheDefaultWithAWrittenPriority` |
| `gcp/network.go` subject's `priorityDefaulted` | false | gcp: `TestAnOmittedPriorityIsTheProvidersDefault`, `TestAKnownPriorityNobodyWroteIsTheProvidersDefault` |
| `gcp/network.go` priority absent | false | gcp: `TestAnOmittedPriorityIsTheProvidersDefault` |
| `gcp/network.go` priority known and unwritten | false | gcp: `TestAKnownPriorityNobodyWroteIsTheProvidersDefault`, `TestADenySkippedOnADefaultedPriorityIsTheProvidersDefault`, `TestADenyAppliedOnADefaultedPriorityIsTheProvidersDefault` |
| `gcp/network.go` deny skipped above the rule, its `priorityDefaulted` | drop | gcp: `TestADenySkippedOnADefaultedPriorityIsTheProvidersDefault` |
| `gcp/network.go` deny applied (`\|\| deny.priorityDefaulted`) | drop `\|\| deny.priorityDefaulted` | gcp: `TestADenyAppliedOnADefaultedPriorityIsTheProvidersDefault` |
| `gcp/gcp.go` `policy_data` | stated | gcp: `TestAPolicyDataGrantIsInterpreted` |
| `gcp/gcp.go` `statedGrant`, member arm | force `false` | gcp: `TestAMemberGrantIsStated`, `TestAGrantProvenTwiceTakesTheStatedProof` |
| `gcp/gcp.go` `statedGrant`, binding arm | force `false` | gcp: `TestABindingGrantIsStated` |
| `azure/database.go` type-derived port | stated | azure: `TestATypeDerivedPortIsFromTheTableAndNotInferred` |
| `azure/database.go` `public_network_access_enabled` | stated | azure: `TestAnUnwrittenEndpointSwitchIsTheProviderDefault` |
| `azure/azure.go` `methodOf` | stated | azure: `TestAnUnwrittenEndpointSwitchIsTheProviderDefault`, `TestStorageAccessSettingsFollowTheConfiguration`, `TestAnAccountAloneTakesItsGatesMethod` |
| `azure/azure.go` account with no container | false | azure: `TestAnAccountAloneTakesItsGatesMethod` |
| `azure/azure.go` gate says no | stated | azure: `TestStorageAccessSettingsFollowTheConfiguration` |
| `azure/azure.go` container says no | stated | azure: `TestStorageAccessSettingsFollowTheConfiguration` |
| `azure/azure.go` both say yes | stated | azure: `TestStorageAccessSettingsFollowTheConfiguration` |
| `azure/azure.go` both say yes, the gate's default dropped | drop the gate | azure: `TestStorageAccessSettingsFollowTheConfiguration` |
| `azure/azure.go` both say yes, the container's default dropped | drop the container | azure: `TestStorageAccessSettingsFollowTheConfiguration` |
| `azure/azure.go` gate `defaulted` | false | azure: `TestStorageAccessSettingsFollowTheConfiguration`, `TestAnAccountAloneTakesItsGatesMethod` |
| `azure/azure.go` container `defaulted` | false | azure: `TestStorageAccessSettingsFollowTheConfiguration` |
| `policy/database.go` gate hop `reference-resolved` | stated | policy: `TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate` |
| `policy/database.go` gate's own step | omitted | policy: `TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate` |
| `policy/database.go` `byPort` | force `true` | policy: `TestThePortStepAppearsOnlyWhenThePortDecided` |
| `policy/database.go` `byPort` | force `false` | policy: `TestThePortStepAppearsOnlyWhenThePortDecided`, `TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate` |
| `policy/rules.go` `change.destructive` `plan-action` | stated | policy: `TestEveryGenericRuleSaysHowItKnows` |
| `policy/rules.go` `resource.cloud` `plan-stated-value` | `plan-action` | policy: `TestEveryGenericRuleSaysHowItKnows` |
| `policy/steps.go` contract `intent-comparison` | stated | policy: `TestEveryGenericRuleSaysHowItKnows`, `TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate`, `TestAPolicyDocumentGrantIsInterpretedInTheStep`, `TestTheIPv4DefaultChangesOneStepAndNothingElse`, `TestTheDirectionDefaultChangesOneStepAndNothingElse` |
| `policy/database.go` admission settled `false` through gates, `reference-resolved` | stated | nothing: unobservable |
| `policy/database.go` admission settled `false` by the mapper, its own method | `reference-resolved` | nothing: unobservable |

Every `provider-default`, `documented-table` and `policy-document-interpreted`
assignment now breaks at least one test, which is criterion 9. So does every
method the policy layer assigns that can reach a bundle.

The last two rows are the only survivors, and no output can observe either. Both
assign the method of a `Known(false)` admission. The database rule handles a known
`false` admission before it builds any finding, and it builds no finding and no
step from it. The withdrawn branch produces an unknown, which carries no steps. A test
would have to reach into the policy package's internals to pin a method nothing
emits, so none was added.

### Re-measured after the adversarial review's fix wave

The fix wave replaced the per-site booleans (`defaulted`, `directionDefaulted`,
`priorityDefaulted`, Azure's `methodOf`) with `declared.Argument`, so the rows
above that name them describe code that no longer exists; the rows below
supersede them. Every new or changed method site, and the validation the wave
added, was mutated by a harness rather than by hand
(`scratchpad/fixmut/run.py`): each mutant replaces one string that occurs once
in its file, the harness refuses it unless `git diff --stat` then shows a
change, runs `go vet ./...` so that a mutant that does not compile is recorded
as such rather than as killed, runs `go test ./... -count=1`, and restores the
file with `git checkout`. Four mutants did not compile on the first pass
(an unused variable); each was re-expressed in a form that compiles and
re-run, and the table records the re-run. 68 mutants.

| mutant | file | result |
| --- | --- | --- |
| `declared-block-absence-unwritten` | `providers/declared/method.go` | killed: `TestADynamicSettingsBlockIsConfigurationUnrecorded`, `TestAFirewallWhoseAllowIsNotRecordedIsUnrecorded`, `TestAGrantThroughADynamicAllowIsConfigurationUnrecorded`, `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords` and 5 more |
| `declared-parent-unrecorded-ignored` | `providers/declared/method.go` | killed: `TestADynamicSettingsBlockIsConfigurationUnrecorded`, `TestAnAbsentIPv4SwitchInAnUnrecordedBlockIsUnrecorded`, `TestAnIPConfigurationNobodyRecordedIsConfigurationUnrecorded`, `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `declared-required-unwritten` | `providers/declared/method.go` | killed: `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `declared-noconfig-as-declared` | `providers/declared/method.go` | killed: `TestADatabaseAdmissionInAPlanWithoutConfigurationIsUnrecorded`, `TestANonDefaultValueOfAnArgumentNotComputedWasWritten`, `TestAProofOfPreventionWithoutConfigurationIsUnrecorded`, `TestAnEnvironmentReadFromAPlanSaysHowItKnows` and 1 more |
| `declared-prior-state-never` | `providers/declared/method.go` | killed: `TestAGrantThroughAPreventionCarriedFromStateIsPriorState`, `TestANonDefaultValueOfAnArgumentNotComputedWasWritten`, `TestAnUnwrittenComputedSwitchCarriedFromStateIsPriorState`, `TestAnUnwrittenPortCarriedFromStateIsPriorState` and 2 more |
| `declared-unrecorded>stated` | `providers/declared/method.go` | killed: `TestADatabaseAdmissionInAPlanWithoutConfigurationIsUnrecorded`, `TestADynamicSettingsBlockIsConfigurationUnrecorded`, `TestAFirewallInAPlanWithoutConfigurationIsUnrecorded`, `TestAFirewallWhoseAllowIsNotRecordedIsUnrecorded` and 10 more |
| `declared-unwritten-default>stated` | `providers/declared/method.go` | killed: `TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault`, `TestADenyAppliedOnADefaultedPriorityIsTheProvidersDefault`, `TestADenySkippedOnADefaultedPriorityIsTheProvidersDefault`, `TestADynamicSettingsBlockIsConfigurationUnrecorded` and 20 more |
| `declared-methodfor-contradiction-off` | `providers/declared/method.go` | killed: `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords`, `TestANonDefaultValueOfAnArgumentNotComputedWasWritten`, `TestAProofOfPreventionRestsOnFlagsSomebodyWrote`, `TestASeparateRuleAddressIsStatedEvenWhenTheConfigurationListsOnlyItsReferences` and 1 more |
| `declared-updates-replace` | `providers/declared/method.go` | killed: `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `declared-weakest-order` | `providers/declared/method.go` | killed: `TestAFirewallWhoseAllowIsNotRecordedIsUnrecorded`, `TestAGrantThroughADynamicAllowIsConfigurationUnrecorded`, `TestTheDirectionDefaultChangesOneStepAndNothingElse`, `TestTheStrongestProofOfADisjunctionWins` and 1 more |
| `declared-strongest-invert` | `providers/declared/method.go` | killed: `TestAGrantProvenTwiceTakesTheStatedProof`, `TestTheStrongestProofOfADisjunctionWins` |
| `plan-declared-false` | `terraformplan/config.go` | killed: `TestAnEmptyAccountBlockIsAsDefaultedAsOneThatWritesSomethingElse`, `TestAnEntryWithoutExpressionsIsDeclaredButNotConfigured`, `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `aws-db-switch-not-computed` | `providers/aws/database.go` | killed: `TestAnUnwrittenComputedSwitchCarriedFromStateIsPriorState`, `TestValuesCarriedFromStateArePriorStateInTheSteps` |
| `aws-db-switch>stated` | `providers/aws/database.go` | killed: `TestAKnownSwitchNobodyWroteIsTheProvidersDefault`, `TestAnUnwrittenComputedSwitchCarriedFromStateIsPriorState`, `TestValuesCarriedFromStateArePriorStateInTheSteps` |
| `aws-db-port>stated` | `providers/aws/database.go` | killed: `TestAnUnwrittenPortCarriedFromStateIsPriorState`, `TestValuesCarriedFromStateArePriorStateInTheSteps` |
| `aws-db-port-not-computed` | `providers/aws/database.go` | killed: `TestAnUnwrittenPortCarriedFromStateIsPriorState`, `TestValuesCarriedFromStateArePriorStateInTheSteps` |
| `aws-net-inline>stated` | `providers/aws/network.go` | killed: `TestAnInlineGrantNobodyRecordedIsConfigurationUnrecorded` |
| `aws-net-openedby-contradiction-off` | `providers/aws/network.go` | killed: `TestASeparateRuleAddressIsStatedEvenWhenTheConfigurationListsOnlyItsReferences` |
| `aws-net-grant>stated` | `providers/aws/network.go` | killed: `TestAnInlineGrantNobodyRecordedIsConfigurationUnrecorded` |
| `aws-net-closed>stated` | `providers/aws/network.go` | survived: a `Known(false)` group builds no finding, unobservable |
| `aws-st-flag>stated` | `providers/aws/aws.go` | killed: `TestAnACLGrantThroughDefaultedAccountFlagsIsTheProvidersDefault`, `TestAnACLGrantThroughDefaultedBucketFlagsIsTheProvidersDefault`, `TestAnEmptyAccountBlockIsAsDefaultedAsOneThatWritesSomethingElse`, `TestTheBlockFlagDefaultChangesTheACLStep` |
| `aws-st-acl>default` | `providers/aws/aws.go` | killed: `TestAGrantProvenTwiceTakesTheStatedProof`, `TestAJoinThatOnlyLocatesAGrantIsNotReferenceResolved`, `TestAnACLGrantIsStated`, `TestTheBlockFlagDefaultChangesTheACLStep` |
| `aws-st-ownership>unrecorded` | `providers/aws/aws.go` | killed: `TestAnEmptyAccountBlockIsAsDefaultedAsOneThatWritesSomethingElse` |
| `aws-st-gates-dropped` | `providers/aws/aws.go` | killed: `TestAnACLGrantThroughDefaultedAccountFlagsIsTheProvidersDefault`, `TestAnACLGrantThroughDefaultedBucketFlagsIsTheProvidersDefault`, `TestAnEmptyAccountBlockIsAsDefaultedAsOneThatWritesSomethingElse`, `TestTheBlockFlagDefaultChangesTheACLStep` |
| `aws-st-proof>stated` | `providers/aws/aws.go` | killed: `TestAProofOfPreventionWithoutConfigurationIsUnrecorded` |
| `gcp-db-switch>stated` | `providers/gcp/database.go` | killed: `TestADynamicSettingsBlockIsConfigurationUnrecorded`, `TestAnIPConfigurationNobodyRecordedIsConfigurationUnrecorded`, `TestAnUnwrittenIPv4SwitchIsTheProvidersDefault`, `TestTheIPv4DefaultChangesOneStepAndNothingElse` |
| `gcp-db-default-branch>stated` | `providers/gcp/database.go` | killed: `TestAnAbsentIPv4SwitchInAnUnrecordedBlockIsUnrecorded` |
| `gcp-db-allow>stated` | `providers/gcp/database.go` | killed: `TestADynamicSettingsBlockIsConfigurationUnrecorded`, `TestAnIPConfigurationNobodyRecordedIsConfigurationUnrecorded` |
| `gcp-db-allow-not-block` | `providers/gcp/database.go` | killed: `TestADynamicAllowListInsideAWrittenBlockIsConfigurationUnrecorded` |
| `gcp-db-closed>stated` | `providers/gcp/database.go` | survived: a `Known(false)` admission builds no finding, unobservable |
| `gcp-st-prevention-dropped` | `providers/gcp/gcp.go` | killed: `TestAGrantThroughAPreventionCarriedFromStateIsPriorState`, `TestAGrantThroughAnUnwrittenPreventionIsTheProvidersDefault` |
| `gcp-st-prevention-not-computed` | `providers/gcp/gcp.go` | killed: `TestAGrantThroughAPreventionCarriedFromStateIsPriorState` |
| `gcp-st-policydoc-not-kept` | `providers/gcp/gcp.go` | killed: `TestAPolicyDataGrantIsInterpreted`, `TestAPolicyDataGrantThroughAnUnwrittenPreventionStaysInterpreted` |
| `gcp-st-written-unknown-contributes` | `providers/gcp/gcp.go` | survived: equivalent, a stated input never weakens a fact; the branch was removed |
| `gcp-st-member>interpreted` | `providers/gcp/gcp.go` | killed: `TestAGrantProvenTwiceTakesTheStatedProof`, `TestAGrantThroughAPreventionCarriedFromStateIsPriorState`, `TestAGrantThroughAnUnwrittenPreventionIsTheProvidersDefault`, `TestAJoinThatOnlyLocatesAGrantIsNotReferenceResolved` and 1 more |
| `gcp-st-members>interpreted` | `providers/gcp/gcp.go` | killed: `TestABindingGrantIsStated` |
| `gcp-st-strongest>weakest` | `providers/gcp/gcp.go` | killed: `TestAGrantProvenTwiceTakesTheStatedProof` |
| `gcp-st-enforced>stated` | `providers/gcp/gcp.go` | survived: enforced prevention is `Known(false)`, unobservable |
| `gcp-fw-blocks-dropped` | `providers/gcp/network.go` | killed: `TestAFirewallWhoseAllowIsNotRecordedIsUnrecorded`, `TestAGrantThroughADynamicAllowIsConfigurationUnrecorded`, `TestTheDirectionDefaultChangesOneStepAndNothingElse` |
| `gcp-fw-source-dropped` | `providers/gcp/network.go` | survived: equivalent, see the removed `source_ranges` input; removed |
| `gcp-fw-source-contradiction-off` | `providers/gcp/network.go` | survived: equivalent for the same reason; removed |
| `gcp-fw-deny-inputs-dropped` | `providers/gcp/network.go` | survived; re-measured as `gcp-fw-deny-blocks-dropped` after a test was added |
| `gcp-fw-direction-not-computed` | `providers/gcp/network.go` | killed: `TestADirectionCarriedFromStateIsPriorState` |
| `gcp-fw-deny-block-name` | `providers/gcp/network.go` | killed: `TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault`, `TestADenyAppliedOnADefaultedPriorityIsTheProvidersDefault` |
| `az-st-both-gate-only` | `providers/azure/azure.go` | killed: `TestAGrantIsOnlyAsStrongAsTheWeakerSetting` |
| `az-st-both-setting-only` | `providers/azure/azure.go` | killed: `TestStorageAccessSettingsFollowTheConfiguration` |
| `az-st-container-contradiction-off` | `providers/azure/azure.go` | killed: `TestStorageAccessSettingsFollowTheConfiguration` |
| `az-db-endpoint>stated` | `providers/azure/database.go` | killed: `TestAnUnwrittenEndpointSwitchIsTheProviderDefault` |
| `az-db-allow>default` | `providers/azure/database.go` | killed: `TestADatabaseAdmissionInAPlanWithoutConfigurationIsUnrecorded`, `TestADatabaseAdmissionThroughAFirewallRuleIsStated`, `TestAJoinThatOnlyLocatesAGrantIsNotReferenceResolved` |
| `az-db-allow>stated` | `providers/azure/database.go` | killed: `TestADatabaseAdmissionInAPlanWithoutConfigurationIsUnrecorded` |
| `az-net-inline>stated` | `providers/azure/network.go` | killed: `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords` |
| `az-net-separate>default` | `providers/azure/network.go` | killed: `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords` |
| `az-net-grant>default` | `providers/azure/network.go` | killed: `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords` |
| `az-net-grant>stated` | `providers/azure/network.go` | killed: `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords` |
| `az-net-separate-contradiction-off` | `providers/azure/network.go` | killed: `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords` |
| `az-net-closed>stated` | `providers/azure/network.go` | survived: a `Known(false)` group builds no finding, unobservable |
| `env>default` | `providers/declared/environment.go` | killed: `TestAnEnvironmentReadFromAPlanSaysHowItKnows` |
| `env>stated` | `providers/declared/environment.go` | killed: `TestAnEnvironmentReadFromAPlanSaysHowItKnows` |
| `ev-duplicate-check-off` | `evidence/validate.go` | killed: `TestAFactIsEstablishedOnce` |
| `ev-contract-step-off` | `evidence/validate.go` | killed: `TestAVersionWithStepsRequiresTheContractStep` |
| `ev-contract-any-method` | `evidence/validate.go` | killed: `TestAVersionWithStepsRequiresTheContractStep` |
| `ev-contract-any-fact` | `evidence/validate.go` | killed: `TestAVersionWithStepsRequiresTheContractStep` |
| `ev-factpath-one-segment` | `evidence/validate.go` | killed: `TestAStepPresentIsValidatedWhateverTheVersion` |
| `ev-factpath-off` | `evidence/validate.go` | killed: `TestAStepPresentIsValidatedWhateverTheVersion` |
| `ev-enum-unrecorded` | `evidence/enums.go` | killed: `TestEveryFindingSaysHowItKnows`, `TestEveryMethodInTheClosedSetIsValid`, `TestEveryModelMethodIsAnEvidenceMethod` |
| `ev-enum-prior` | `evidence/enums.go` | killed: `TestEveryFindingSaysHowItKnows`, `TestEveryMethodInTheClosedSetIsValid`, `TestEveryModelMethodIsAnEvidenceMethod` |
| `pol-db-338-byport` | `policy/database.go` | killed: `TestAnUnusablePortBehindAGateOpenOnEveryPortNamesNoPortStep` |
| `gcp-fw-deny-blocks-dropped` | `providers/gcp/network.go` | killed: `TestADenyAppliedThroughAnUnrecordedBlockIsConfigurationUnrecorded` |

Every survivor is one of two kinds. Four assign the method of a `Known(false)`
fact, which builds no finding and no step, so no output can observe them --
the same reason the two `policy/database.go` rows above survive. Three were
equivalent: the line they mutated could not change any method, because a
`source_ranges` that reaches every address is stated wherever the configuration
records anything, and a stated input never weakens a fact. Those lines were
deleted rather than kept untested. Every `provider-default`, `prior-state`,
`configuration-unrecorded`, `documented-table` and `policy-document-interpreted`
assignment that can reach a bundle breaks at least one test, which is criterion
9 extended to the two new methods.

## Amendment: adversarial review (3 rounds)

Three independent reviews ran at `bfcfb72`, one on provider reality with real
plans (Terraform 1.14.0, `hashicorp/aws` 6.67.0, `hashicorp/google` 6.50.0,
`plan -refresh=false`, nothing applied), one on the contract's soundness, and
one on claims against measurement. All three returned BLOCK. No verdict was
wrong; the method was, in the direction the milestone exists to remove.

### Decisions taken on the findings

- **D1, two new methods.** `prior-state` for an unwritten argument whose value
  Terraform carried across an update, and `configuration-unrecorded` for an
  argument the plan does not record either way. `plan-stated-value` is assigned
  only on a positive record and is never the fallback for "cannot tell";
  `provider-default` only where the configuration records the argument as
  unwritten on a new object. Schema version stays `1.3`, which was unreleased.
- **D2, `reference-resolved` is narrow.** It means a value obtainable only by
  resolving a reference. A grant written on its own ACL, IAM or firewall-rule
  resource is stated; the join only locates where it applies.

### Claims this document made that turned out false

- *"Every AWS network fact is `plan-stated-value`."* An update carries an
  inline `ingress` set nobody wrote, and the grant rested on it as stated.
- *"Every site measured at `3b50544` mixes at most one input that is not
  stated."* A firewall's unrecorded `allow` beside a defaulted direction mixes
  two, and so does a carried prevention beside an unrecorded binding.
- *"The AWS policy channel is the one measured site that mixes two inputs that
  are not stated."* GCP `policy_data` beside an unwritten
  `public_access_prevention` is a second.
- *"A plan with no `configuration` section ... reads `plan-stated-value`"* was
  documented as a limitation; the review showed it is the defect itself, and
  so is every resource the configuration omits and every dynamic block. They
  all now read `configuration-unrecorded`.
- *"An empty expressions object ... is recorded"* (`recordsArguments`):
  Terraform never emits one. An empty body has no `expressions` key, and
  writing one irrelevant flag flipped a `BLOCK`'s step from stated to default --
  the less the author wrote, the stronger the claim.
- *"A dynamic `ip_configuration` that writes `ipv4_enabled` is labelled
  `provider-default`"* was the only dynamic case listed. Its mirror, a dynamic
  `settings` reading as stated, was not, and the `wroteSettings` guard was the
  cause.
- *"The Aurora default is false"* was right, and the step still called a
  carried `true` the provider's default.
- *GCP storage grants were not listed at all.* A grant settles only because
  prevention is not enforced, and an unwritten prevention read as stated.
- *Criterion 3 was claimed for `ipv4_enabled`* by a test that compared two
  different instances from two different plans and never asserted "nowhere
  else". It is now a true pair.
- *"The last two rows are the only survivors"* held for the table as written.
  A full sweep found five more that change bundle output with the suite green:
  Azure `database.admitted_by`, Azure `NETWORK_PUBLIC_INGRESS`, the
  environment's method through the real path, and the port step on the
  "port unusable, gate opens every port" branch. Each now has a test.
- *Criterion 7, "cannot be constructed"*: `Fact.State` is exported. Reworded.
- *Criterion 8, "the 15 new ones are the only plan fixtures with no
  baseline"*: there were 24.
- *`public-blob-container-defaulted`* defended a provider-default branch with a
  shape Terraform cannot produce, and the milestone 03 `public-blob` and
  `public-container` called a written `blob` the provider's default.
- *`TestEveryFindingSaysHowItKnows`* skipped a fixture it could not verify,
  which for the fixtures without a baseline meant in silence.
- *Validation* accepted a fact established twice, two methods for one fact, a
  finding with no contract step and fact paths that are not paths.

### Tests whose assertion changed

Three assertions were changed because D1 makes what they asserted false, and
each was replaced by the D1 answer, not removed:
`TestAnAbsentIPv4SwitchIsTheProvidersDefault` (settings with no
`ip_configuration` cannot be told from an unresolved dynamic one) became
`TestAnAbsentIPv4SwitchInAnUnrecordedBlockIsUnrecorded`;
`TestAKnownDirectionNobodyWroteIsTheProvidersDefault` on `fw-public`, whose
configuration records no `allow`, became
`TestAFirewallWhoseAllowIsNotRecordedIsUnrecorded`; and the
`public-blob-container-defaulted` row now asserts stated. Three tests that
assert a stated grant now read variants of their fixtures that write
`public_access_prevention`, which is their premise; the originals assert the
default. The criterion 3 pairs were made true pairs. No test was deleted or
skipped.

## Amendment: adversarial review, round 4

A fourth round ran at `3234f72` -- provider reality with real plans
(Terraform 1.14.0, `hashicorp/aws` 6.67.0, `hashicorp/google` 6.50.0,
`plan -refresh=false` against hand-written state, nothing applied), mutations
and claims, and contract coherence. All three returned BLOCK. No verdict was
wrong, and criterion 8 reproduced; the method again put `plan-stated-value` on
values nobody under review wrote. D1 and D2 stand; the second fix wave applied
D1 as written.

### Claims the first fix wave made that turned out false

- *"Terraform plans an unwritten argument that is not Computed to its default
  on every change, so unwritten beside a non-default value is a shape Terraform
  cannot produce; the value was written."* `lifecycle { ignore_changes }`
  carries the prior value into `after` on every update and no-op, and the
  plan's configuration does not record the lifecycle block. Tags, an ACL, an
  inline rule set, a firewall source and an IAM member nobody under review
  wrote read `plan-stated-value` on real-plan BLOCKs. The rule built on the
  premise (`MethodFor`'s "non-default means stated") is gone; such a value is
  `configuration-unrecorded`, or `prior-state` where carried.
- *"prior-state: an update of a Computed argument."* The same plans carry
  non-Computed arguments too (a GCP priority of 500 read as the documented
  1000). Carried is now decided by comparing `before` with `after`, and the
  Computed flag, which then decided nothing anywhere, was removed.
- *"An argument written as `null` reads as written; the provider then applies
  its default."* On real plans the provider does not: an update carries the
  state's value for `publicly_accessible = var.x` and `port = var.x` with `x`
  defaulting to `null`, exactly as when the argument is omitted, and a create
  carries `public_access_prevention = var.x` as unknown, exactly as when it is
  omitted. Both read `plan-stated-value` against `prior-state` and
  `provider-default` for the omitted form. A `null` write is now no write.
- *"A source that reaches every address was written wherever the configuration
  records the resource."* This justified removing GCP `source_ranges` as a
  firewall input. `ignore_changes = [source_ranges]` carries one nobody wrote;
  the input is back.
- *"`provider-default`: ... and the object is new"* while the code returned it
  on updates. The definition and the code now agree: a value not carried, on a
  new object or one the plan moves.
- *Criterion 9, "every killable mutant killed"* held for the wave's own 68
  mutants, not for the changed lines: about fifteen more non-equivalent mutants
  survived (ownership gate, Strongest against Weakest at three grants, the
  granting-only proof filters, the environment's contradiction rule, the
  fact-path rules). Each now has a test; see the criterion 9 re-measure below.
- *"The Computed flag on these blocks matters"* -- it was dead on every block.
- *"`declared.Argument` is the one place that asks"* -- `aws/database.go`
  hard-coded `provider-default` twice; both now go through it.

Four commit messages of the first wave say something false, and history was
not rewritten: `f0c1f13`'s subject and body say a firewall verdict rests on its
source, an input `cc19aee` then removed; `df393bb` says GCP `source_ranges`
uses `MethodFor`; `cc19aee` gives the false reason quoted above for removing
it, and does not name the four testdata README edits it carries; `9bf0eac`'s
subject, "a value nobody wrote is never stated", was false while `MethodFor`
stood and is true only from the second fix wave.

### Also fixed

- An Azure NSG grant took the best of every allow from any address, including
  one a deny cancelled whole, so a grant resting only on an unrecorded inline
  rule read stated. It takes the rules that still open something.
- A GCP deny skipped because it is egress, disabled, narrower in source or on
  another network contributed nothing to the verdict's method; each now does.
- `Weakest` and `Strongest` ranked the empty method as a derived one, so a
  forgotten method could hide behind a valid one; any method outside the closed
  set now makes both empty, which fails validation.
- `public-blob-container-defaulted`, a shape no real plan carries, is removed
  with the rule it defended.
- `EVIDENCE-BUNDLE.md` and `docs/MCP.md` say what each method means for a
  reader and what to do about it; the Markdown line format is unchanged.

### Tests whose assertion changed

The declared unit test that asserted `provider-default` for an unwritten,
non-Computed argument an update carries now asserts `prior-state`, which is the
requirement. Three tests that asserted a stated value on a hand-written fixture
whose configuration lists only references now read a variant whose
configuration records the value, and the originals assert
`configuration-unrecorded`: `TestASeparateRuleAddressIsStatedWhereTheConfigurationWritesIt`
(was `...EvenWhenTheConfigurationListsOnlyItsReferences`),
`TestAProofOfPreventionRestsOnFlagsSomebodyWrote`, and the separate-rule row of
`TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords`. The
`public-blob` row of `TestStorageAccessSettingsFollowTheConfiguration` now
asserts `configuration-unrecorded`, and the `public-blob-container-defaulted`
row is gone with its fixture. No test was skipped.

### Criterion 8, re-measured after the second fix wave

Binaries built from `git archive 3b50544` and from the second wave's head ran
`check --format json` on every plan JSON in the tree under the shipped contract
and the three in `scratchpad/intents/` (all-private, all-public, silent), the
*after* output normalised as before.

| | count |
| --- | --- |
| plans x contracts compared | 304 x 4 = 1216 |
| identical after normalisation, same exit code and stderr | 1216 |
| differing | 0 |
| exit codes, shipped contract (before = after) | 251 x `4`, 37 x `3`, 14 x `0`, 2 x `10` |

`git diff 3b50544 -- internal/verify/testdata/baseline` is empty and no fixture
with a baseline was touched; the 226 baselines still match. Between the first
wave's head and this one, across the fixtures both share, the steps that
changed are the hand-written fixtures that list only references:
`network.public_ingress` from `plan-stated-value` to `configuration-unrecorded`
(20 runs: `sg-public-rule`, `sg-rule-every-protocol`, `nsg-inline-unwritten`,
`nsg-rule-replaced`, `nsg-separate-open`) and `object_storage.public_access`
from `provider-default` to `configuration-unrecorded` (8 runs: `public-blob`,
`public-container`). No real plan's step changed. Steps on plan facts across
the 1216 runs, `resource.cloud` excluded: `plan-stated-value` 789,
`provider-default` 132, `configuration-unrecorded` 163, `prior-state` 95,
`documented-table` 72, `policy-document-interpreted` 12, `reference-resolved`
100.

### Criterion 9, re-measured after the second fix wave

The same harness, against the second wave's head in a separate worktree: 49
mutants of every method site the wave added or changed (the expression
evaluator, `Argument`'s decision, `Carried`, `Weakest` and `Strongest`, the
GCP firewall's source and skip inputs, the Azure grant's surviving rules, the
AWS switch's absent and unknown branches). On the first run 12 survived; each
was given a test or, for two, the code was simplified (a redundant `nil`
guard, a numeric comparison no shape needed); two mutants were malformed and
re-expressed. Final: all 49 killed.

The first wave's 79 mutants and the fourth review's 93 were re-run: 91 killed,
44 no longer apply (the text they mutate is gone -- `MethodFor`'s stated rule,
the Computed flag, `grantMethod`), 9 do not compile for the same reason, and
28 survive. Every survivor is one of the equivalent or unobservable kinds the
review itself triaged: the four `Known(false)` methods and the closed-group
defaults, the `Writing` and `Updates` guards that cannot change an answer, the
Required flags every fixture writes, the per-flag loop of the AWS proof (all
four flags share one method), GCP's allow/deny choice (the provider requires
exactly one), the Azure null-source handling, the ACL and container default
comparison for a value that grants nothing, and an empty-steps guard another
check already refuses. Each non-equivalent survivor the review listed --
`env-isdefault-true`, `aws-ownership-gates-dropped`, `aws-acl-isdefault-true`,
`aws-net-grant-weakest`, `az-db-strongest`, `gcp-st-member-proof-always`,
`gcp-st-policy-proof-always`, `aws-net-separate-proof-always` and the three
fact-path mutants -- is now killed; the Azure grant filters it listed mutate
code replaced by the surviving-rule rule, whose own mutants are killed; the
five "not Computed" mutants mutate a flag that no longer exists. Results:
`scratchpad/w2/mut/{w2b,w2c,prior}-r.json`.


## Amendment: user decision on unevaluated writes (third fix wave)

The second fix wave reported, as its concern 2, that a value written by a
reference, a variable, a function or block syntax and kept from state by
`lifecycle { ignore_changes }` still read `plan-stated-value`: the plan records
no value for the expression to compare with the one carried. The user decided
it, conservatively:

- **Decision.** Where the change keeps an existing object (an update or a
  no-op), the configuration records the argument as written by an expression
  whose value the plan does not record, and `after` equals `before` at the
  argument's path, the method is `configuration-unrecorded`, never
  `plan-stated-value`. Constant writes keep the second wave's behaviour; creates
  are unchanged.
- **Accepted cost.** A referenced value written legitimately that an update
  does not change loses "stated". Pinned on a real plan with no
  `ignore_changes`: `real-reference-write-unchanged`.
- **Block syntax**, by the same principle applied to what the verdict rests on.
  The mapper sites read whole blocks (a firewall's `allow`, the Cloud SQL
  `authorized_networks`, an inline rule set), so the parse now records each
  block written in block syntax from everything written in it
  (`ResourceChange.Block`): a constant only where every attribute inside, at
  every depth, is a constant or `null`, and contradicted where the planned
  blocks are not, one for one, blocks holding those constants on the
  attributes written. A carried block of constants is therefore stated or
  `prior-state` like a constant attribute -- the second wave read every written
  block stated -- and a carried block with anything else inside is
  `configuration-unrecorded`. Where the mechanism cannot decide per path -- an
  attribute written in a repeated block, a block inside a repeated block, a
  Required argument with no recorded expression -- it errs to
  `configuration-unrecorded`.
- **A reference write the update moves** stays `plan-stated-value`. The plan
  cannot show that `after` is what the expression evaluates to; the method
  rests on the move: `ignore_changes` keeps a value, so a value the plan moves
  is the configuration's. Pinned: `real-reference-write-moved`.

Measured on real plans (Terraform 1.14.0, `hashicorp/aws` 6.67.0,
`hashicorp/google` 6.50.0, `plan -refresh=false` against hand-written state,
nothing applied): `lower(var.acl)` is recorded exactly as `var.acl`
(`{"references": ["var.acl"]}`), a function of constants as `{}`, an AWS inline
rule with one referenced attribute as one reference expression for the whole
`ingress`, and a GCP block's attributes one by one.

### Tests whose assertion changed

By the decision, in `TestTheMethodFollowsWhatTheConfigurationRecords`:
`written from a resource, carried` asserted `plan-stated-value` and now asserts
`configuration-unrecorded`; `written as a variable recorded with a value` (an
update that carries the value) is renamed `..., carried` and asserts
`configuration-unrecorded` in place of `plan-stated-value`. Both had pinned the
behaviour the decision removes. Each gained create and moved siblings that
assert `plan-stated-value`. No test was removed or skipped.

### Criterion 8, re-measured after the third fix wave

The binary built from `3b50544` and one built from the third wave's tree ran
`check --format json` on every plan JSON in the tree under the shipped
contract and the three in `scratchpad/intents/`, normalised as before
(`scratchpad/w3/c8/c8.py`).

| | count |
| --- | --- |
| plans x contracts compared | 311 x 4 = 1244 |
| identical after normalisation, same exit code and stderr | 1244 |
| differing | 0 |
| exit codes, shipped contract (before = after) | 253 x `4`, 42 x `3`, 14 x `0`, 2 x `10` |

The seven plans added are the six real plans below and
`real-function-write-unchanged`. `git diff 3b50544 --
internal/verify/testdata/baseline` is empty and no fixture with a baseline was
touched; the 226 baselines still match. Against the second wave's head, across
the 304 plans both share, no step changed (`scratchpad/w3/c8/stepdiff.txt`):
no committed fixture had a carried write by reference or a carried block that
does not hold its constants. On the new plans, against the second wave:
`real-reference-write-ignored` (AWS) and `-unchanged` move
`object_storage.public_access`, `resource.environment` and
`network.public_ingress` from `plan-stated-value` to
`configuration-unrecorded`, except the constant group `const`, which stays
stated; `real-function-write-unchanged` moves `resource.environment` the same
way; `real-reference-write-moved` stays stated; on GCP the variable-written
bucket grant, the local-written firewall source, the variable port inside an
`allow` block and the variable-written authorized network move to
`configuration-unrecorded`, the constant `allow` and the constant network that
`ignore_changes` overrides move to `prior-state`, and the constant twins stay
stated (`scratchpad/w3/c8/newfixtures.txt`). Steps on plan facts across the
1244 runs, `resource.cloud`, `contract.` and `plan-action` excluded:
`plan-stated-value` 825, `configuration-unrecorded` 207, `provider-default` 132,
`prior-state` 107, `reference-resolved` 100, `documented-table` 72,
`policy-document-interpreted` 12.

### Criterion 9, re-measured after the third fix wave

The second wave's harness, re-pointed (`scratchpad/w3/mut/mut.py`): each mutant
replaces one string occurring once, the build must succeed, `go test ./...
-count=1` runs, and the file is restored. Every line the wave added or
changed was mutated. On the first run, 37 mutants: nine survived and four did
not compile:

- the four that did not compile were re-expressed (`&& false`, `_ =`);
- three survivors were equivalent guards, and the code was simplified instead:
  the `!recorded ||` beside the constant test (an unrecorded write is the zero
  `Expression`, which is deferred -- pinned by the repeated-block and
  no-expressions rows, and re-mutated as `m-constant-guard-*`), and the
  empty-body and empty-map guards of the block collection;
- six were given tests: a single nested block inside a block, the same block
  written twice, two blocks written where the plan has one, a block the plan
  does not know, one element it does not know, and planned blocks that are not
  objects.

Final, 38 mutants: the 36 that apply are all killed (failing tests listed are the first
three the harness records). Two more survive and are unobservable: the
`default: continue` of `collectBlocks` and of `blockConstants` handle an entry
that is neither an object nor an array, which `Parse` already rejects
("must be an object or an array of blocks"). Results:
`scratchpad/w3/mut/final-results.json`.

| mutant | file | result |
| --- | --- | --- |
| `m-unrecorded-stated` | `providers/declared/method.go` | killed: `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue`, `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `c-blocks-never` | `terraformplan/config.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestValuesIgnoreChangesKeepsArePriorState` |
| `m-constant-guard-recorded` | `providers/declared/method.go` | killed: `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue`, `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `m-constant-guard-deferred` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `m-block-lookup-dropped` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestValuesIgnoreChangesKeepsArePriorState` |
| `m-block-lookup-inverted` | `providers/declared/method.go` | killed: `TestAnArgumentWrittenAsANullVariableReadsAsUnwritten`, `TestBlockFlagsAnUpdateResetsAreTheProvidersDefault`, `TestValuesIgnoreChangesKeepsArePriorState` |
| `m-not-carried-inverted` | `providers/declared/method.go` | killed: `TestAWriteThePlanDoesNotEvaluateIsStatedWhereTheUpdateMovesTheValue`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue`, `TestValuesIgnoreChangesKeepsArePriorState` |
| `m-not-carried-unrecorded` | `providers/declared/method.go` | killed: `TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate`, `TestAStatedPortIsStatedInTheStep`, `TestTheIPv4DefaultChangesOneStepAndNothingElse` |
| `m-contradicted-stated` | `providers/declared/method.go` | killed: `TestAnAdmissionByAUnionRestsOnEveryRuleInIt`, `TestValuesIgnoreChangesKeepsArePriorState` |
| `c-repeated-recorded` | `terraformplan/config.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `c-repeated-not-propagated` | `terraformplan/config.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `c-repeated-any` | `terraformplan/config.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `c-expression-as-block` | `terraformplan/config.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `c-single-block-skipped` | `terraformplan/config.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `c-blocks-not-assigned` | `terraformplan/config.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestValuesIgnoreChangesKeepsArePriorState` |
| `e-repeated-evaluated` | `terraformplan/expression.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `e-nonconstant-constant` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `e-contradiction-inverted` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `e-contradiction-never` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `e-null-not-constant` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-deferred-wildcard` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `e-single-nested-ignored` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-list-nested-ignored` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-inner-nonconstant-ignored` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-inner-not-kept` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-unknown-mismatch` | `terraformplan/expression.go` | killed: `TestABlockThePlanDoesNotShowIsNeverContradicted` |
| `e-single-count-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-single-branch-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-count-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-used-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-notfound-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `e-body-unknown-mismatch` | `terraformplan/expression.go` | killed: `TestABlockThePlanDoesNotShowIsNeverContradicted` |
| `e-body-kind-match` | `terraformplan/expression.go` | killed: `TestABlockThePlanDoesNotShowIsNeverContradicted` |
| `e-body-nested-skipped` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-body-absent-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-body-constant-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `c-scalar-entry-recorded` | `terraformplan/config.go` | survived: unobservable, `Parse` rejects the shape |
| `e-scalar-entry-nested` | `terraformplan/expression.go` | survived: unobservable, `Parse` rejects the shape |

## Amendment: adversarial review, round 5

A fifth round ran at `44fb773` -- provider reality with real plans (Terraform
1.14.0, `hashicorp/aws` 6.67.0, `hashicorp/google` 6.50.0, `plan
-refresh=false` against hand-written state, nothing applied) and mutations and
claims. Both returned BLOCK. No verdict was wrong and criterion 8 reproduced;
the method again put `plan-stated-value` on BLOCK findings for values carried
from state, because it was decided somewhere other than where the verdict
reads.

### The principle the fix wave applied

On an update or no-op, a value is `plan-stated-value` only if, at the exact
place the verdict reads -- a map key, an element, not the enclosing map or
block -- the configuration records a constant write that equals the planned
value. `null`, or an attribute a written block does not hold, matches only an
empty value. A recorded constant the plan contradicts there is `prior-state` on
any update, moved or not. Whether the plan keeps the value is decided at the
same place, and a sensitive mark must not make a kept value look moved.
Anything the plan cannot decide there is `configuration-unrecorded`; nothing is
stated by default. The third wave's rule for a write the update moves -- stated,
because `ignore_changes` keeps a value -- stands, now decided at that place and
only where the plan does not contradict the write.

### Claims the third wave made that turned out false

- *"Carried is decided by comparing `before` with `after` at the argument's
  path."* The environment's argument path was the whole `tags`/`labels` map,
  not the key the verdict reads, so `ignore_changes = [tags["environment"]]`
  beside another tag the configuration moves read the written `staging` as
  stated while the plan held the state's `prod` (`real-tags-partial-ignore`,
  `real-labels-partial-ignore`). Fixed: `declared.Argument.Key`, and each key
  of a constant map compared on its own.
- *"A value known and equal on both sides."* One tag written from a `sensitive`
  variable made the map unreadable on both sides, so a no-op read as moved and
  the reference write as stated, where its non-sensitive twin read
  `configuration-unrecorded` (`real-tags-sensitive-ignored` and `-control`).
  Fixed: `terraformplan.Value.Carried` is decided while parsing from the raw
  `before` and `after`, before marks apply, and keeps only the answer.
- *"An attribute written as blocks records every attribute, null where nothing
  was written, so a null matches anything"* (the `Expression` documentation and
  `constantMatches`). It let a source only the state held read stated: an AWS
  inline rule writing `10.0.0.0/8` under `ignore_changes = [ingress]` with
  `::/0` in state, and one writing no source with `0.0.0.0/0` in state, were
  BLOCKs with `network.public_ingress = plan-stated-value`
  (`real-sg-null-attribute-from-state`, `real-sg-unwritten-source-from-state`).
  Azure's inline `security_rule` has the same encoding. Fixed: `null` matches
  only `null`, `[]`, `{}`, `""` or `false`, which is what the controls plan.
- *"Compared one for one on the attributes written; extra planned attributes
  are ignored."* `allow { protocol = "tcp" }` under `ignore_changes = [allow]`
  with `ports = ["22"]` in state read the state's ports as stated
  (`real-blocks-unwritten-from-state`). Fixed: an attribute a block does not
  write is compared as written as nothing.
- *"A provider that normalizes a constant ... would read `prior-state`, never
  stated; none was found."* Found, on real no-op plans: GCP
  `protocol = "TCP"`, AWS `protocol = "TCP"` and `protocol = "6"` against
  `tcp`. The first half held; the Limitations now say so and the fixtures pin
  it. No normalization was added (see Limitations).
- *"36 of 36 applicable mutants killed"* held for the wave's own set, not for
  every changed line: five evaluator survivors changed bundle output (an
  indexed attribute of a variable, a variable whose name another's begins
  with, a map key the plan lacks, two comparisons of mismatched kinds), and
  about twelve more were unpinned without being permissive. Each now has a
  test or was removed with the code it mutated (`equal`, replaced by the parse's
  answer).
- *The definition of `plan-stated-value`* in the method table here, in
  `EVIDENCE-BUNDLE.md`, `MCP.md` and `PRODUCT.md` -- "the plan carries that
  value" -- and the reader guide's "it is what the author wrote" were false for
  the null-attribute shape. All now state the principle above.
- Found by reasoning, not planned: an `optional(T, default)` attribute set to
  `null` through a module input reads as unwritten while Terraform applies the
  default. That understates; it is now a Limitation.

### Tests whose assertion changed

- `TestTheMethodFollowsWhatTheConfigurationRecords`, "written as another
  constant, on an update that moves it": `plan-stated-value` became
  `prior-state`, by the principle (a contradicted constant is `prior-state`
  moved or not).
- `TestABlockIsDecidedByWhatIsWrittenInsideIt`, "null inside a block is no
  write": `plan-stated-value` became `prior-state` (renamed "null inside a block
  matches only an empty value"): the row asserted the defect.
  `TestABlockIsRecordedFromEverythingWrittenInIt`, "a literal null inside" and
  "a variable recorded as null inside": not contradicted became contradicted
  (renamed "..., where the plan holds a value"), for the same reason.
- Rows whose subject was ordering or nesting -- "constants", "constants in
  another order", "a block inside a block", "a single block inside a block",
  "constants, carried, in another order", "a block inside a block, constants,
  carried" -- now write every attribute the planned blocks hold, so they still
  test what they are named for; their original inputs came back as new rows
  asserting the contradiction.
- No test was removed or skipped.

### Criterion 8, re-measured after the fifth review's fix wave

The binary built from `3b50544`, one built from the third wave's head
(`44fb773`) and one built from this wave's tree ran `check --format json` on
every plan JSON in the tree under the shipped contract and the three in
`scratchpad/intents/`, normalised as before (`scratchpad/w4/c8.py`).

| | count |
| --- | --- |
| plans x contracts compared | 322 x 4 = 1288 |
| identical to `3b50544` after normalisation, same exit code and stderr | 1288 |
| identical to `44fb773` after normalisation, same exit code and stderr | 1288 |
| differing | 0 |
| exit codes, shipped contract (before = after) | 259 x `4`, 46 x `3`, 15 x `0`, 2 x `10` |

The 322 plans include `examples/tfplan.json` and the ten fixtures this wave
added (seven real plans, three hand-authored). `git diff 3b50544 --
internal/verify/testdata/baseline` is empty and no fixture that existed before
this wave was touched; the 226 baselines still match. Against `44fb773`, no
step changed on any plan that existed there: the 27 step changes
(`scratchpad/w4/c8-final.txt`) are all on the new fixtures, each one
`plan-stated-value` that became `prior-state` or, for the sensitive tag,
`configuration-unrecorded`. Steps on plan facts across the 1288 runs,
`resource.cloud`, `contract.` and `plan-action` excluded: `plan-stated-value`
838, `configuration-unrecorded` 219, `prior-state` 158, `provider-default` 132,
`reference-resolved` 100, `documented-table` 72, `policy-document-interpreted`
12.

### Criterion 9, re-measured after the fifth review's fix wave

The same harness (`scratchpad/w4/mut.py`, the fifth review's `run.py`
re-pointed at a worktree of this wave's head): each mutant replaces one string
occurring once, the change must show in `git diff`, `go vet ./...` must pass,
`go test ./... -count=1` runs, and the file is restored. Every line this wave
added or changed was mutated -- the carried mark the parse sets, the tri-state
comparison, per-key elements, the decision at the key, `Carried`, the
environment's keys -- 85 mutants, and the fifth review's survivors and the
third wave's 38 were re-run beside them.

On the first run 66 of the 85 were killed, six did not compile (an unused
variable) and thirteen survived:

- three survivors, and one mutant that did not compile, were redundant code,
  and the code was removed: the descent guard for a withheld node (it has no
  kind to descend by), the shape checks on a prior value (one of another shape
  holds nothing below), and the early `break` when a set element matches;
- two are the survivors below;
- nine were given tests, and the re-run killed them: a value with no prior
  state at its place, or named only by a mask; an element not yet known; a path
  naming no single planned value; a set pairing through withheld values, and an
  undecided element compared first; a block withheld, unknown or absent; an
  outer block contradicted through its inner block alone;
- the other five that did not compile were re-expressed (`|| true`, `_ =`) and
  re-run.

The re-run found `n-key-dropped` alive: the fifth review's fixtures are
fixed by the contradiction rule alone, so nothing showed the key deciding apart
from the map. A row where only another key is kept now does.

Final, 82 mutants of this wave: 80 killed. Two survive: the comparison of a
constant that is neither a string, a bool nor a number, which `Parse` never
produces, and `Carried` following a prior value that is not a list, which is
equivalent. Of the fifth review's eleven, nine are killed, including all five
it named as permissive; `r5-ev-mostspecific-bracket` and
`r5-ev-traversal-index-deferred` are the equivalents it triaged. Of the third
wave's 38, 21 are killed, 15 no longer apply because this wave rewrote the
comparison they mutate (its own mutants above cover the new code), and the two
`Parse`-rejected shapes survive as before. Results:
`scratchpad/w4/{mut2,mut3,mut4}-r.json`.

| mutant | file | result |
| --- | --- | --- |
| `v-carried-true` | `terraformplan/value.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAKeyOfAMapIsDecidedAtTheKey` and 7 more |
| `v-carried-false` | `terraformplan/value.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` and 16 more |
| `p-mark-dropped` | `terraformplan/parse.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` and 16 more |
| `c-before-present` | `terraformplan/mask.go` | killed: `TestAValueIsCarriedWhateverItsSensitivity` |
| `c-after-present` | `terraformplan/mask.go` | killed: `TestAValueIsCarriedWhateverItsSensitivity` |
| `c-unknown` | `terraformplan/mask.go` | killed: `TestAValueIsCarriedWhateverItsSensitivity` |
| `c-equal-true` | `terraformplan/mask.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAKeyOfAMapIsDecidedAtTheKey` and 7 more |
| `c-obj-in-before` | `terraformplan/mask.go` | killed: `TestAValueIsCarriedWhateverItsSensitivity` |
| `c-obj-in-after` | `terraformplan/mask.go` | killed: `TestAValueIsCarriedWhateverItsSensitivity` |
| `c-obj-unknown-mask` | `terraformplan/mask.go` | killed: `TestAValueIsCarriedWhateverItsSensitivity` |
| `c-obj-not-assigned` | `terraformplan/mask.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` and 16 more |
| `c-arr-in-before` | `terraformplan/mask.go` | killed: `TestAValueOfTheWrongKindIsNotAnAnswer`, `TestEveryFixtureIsUnchangedWhenNothingMatches`, `TestEveryMissingControlAnUnsettledSetReportsIsAsserted` and 6 more |
| `c-arr-in-after` | `terraformplan/mask.go` | killed: `TestEveryFixtureIsUnchangedWhenNothingMatches`, `TestEveryValidFixtureParses`, `TestInspectReportsUnknownPaths` and 1 more |
| `c-arr-unknown-mask` | `terraformplan/mask.go` | killed: `TestAValueIsCarriedWhateverItsSensitivity` |
| `c-arr-not-assigned` | `terraformplan/mask.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAValueIsCarriedWhateverItsSensitivity`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` and 2 more |
| `e-elem-nil-null` | `terraformplan/expression.go` | killed: `TestAKeyOfAMapIsDecidedAtTheKey`, `TestASensitiveTagDoesNotMakeAKeptMapMove`, `TestAWriteThePlanDoesNotEvaluateIsStatedWhereTheUpdateMovesTheValue` and 2 more |
| `e-elem-found-ignored` | `terraformplan/expression.go` | killed: `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords`, `TestAKeyOfAMapIsDecidedAtTheKey`, `TestAKeyTheLifecycleKeepsIsPriorStateWhileTheMapMoves` and 3 more |
| `e-elem-missing-whole` | `terraformplan/expression.go` | killed: `TestAKeyOfAMapIsDecidedAtTheKey`, `TestEachKeyOfAWrittenMapIsDecidedOnItsOwn` |
| `e-expr-record-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantNotInAfterIsContradicted` and 13 more |
| `e-expr-elements-dropped` | `terraformplan/expression.go` | killed: `TestAKeyOfAMapIsDecidedAtTheKey`, `TestEachKeyOfAWrittenMapIsDecidedOnItsOwn` |
| `e-elem-null-constant` | `terraformplan/expression.go` | killed: `TestEachKeyOfAWrittenMapIsDecidedOnItsOwn` |
| `e-elem-record-dropped` | `terraformplan/expression.go` | killed: `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords`, `TestAKeyOfAMapIsDecidedAtTheKey`, `TestAKeyTheLifecycleKeepsIsPriorStateWhileTheMapMoves` and 3 more |
| `e-elem-whole-value` | `terraformplan/expression.go` | killed: `TestAKeyOfAMapIsDecidedAtTheKey`, `TestAWithheldKeyIsUndecided`, `TestEachKeyOfAWrittenMapIsDecidedOnItsOwn` |
| `e-blocks-record-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestABlockThePlanDoesNotShowIsNeverContradicted` and 5 more |
| `e-record-contra-any` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockThePlanDoesNotShowIsNeverContradicted`, `TestAComparisonThePlanCannotCompleteIsUndecided` and 4 more |
| `e-record-undecided-never` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept` and 1 more |
| `e-compareif-matched` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAComparisonThePlanCannotCompleteIsUndecided` |
| `e-notshown-matched` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAWithheldKeyIsUndecided` |
| `e-notshown-redacted-dropped` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAValueThePlanDoesNotShowIsNeverContradicted` and 1 more |
| `e-notshown-absent-nil-contra` | `terraformplan/expression.go` | killed: `TestNothingWrittenMatchesOnlyAnEmptyValue` |
| `e-notshown-absent-matched` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantNotInAfterIsContradicted` |
| `e-nil-anything` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAnAttributeABlockDoesNotWriteIsNotStated` and 3 more |
| `e-nil-nothing` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAConstantNotInAfterIsContradicted` and 5 more |
| `e-list-shape-matched` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantNotInAfterIsContradicted` |
| `e-list-len-dropped` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantNotInAfterIsContradicted` |
| `e-map-kind-matched` | `terraformplan/expression.go` | killed: `TestAConstantNotInAfterIsContradicted` |
| `e-map-extra-key-dropped` | `terraformplan/expression.go` | killed: `TestAConstantNotInAfterIsContradicted` |
| `e-map-last-wins` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantTheProviderCanonicalizesReadsPriorState`, `TestAnAttributeNobodyWroteInAnInlineRuleIsNotStated` and 4 more |
| `e-scalar-notext-matched` | `terraformplan/expression.go` | survived: unobservable, every constant Parse decodes is a string, a bool or a number |
| `e-scalar-string-true` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAComparisonThePlanCannotCompleteIsUndecided`, `TestAConstantNotInAfterIsContradicted` and 13 more |
| `e-scalar-number-true` | `terraformplan/expression.go` | killed: `TestABlockThePlanDoesNotShowIsNeverContradicted` |
| `e-scalar-bool-true` | `terraformplan/expression.go` | killed: `TestAConstantNotInAfterIsContradicted`, `TestAValueNobodyRecordedWritingIsNeverStated`, `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `e-scalar-same-ignored` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestABlockThePlanDoesNotShowIsNeverContradicted`, `TestAComparisonThePlanCannotCompleteIsUndecided` and 16 more |
| `e-empty-null-false` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestNothingWrittenMatchesOnlyAnEmptyValue` |
| `e-empty-container-any` | `terraformplan/expression.go` | killed: `TestAnAttributeABlockDoesNotWriteIsNotStated`, `TestAnAttributeNobodyWroteInAnInlineRuleIsNotStated`, `TestAnInlineRuleAttributeNobodyWroteIsNotStated` and 1 more |
| `e-empty-object-dropped` | `terraformplan/expression.go` | killed: `TestNothingWrittenMatchesOnlyAnEmptyValue` |
| `e-empty-string-any` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestNothingWrittenMatchesOnlyAnEmptyValue` |
| `e-empty-bool-any` | `terraformplan/expression.go` | killed: `TestNothingWrittenMatchesOnlyAnEmptyValue` |
| `e-empty-default-true` | `terraformplan/expression.go` | killed: `TestNothingWrittenMatchesOnlyAnEmptyValue` |
| `e-set-strict-lt` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided` |
| `e-set-unpaired-matched` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestABlockThePlanDoesNotShowIsNeverContradicted` and 12 more |
| `e-set-reuse` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided` |
| `e-set-last-wins` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided` |
| `e-set-used-skip-dropped` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided` |
| `e-blocks-single-count` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-blocks-shape-matched` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAnAttributeABlockDoesNotWriteIsNotStated` |
| `e-body-kind-matched` | `terraformplan/expression.go` | killed: `TestABlockThePlanDoesNotShowIsNeverContradicted` |
| `e-body-nested-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `e-body-written-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestABlockThePlanDoesNotShowIsNeverContradicted` and 3 more |
| `e-body-unwritten-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAComparisonThePlanCannotCompleteIsUndecided` and 2 more |
| `e-body-unwritten-matched` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAComparisonThePlanCannotCompleteIsUndecided` and 2 more |
| `e-body-notshown-matched` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided` |
| `e-blocks-notshown-matched` | `terraformplan/expression.go` | killed: `TestAComparisonThePlanCannotCompleteIsUndecided` |
| `d-key-ignored` | `providers/declared/method.go` | killed: `TestAKeyOfAMapIsDecidedAtTheKey` |
| `d-key-path-whole` | `providers/declared/method.go` | killed: `TestAKeyOfAMapIsDecidedAtTheKey` |
| `d-key-element-whole` | `providers/declared/method.go` | killed: `TestAKeyOfAMapIsDecidedAtTheKey` |
| `d-create-prior` | `providers/declared/method.go` | killed: `TestABindingGrantIsStated`, `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault` and 50 more |
| `d-create-contradicted` | `providers/declared/method.go` | killed: `TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords`, `TestTheMethodFollowsWhatTheConfigurationRecords` |
| `d-contradicted-dropped` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantTheProviderCanonicalizesReadsPriorState`, `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` and 15 more |
| `d-contradicted-stated` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantTheProviderCanonicalizesReadsPriorState`, `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` and 15 more |
| `d-moved-stated-unrecorded` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAKeyOfAMapIsDecidedAtTheKey` and 2 more |
| `d-undecided-dropped` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept` |
| `d-nonconstant-dropped` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAKeyOfAMapIsDecidedAtTheKey`, `TestASensitiveTagDoesNotMakeAKeptMapMove` and 2 more |
| `d-carried-before-kind` | `providers/declared/method.go` | survived: equivalent, a prior value that is not a list holds nothing at the places below and is never equal to a planned list |
| `d-carried-before-len` | `providers/declared/method.go` | killed: `TestCarriedFollowsABlockOnlyThroughItsOneElement` |
| `d-carried-after-len` | `providers/declared/method.go` | killed: `TestCarriedFollowsABlockOnlyThroughItsOneElement` |
| `d-carried-block-true` | `providers/declared/method.go` | killed: `TestCarriedFollowsABlockOnlyThroughItsOneElement` |
| `d-carried-block-false` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestCarriedFollowsABlockOnlyThroughItsOneElement` |
| `d-carried-leaf-true` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAKeyOfAMapIsDecidedAtTheKey` and 6 more |
| `n-strongest` | `providers/declared/environment.go` | killed: `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` |
| `n-first-key-only` | `providers/declared/environment.go` | killed: `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` |
| `n-key-dropped` | `providers/declared/environment.go` | killed: `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` |
| `r5-ev-traversal-nonobject-deferred` | `terraformplan/expression.go` | killed: `TestAnExpressionSaysWhatItEvaluatesToOffline` |
| `r5-ev-traversal-missing-null` | `terraformplan/expression.go` | killed: `TestAnExpressionSaysWhatItEvaluatesToOffline` |
| `r5-ev-traversal-nil-constant` | `terraformplan/expression.go` | killed: `TestAnExpressionSaysWhatItEvaluatesToOffline` |
| `r5-ev-traversal-off` | `terraformplan/expression.go` | killed: `TestAnExpressionSaysWhatItEvaluatesToOffline` |
| `r5-ev-mostspecific-bracket` | `terraformplan/expression.go` | survived: equivalent, an indexed reference is unresolved and decides the expression whatever else is read |
| `r5-ev-mostspecific-anyprefix` | `terraformplan/expression.go` | killed: `TestAnExpressionSaysWhatItEvaluatesToOffline` |
| `r5-m-unwritten-carried-unrecorded` | `providers/declared/method.go` | killed: `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords`, `TestADenySkippedRestsTheVerdictOnWhyItWasSkipped`, `TestADirectionCarriedFromStateIsPriorState` and 9 more |
| `r5-gn-disabled-isdefault-true` | `providers/gcp/network.go` | killed: `TestADenySkippedRestsTheVerdictOnWhyItWasSkipped` |
| `r5-aws-openedby-weakest` | `providers/aws/network.go` | killed: `TestASeparateRuleOpenedTwiceTakesTheBestProof` |
| `r5-aws-openedby-isdefault-true` | `providers/aws/network.go` | killed: `TestASeparateRuleAddressTheConfigurationDoesNotRecordIsUnrecorded`, `TestASeparateRuleOpenedTwiceTakesTheBestProof` |
| `r5-ev-traversal-index-deferred` | `terraformplan/expression.go` | survived: equivalent, an indexed attribute misses the key and is unresolved anyway |
| `w3:c-scalar-entry-recorded` | `terraformplan/config.go` | survived: unobservable, `Parse` rejects the shape |
| `w3:e-scalar-entry-nested` | `terraformplan/expression.go` | survived: unobservable, `Parse` rejects the shape |
| `w3:m-unrecorded-stated` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAKeyOfAMapIsDecidedAtTheKey` and 3 more |
| `w3:c-blocks-never` | `terraformplan/config.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestABlockThePlanDoesNotShowIsNeverContradicted` and 10 more |
| `w3:m-constant-guard-recorded` | `providers/declared/method.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:m-constant-guard-deferred` | `providers/declared/method.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:m-block-lookup-dropped` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestADenyAppliedThroughACarriedSourceIsPriorState`, `TestADenySkippedRestsTheVerdictOnWhyItWasSkipped` and 5 more |
| `w3:m-block-lookup-inverted` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantTheProviderCanonicalizesReadsPriorState`, `TestADeclaredEnvironmentSaysWhatTheConfigurationRecords` and 22 more |
| `w3:m-not-carried-inverted` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAKeyOfAMapIsDecidedAtTheKey` and 4 more |
| `w3:m-not-carried-unrecorded` | `providers/declared/method.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept`, `TestAKeyOfAMapIsDecidedAtTheKey` and 2 more |
| `w3:m-contradicted-stated` | `providers/declared/method.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:c-repeated-recorded` | `terraformplan/config.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `w3:c-repeated-not-propagated` | `terraformplan/config.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `w3:c-repeated-any` | `terraformplan/config.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` and 1 more |
| `w3:c-expression-as-block` | `terraformplan/config.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `w3:c-single-block-skipped` | `terraformplan/config.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `w3:c-blocks-not-assigned` | `terraformplan/config.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestABlockThePlanDoesNotShowIsNeverContradicted` and 10 more |
| `w3:e-repeated-evaluated` | `terraformplan/expression.go` | killed: `TestOnlyABlockWrittenInOnePlaceIsRecorded` |
| `w3:e-nonconstant-constant` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `w3:e-contradiction-inverted` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-contradiction-never` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-null-not-constant` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `w3:e-deferred-wildcard` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestABlockIsRecordedFromEverythingWrittenInIt`, `TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue` |
| `w3:e-single-nested-ignored` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `w3:e-list-nested-ignored` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `w3:e-inner-nonconstant-ignored` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `w3:e-inner-not-kept` | `terraformplan/expression.go` | killed: `TestABlockIsRecordedFromEverythingWrittenInIt` |
| `w3:e-unknown-mismatch` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-single-count-dropped` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-single-branch-dropped` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-count-dropped` | `terraformplan/expression.go` | killed: `TestABlockIsDecidedByWhatIsWrittenInsideIt`, `TestAnAttributeABlockDoesNotWriteIsNotStated` |
| `w3:e-used-dropped` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-notfound-dropped` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-body-unknown-mismatch` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-body-kind-match` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-body-nested-skipped` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-body-absent-dropped` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
| `w3:e-body-constant-dropped` | `terraformplan/expression.go` | not applied: the text it mutates was rewritten by this wave |
