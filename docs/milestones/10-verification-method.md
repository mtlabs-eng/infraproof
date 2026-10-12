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
  | `plan-stated-value` | the plan's configuration records that the author wrote the argument |
  | `provider-default` | the configuration records the argument as unwritten, and the object is new: the value is the provider's documented default |
  | `prior-state` | the configuration records the argument as unwritten, the change updates an existing object, and the value is the one Terraform carried from its prior state |
  | `configuration-unrecorded` | the plan does not record whether the author wrote the argument |
  | `policy-document-interpreted` | the value results from this build's reading of a JSON policy document |
  | `reference-resolved` | the value is obtainable only by resolving a reference: the security groups a database reaches through `vpc_security_group_ids` |
  | `documented-table` | the value comes from a closed, documented table in this build |
  | `plan-action` | the value is the classification of the plan's actions |
  | `intent-comparison` | the fact is the comparison with the intent contract |

  `prior-state` and `configuration-unrecorded` were added by the adversarial
  review (decision D1, see the amendment below); 1.3 was unreleased, so the
  schema version stays `1.3`. `reference-resolved` was narrowed by decision
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

## Prerequisites

Milestones 01, 03, 08 and 09. The plan should report, as milestone 09 did, any
shared machinery this milestone turns out to need changed beyond `model.Fact`
and the mappers' call sites.

## Limitations as built

Written from what the tests measure at the end of the milestone, after the
adversarial review's fix wave.

- **The method follows what the configuration records, not the `after`
  value.** Real plans showed that a provider writes the default of an unwritten
  Optional argument into `after` as a known value, and that Terraform carries
  an unwritten Computed value over from prior state on an update. One
  mechanism, `declared.Argument`, decides every mapper's method: stated only on
  a positive record; `provider-default` where the configuration records the
  argument as unwritten on a new object; `prior-state` where it does so on an
  update and the argument is Computed; `configuration-unrecorded` everywhere
  else. The value itself is read exactly as in milestone 09.
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
- **`prior-state` is decided by the change's actions and the schema.** An
  update that creates nothing, of an argument the mapper knows is Computed. The
  method does not compare `before` with `after`, so a provider that recomputes
  an unwritten Computed value on update would still read `prior-state`.
- **One contradiction is settled as stated.** An argument that is neither
  Computed nor a block is planned to its default whenever it is unwritten, so a
  configuration recording it as unwritten beside a non-default value is a shape
  Terraform cannot produce; the value was written. This is applied where the
  default is known: AWS rule addresses, the bucket ACL and the block flags'
  proof of prevention, GCP `source_ranges`, Azure `container_access_type` and
  separate NSG rule sources, and the environment tags. It is what lets the
  hand-written fixtures that list only references read their written values as
  stated. The Azure account gate's default is not measured here, so it takes
  only what the configuration records.
- **An argument written as `null` reads as written.** The configuration lists an
  argument the author wrote as `null`, either as a constant or through a
  variable that defaults to `null`, exactly as it lists one with a value. The
  provider then applies its default, and the method reads `plan-stated-value`.
  The value is still the one milestone 09 read.
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
- **An Azure NSG grant takes the method of its granting rules, not of the
  denies it survived.** GCP's firewall counts the inputs of a deny it applied or
  skipped on priority; the Azure resolve does not report which deny it weighed.
- **GCP firewall `disabled` carries no method of its own.** A verdict on an
  enabled firewall rests on `disabled` being `false`, which the provider
  defaults when it is unwritten. `disabled` is not cited as evidence, so it
  takes no part in the method either, and the verdict takes the method of its
  other inputs.
- **The hand-written fixtures from before this milestone under-state what they
  write, and cannot be corrected.** Their configurations list only the
  arguments that carry a reference, such as `bucket` or `network`. Correcting
  one changes its plan digest, which the frozen milestone 09 baselines record,
  so they stay as they are. Where the value is one the contradiction above
  settles, it reads stated; where it is a block, such as `fw-public`'s `allow`,
  the finding reads `configuration-unrecorded`. The fixtures added for this
  milestone, which have no baseline, now record the allow and source their
  `after` carries.
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

The fix wave added 15 provider fixtures, all without a baseline: twelve real
plans (`real-rds-unwritten-update` and `-create`, `real-sg-ingress-from-state`,
`real-acl-account-block-empty` and `-one-flag`, `real-sql-ip-configuration-from-state`,
`real-sql-dynamic-settings`, `real-bucket-prevention-pair` and `-from-state`,
`real-firewall-dynamic-allow`, `real-sql-ipv4-written` and `-unwritten`), and
three variants of GCP grant fixtures that write `public_access_prevention`. It edited only the `configuration` block of
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
| plans × contracts compared | 271 × 4 = 1084 |
| identical after normalisation, same exit code and stderr | 1084 |
| differing | 0 |
| provider fixtures | 240, of which 39 have no baseline |
| exit codes, shipped contract (before = after) | 226 × `4`, 30 × `3`, 13 × `0`, 2 × `10` |

The two `10`s are malformed-input fixtures and were `10` before. Steps observed
across the 1084 runs, by method, on plan facts: `plan-stated-value` 1174,
`provider-default` 124, `configuration-unrecorded` 119, `prior-state` 16,
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
