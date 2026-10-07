# Milestone 09: database exposure

## Objective

Detect a managed database the change makes reachable from the public internet,
across AWS, Azure and GCP, through one universal rule — and find out whether a
family that **composes two existing ones** can be added without either of them
changing.

## Why this family

The tool decides two families. Object storage asks "who may read this data", and
network exposure asks "who may reach this port". A managed database is the first
resource where the answer needs both at once, and it is where the two previous
milestones' machinery either pays off or does not.

It is also the highest-impact thing the build still cannot decide. A publicly
reachable Postgres instance is reported today as a resource no mapper
interpreted.

## What makes this different from 08

Every cloud splits the question into two independent facts, and **both** must be
true for the database to be reachable:

| | public endpoint switch | who may reach it |
| --- | --- | --- |
| AWS `aws_db_instance`, `aws_rds_cluster_instance` | `publicly_accessible` | `vpc_security_group_ids` — the security groups milestone 08 already resolves |
| Azure `azurerm_mssql_server`, `azurerm_postgresql_flexible_server` | `public_network_access_enabled` | separate firewall-rule resources, as start/end IP **ranges** |
| GCP `google_sql_database_instance` | `settings.ip_configuration.ipv4_enabled` | `authorized_networks` CIDRs inside the same block |

Neither fact alone is a finding. A public endpoint nobody is admitted to is not
reachable; an allow list on a database with no public endpoint reaches nothing.
Reporting either alone would produce a finding on the ordinary shape, which is
how a tool teaches people to ignore it.

That conjunction is the whole milestone. It is also why this family is worth
doing third rather than a fourth independent one: it is the first test of whether
the normalized model composes, instead of growing a parallel column per family.

## What the provider schemas and real plans say

Measured against `terraform providers schema -json` and against genuine
`terraform plan` output, not against documentation prose. Milestone 08 shipped
three defects that came from reading docs instead of plans.

- **AWS is the easy cloud for a plain instance and not for Aurora.** On
  `aws_db_instance`, `publicly_accessible` is `Optional` and *not* `Computed`: a
  real plan emits `false` when it is unwritten, which is both the provider's
  default and the safe one, and no configuration guard is needed there.
  - On `aws_rds_cluster_instance` it is `Optional` **and `Computed`**, and a real
    plan emits it **unknown** when unwritten. That is milestone 08's worst trap
    again, so the Aurora path does need `declared.Unwritten` — a mapper built on
    the first sentence alone would answer UNKNOWN for every idiomatic Aurora
    instance. An independent review found this stated the other way round here,
    and the schema and a real plan both contradicted it.
- **AWS splits the switch away from the cluster.** `aws_rds_cluster` has no
  `publicly_accessible` at all; `aws_rds_cluster_instance` does. An Aurora
  cluster is reachable through its instances, so the subject is the instance and
  a cluster with no instance in the plan settles nothing.
- **GCP repeats milestone 08's worst trap, one level deeper than the machinery
  reached.** An instance that writes no `ip_configuration` emits the whole block
  as *unknown*, and Google's documented default for `ipv4_enabled` is a public IP.
  `declared.Unwritten` is the question this needs -- but the switch sits at
  `settings.ip_configuration.ipv4_enabled`, three levels down, and `Stated`
  recorded only top-level arguments. Measured on a real plan, an instance writing
  no `ip_configuration` and one writing `ipv4_enabled` from an unresolvable value
  produced the identical `[database_version name settings]`, so the default and
  the gap were indistinguishable. `Stated` records nested arguments by their path
  now; the configuration walker already built those paths for the references it
  finds, so only the recording had stopped at the top.
- **Azure's allow list is not CIDR.** A firewall rule is `start_ip_address` and
  `end_ip_address`, both Required. `0.0.0.0` to `255.255.255.255` is the whole
  internet, and the well-known `0.0.0.0`–`0.0.0.0` rule means "Azure services"
  rather than one host. `declared.SetReach` is already interval arithmetic
  internally, so a range maps onto it without a second implementation.
- **`port` is usually not in the plan, and "never" was wrong.** `Optional` and
  `Computed` on `aws_db_instance` and `aws_rds_cluster`, and `Computed` only --
  not settable at all -- on `aws_rds_cluster_instance`. It comes back unknown on
  a create *when nobody writes it*, even with `engine` written, so a design that
  needs the port has to get it from somewhere else. This section originally said
  the attribute is never in the plan and that the conclusion held for all three;
  an independent review disproved the first half. An author who writes `port`
  states it, the plan carries it, and the mapper reads it in preference to the
  engine table -- a stated fact outranks a documented default, and the earlier
  reading would have ignored a Postgres instance deliberately moved to 5433. The
  conclusion survives only where the attribute cannot be written, which is
  `aws_rds_cluster_instance`.
- **Azure cannot be planned offline**, as in milestone 08: the provider acquires
  an AAD token before it finishes building. Its fixtures come from the
  authoritative schema and say so.
- **For Aurora the two halves live on two different resources.** Measured against
  the schema: `aws_rds_cluster_instance` has `publicly_accessible` and **no**
  `vpc_security_group_ids`; `aws_rds_cluster` has `vpc_security_group_ids` and
  **no** `publicly_accessible`. So the endpoint switch is on the instance and the
  allow list is on the cluster, and reaching one from the other takes two hops --
  instance to cluster by `cluster_identifier`, cluster to security group by
  `vpc_security_group_ids`. A subject's `related` carries one hop, so the mapper
  needs `scope`, which `Map` already receives. This was not in the design and is
  the kind of thing only a real plan says.
- **`vpc_security_group_ids` is Optional and Computed, so it is unknown even when
  unwritten.** The configuration is what separates "the author named no group",
  where AWS assigns the default VPC security group that is not in the plan, from
  "the author named one the plan cannot resolve". `declared.Unwritten` answers it,
  and both answers are the same verdict for different reasons -- which is exactly
  the distinction milestone 08 learned to keep.

## Product decisions taken before implementation

- **The rule asserts that the change makes a database reachable from any
  address**, which requires the public endpoint *and* an allow covering every
  address. Neither alone is reported as a finding. Where one is known and the
  other is not in the plan, the answer is `UNKNOWN` with the missing half named —
  which, for AWS, is the common case, because a security group is usually
  elsewhere.
- **The contract declares an exposure, not ports.** A `database` family entry
  takes `exposure` with the same three values object storage uses, because the
  question is binary: reachable from the internet, or not. Ports belong to the
  `network` family, where the author is describing a service they chose to
  publish; nobody publishes a database port on purpose and then wants to name it.
  Intent Contract becomes `1.2`; `1.1` and `1.0` keep loading. The bump is a
  statement about what a reader of the contract may expect and **gates nothing**:
  validation is version-independent, so a `1.0` document declaring a `database`
  entry is accepted. That is deliberate — the same reading that accepts
  `public_ports` in a `1.0` contract, recorded in `INTENT-CONTRACT.md` — but it
  is worth saying beside a sentence that reads as though the minor versions
  differed in capability.
- **Severity is `HIGH`, not `CRITICAL`.** Public object storage is `CRITICAL`
  because it exposes the data itself to anyone; a reachable database still
  demands credentials, so it is one layer of several — the same reading network
  exposure already uses. Severity communicates impact and may not depend on the
  contract.
- **The port comes from the engine, through a closed table.** `engine` is in the
  plan and `port` is not, so the mapper maps the documented default port for the
  engines it can name — the same argument this build already accepted for IANA
  protocol numbers in `declared.ProtocolNumber`, and refused for anything
  outside a closed set. An engine this build cannot name makes the port
  undetermined, and an undetermined port means any public ingress is reported as
  possibly reaching it, with the approximation recorded. Over-reporting is the
  safe direction; silently requiring a port match would hide a finding whenever
  the table is incomplete.
- **A database is a subject; its firewall rules and security groups are
  controls.** The correlation goes through references, by instance, using
  `declared.Target` — not by comparing attribute values, which are unknown until
  apply.

## Open question this milestone must answer, not assume

**What a shared security group means.** A security group open to `0.0.0.0/0` on
443 attached to a publicly accessible Postgres instance reaches the endpoint only
if 443 is the database's port. With the engine table above the answer is usually
no, and the finding is correctly absent. The decision to confirm against a real
deployment is whether that silence is right when the engine is one the table does
not name — the design says report and record the approximation, and that is the
choice most likely to be wrong in practice.

## Scope

- AWS: `aws_db_instance`, `aws_rds_cluster`, `aws_rds_cluster_instance`, joined
  to `aws_security_group` through `vpc_security_group_ids`.
- Azure: `azurerm_mssql_server`, `azurerm_postgresql_flexible_server`, joined to
  `azurerm_mssql_firewall_rule` and
  `azurerm_postgresql_flexible_server_firewall_rule`.
- GCP: `google_sql_database_instance`, whose allow list is inside it.
- One universal rule in `internal/policy`, naming no cloud and no attribute.
- `model.DatabaseCapabilities`, carrying the two facts separately so a reader is
  told which half is missing.

## Acceptance criteria

1. An equivalent publicly-reachable database in all three clouds produces one
   finding with the same rule identifier, severity and disposition, and
   cloud-specific evidence.
2. An equivalent private database in all three clouds produces none.
3. A public endpoint with no allow covering every address produces no finding,
   and an allow covering every address with no public endpoint produces none.
4. A plan holding one half of the pair and not the other produces `UNKNOWN`, and
   the missing control names which half.
5. An AWS database joined to a security group milestone 08 reports as open to any
   address is reported through that same resolution, with **no change to the
   network mapper or to `NetworkExposure`**. This is the composition criterion and
   the reason the milestone exists.
6. A GCP instance that writes no `ip_configuration` takes the provider's
   documented default, and one that writes it from an unresolvable value is
   `UNKNOWN` — both proven against real `terraform plan` output committed as a
   fixture, with a guard test pinning the shape.
7. An Azure firewall rule spanning `0.0.0.0`–`255.255.255.255` is every address,
   a rule spanning one host is not, and the pair is decided by the same
   arithmetic `declared.SetReach` already uses.
8. An Aurora cluster whose instances are not in the plan settles nothing, and
   says so.
9. The declared exposure changes the disposition and not the finding.
10. Object-storage and network verdicts are unchanged: every committed fixture
    produces the bundle it produced before this milestone, proven by comparing
    binaries built at both ends.

## Limitations as built

Written after the implementation, from what the tests and fixtures measure rather
than from what the design intended.

- **The port is read from the engine where the plan does not state it.** The table
  is closed and documented, and an engine outside it leaves the port undetermined.
  An undetermined port makes any public ingress count as possibly reaching the
  database, which over-reports, and the approximation is recorded beside the
  verdict. In the other direction, a database that reads as unreachable *because*
  of an engine-derived port carries a non-required unknown saying so.
- **The port reaches no decision on Azure or GCP.** It is consulted only when
  resolving a gate, which walks `GatedBy` -- so on a cloud where the mapper
  answers the admission from inside the subject, the port is reported and nothing
  compares it. Both clouds disclose that the port is undetermined where it is;
  neither claims the verdict rests on it.
- **Closure is never provable on Azure.** The firewall rules are separate
  resources, so a set that looks closed may be missing one declared elsewhere.
  The same asymmetry milestone 08 has, for the same reason.
- **One Azure fixture's shape is unverified.** `sql-switch-absent` encodes the
  endpoint switch stated in neither half of the change. The attribute is Optional
  and not Computed, and the analogous AWS attribute was measured stating a
  determined `false` when unwritten -- so a real plan may always state it and this
  shape may not occur. If so, the fixture defends a path nothing reaches and the
  `UNKNOWN` over-reports. Measuring it needs a tenant.
- **`declared.Targets` cannot tell a conditional inside a list from a list
  literal.** Both record the same way in the configuration, so both branches are
  returned. A gate can only open the question, never close it, so the
  over-reporting is safe -- but the set is not exact and the AWS mapper bounds it
  rather than presenting it as exact.
- **A cluster whose instances are not in the plan settles nothing**, and says so.
  An Aurora cluster is reachable through its instances, and the endpoint switch is
  on the instance.
- **Criterion 5 held, with one qualification.** No file of the network family
  changed. `internal/policy/storage.go` changed by one line, when `referencesOf`
  was made generic across families; an earlier commit on this branch claimed
  storage was untouched and that claim was wrong.
- **`model.NormalizedResource.Removed` is set only by the database mappers.** The
  storage and network families answer the question from their controls and have
  never needed it. Setting it there would change files this milestone promised not
  to touch, for no behaviour.

## Out of scope

Database users, grants and password policy. Encryption at rest and in transit —
a different question about the same resource, and one the contract does not yet
describe. Reachability through a bastion, a VPN, a peering or a private endpoint.
Whether a database that is reachable is also authenticated weakly. Managed
caches, search clusters and data warehouses: `aws_elasticache_*`,
`aws_redshift_cluster` and `aws_docdb_cluster` have the same shape and are left
until the shape is proven on the three above.

## Prerequisites

Milestones 03, 04 and 08. This milestone adds no new machinery of its own: it
uses `declared.Unwritten` for the GCP default, `declared.Target` for the
correlation, `declared.SetReach` for the address arithmetic, and milestone 08's
security-group resolution unchanged. If it needs any of them changed, that is a
finding about the architecture and is worth more than the family.
