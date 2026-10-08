# Provenance

Every fixture in this directory is **hand-authored** from the current
`aws` provider schema, not produced by Terraform.

That is a real limitation. Milestone 02 showed that hand-written fixtures can
misrepresent a format, and milestone 03 showed it again: three shapes absent
from these files were only found by generating real plans, and one of them hid a
bucket reported as private while being public.

Real plans covering the shapes that matter — repeated resources, nested blocks,
meta-argument references — live in `internal/providers/testdata`. The `aws` provider does plan offline, so these
fixtures could be replaced by generated ones; the real plans already committed
cover the shapes that were getting it wrong.

## Database fixtures

Real `terraform show -json` output throughout, which is what caught the one trap
this cloud has. Terraform 1.14.0, `hashicorp/aws` v6, `terraform plan` only --
never applied, no cloud contacted, `skip_*` flags and placeholder strings, with
the two placeholder credential arguments and every password-shaped value removed
afterwards.

What was verified against the authoritative schema or a real plan:

- `publicly_accessible` is Optional and **not** Computed on `aws_db_instance`: an
  unwritten one is emitted as a determined `false`, which is the provider's
  default and the safe answer. On `aws_rds_cluster_instance` it is Optional **and
  Computed** and comes back unknown, so the Aurora path needs the configuration
  to tell a default from a gap. The milestone first recorded this the other way
  round and a review disproved it.
- The schema splits the conjunction across two resources: an Aurora instance has
  the endpoint switch and no `vpc_security_group_ids`; its cluster has the groups
  and no switch. Reaching one from the other is two hops.
- `vpc_security_group_ids` is Optional and Computed, so it is unknown even when
  unwritten -- the configuration separates "the author named no group", where AWS
  applies the VPC's default group, from "named one the plan does not contain".
- `port` is Optional and Computed on an instance and a cluster, so a create emits
  it unknown when nobody writes it and carries it when somebody does -- which
  `rds-port-written` is for -- and Computed only on a cluster instance, where it
  cannot be written at all. This line used to say the attribute is never in the
  plan, beside a fixture that exists because it is.
- The provider lower-cases `engine`, so `POSTGRES` arrives as `postgres`.

| fixture | what it asks |
| --- | --- |
| `real-databases` | every shape of the conjunction in one plan, and the Aurora pair |
| `real-aurora-defaults` | the switch written true, written false, and not written at all |
| `real-aurora-interpolated` | the switch written from a value the plan cannot resolve, which is the only shape where its unknown is a gap |
| `rds-cluster-elsewhere` | an Aurora instance whose cluster, and so whose allow list, is managed outside this plan |
| `rds-cluster-without-instances` | a cluster with no instance to answer for it |
| `rds-switch-stated-nowhere` | the sanitized shape: the switch in neither half of the change |
| `rds-destroyed` | a destroy-only change, where `after` is JSON null and the switch is therefore absent |
| `rds-replaced` | a replacement, where `after` is a full object because the database is there afterwards |
| `rds-destroyed` is not the only change that states nothing: | |
| `rds-forgotten` | a `removed` block with `lifecycle { destroy = false }`, which Terraform emits as `actions: ["forget"]` with `after` null -- the database stays up, stays publicly accessible, and leaves Terraform's management |
| `rds-delete-contradicted` | a plan claiming to delete while still stating a public endpoint, which is not a shape Terraform emits and is not one this build resolves in the permissive direction |
| `rds-port-out-of-range` | `port = 70000`, which the provider accepts and no port is |
| `rds-group-keyed-expression` | a group named `aws_security_group.each[each.key].id`, which records `each.key` and so draws on something the plan does not describe |
| `rds-group-splat` | a group named `values(aws_security_group.each)[*].id`, which records a repeated type with no key and nothing opaque -- the only shape that reaches the undecidable arm |
| `rds-aurora-keyed-expression` | an Aurora instance naming its cluster through `each.key`, beside one whose cluster is genuinely in another module |

`rds-destroyed` and `rds-replaced` are genuine `terraform show -json`: Terraform
1.14.0, hashicorp/aws v6, planned with `-refresh=false` against a hand-written
state file so no cloud was contacted. Provider credentials were placeholders and
the arguments were deleted from the plan afterwards; the database password, also
a placeholder, is redacted in the committed files.

`rds-forgotten` is genuine `terraform show -json`, planned the same way as the two
above. `rds-delete-contradicted` is derived from `real-databases` by setting one
database's actions to `["delete"]` while leaving its `after` intact: Terraform
does not emit that, and the fixture exists precisely because a plan is input and a
plan whose action list contradicts its own state must not be read as the half that
reports less.

`rds-port-out-of-range`, `rds-group-keyed-expression`, `rds-group-splat` and
`rds-aurora-keyed-expression` are genuine `terraform show -json`, planned the same
way as the rest: Terraform 1.14.0, hashicorp/aws v6, `terraform plan` only,
placeholder credentials, and the provider's credential arguments and the database
password removed from the committed files. Each exists because a review found a
decision nothing exercised, and each was generated rather than written so the
shape it turns on is the provider's rather than this project's.
