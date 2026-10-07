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
- `port` is never in the plan: Optional and Computed on an instance and a
  cluster, Computed only on a cluster instance.
- The provider lower-cases `engine`, so `POSTGRES` arrives as `postgres`.

| fixture | what it asks |
| --- | --- |
| `real-databases` | every shape of the conjunction in one plan, and the Aurora pair |
| `real-aurora-defaults` | the switch written true, written false, and not written at all |
| `real-aurora-interpolated` | the switch written from a value the plan cannot resolve, which is the only shape where its unknown is a gap |
| `rds-cluster-elsewhere` | an Aurora instance whose cluster, and so whose allow list, is managed outside this plan |
| `rds-cluster-without-instances` | a cluster with no instance to answer for it |
| `rds-switch-stated-nowhere` | the sanitized shape: the switch in neither half of the change |
