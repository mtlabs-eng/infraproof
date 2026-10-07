# Measured provider behaviour

Genuine `terraform show -json` output, kept because milestone 08 shipped three
defects that came from reading provider documentation instead of a plan, and
re-deriving these costs a provider download and a planning run.

They are evidence for the milestone that cites them, not test fixtures: nothing
under `internal/` reads this directory. A milestone that needs one as a fixture
copies it into the package's `testdata` and says so there.

Terraform 1.14.0 with `hashicorp/aws` v6 and `hashicorp/google` v6, `plan` only.
Never applied, no cloud contacted — placeholder strings and `skip_*` flags for
AWS, a placeholder credentials filename for GCP. Provider authentication
arguments and every password-shaped field were removed afterwards; no resource
data was otherwise touched.

| file | what it settles |
| --- | --- |
| `09-aws-rds-plan.json` | `publicly_accessible` is emitted known and `false` when unwritten; `port` is unknown on every create; `aws_rds_cluster` carries no switch and `aws_rds_cluster_instance` does |
| `09-aws-rds-reachability-plan.json` | the conjunction's shapes in one plan: a public endpoint behind a group open on the database's port, behind one open only on 443, behind a closed one, with no group written at all, and an Aurora pair whose two halves sit on two resources |
| `09-gcp-cloudsql-reachability-plan.json` | every shape of the conjunction, and the pair that matters: an instance writing no `ip_configuration` against one writing `ipv4_enabled` from something unresolvable |
| `09-gcp-cloudsql-plan.json` | an instance that writes no `ip_configuration` emits the whole block unknown, so the provider's default applies and the configuration is the only thing that says so |
