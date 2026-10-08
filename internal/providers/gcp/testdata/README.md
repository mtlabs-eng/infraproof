# Provenance

Every fixture in this directory is **hand-authored** from the current
`gcp` provider schema, not produced by Terraform.

That is a real limitation. Milestone 02 showed that hand-written fixtures can
misrepresent a format, and milestone 03 showed it again: three shapes absent
from these files were only found by generating real plans, and one of them hid a
bucket reported as private while being public.

Real plans covering the shapes that matter — repeated resources, nested blocks,
meta-argument references — live in `internal/providers/testdata`. The `google` provider plans offline with no
credentials at all, so these fixtures could be replaced by generated ones.

## Database fixtures

Real `terraform show -json` output, which is how the trap this cloud has was
found before any code was written. Terraform 1.14.0, `hashicorp/google` v6,
`terraform plan` only -- never applied, no cloud contacted, a placeholder
credentials filename and a fake project.

The trap, and the reason this is the cloud where it lives: an instance that
writes no `ip_configuration` emits the **whole block** as unknown, and Google's
documented default for `ipv4_enabled` is a public IP. That is milestone 08's
worst defect one level deeper -- and deeper than the machinery reached, because
`Stated` recorded only top-level arguments and so an instance writing no block and
one writing an unresolvable `ipv4_enabled` produced the identical
`[database_version name settings]`. It records nested arguments by their path now.

The same silence governs both halves of the block, and it has to: if nobody wrote
`ip_configuration`, nobody wrote `authorized_networks` either, and the default for
those is none. So the idiomatic Cloud SQL instance has a public IP that nothing is
authorized to reach -- not reachable, which is correct and is what most
deployments look like before a network is added.

Every family Cloud SQL writes -- `POSTGRES_*`, `MYSQL_*`, `SQLSERVER_*` -- is one
the port table names, so there is no unnameable version to make a fixture of. The
refusal is covered where the table lives.

| fixture | what it asks |
| --- | --- |
| `real-databases` | every shape of the conjunction, including the two unknowns that need opposite answers |
| `real-databases-unreadable` | a version and an authorized address each written from something the plan cannot resolve |
| `sql-cloned` | an instance created from a clone, which writes no `settings` and inherits the source's authorized networks |
| `sql-destroyed` | a destroy-only change, where `after` is JSON null so `ipv4_enabled` is absent for a reason that is not a gap |
| `sql-replaced` | a replacement, whose `after` is complete because the instance exists when the change is done |
| `sql-dynamic-unresolvable` | a `dynamic "ip_configuration"` whose `for_each` nobody can resolve, which the plan records identically to an instance writing no `ip_configuration` at all |
| `sql-unreadable-and-unknown-networks` | the two ways an allow list cannot be read: an address the provider accepts and this build cannot parse, and a `dynamic "authorized_networks"` leaving the whole set unknown while the block stays readable |

A fixture encoding the `ip_configuration` block as unknown **and** written was
removed rather than kept as a guard. Measured against the provider, a
`dynamic "ip_configuration"` records nothing in the configuration and resolves to
a readable list, and the attribute form is refused outright -- so that shape is
not one Terraform emits, and the identifier it covered is reached by the clone
instead.

`sql-destroyed` and `sql-replaced` are genuine `terraform show -json`: Terraform
1.14.0, hashicorp/google v6, planned with `-refresh=false` against a hand-written
state file so no cloud was contacted. The provider's `credentials` argument was a
placeholder and was deleted from the plan afterwards.

`sql-dynamic-unresolvable` is genuine `terraform show -json`. It is the fixture
that disproved this cloud's earlier reading of an absent `ip_configuration`.
Measured against a real plan of an instance writing `settings` with no
`ip_configuration`, the two are identical in `after`, in `after_unknown` and in
`configuration` -- the plan records nothing about a `dynamic` block, not even its
`for_each` reference -- and one of them admits every address. So this build no
longer proves an empty allow list from the block's absence.

`sql-unreadable-and-unknown-networks` is genuine `terraform show -json`. Both
shapes in it were measured rather than imagined: the provider accepts
`value = "0.0.0./0"` and the plan carries it verbatim as a readable string, and a
`dynamic "authorized_networks"` over an unresolvable `for_each` emits
`after_unknown…authorized_networks: true` while `ip_configuration` itself stays
readable -- which is a different shape from the block being unknown.
