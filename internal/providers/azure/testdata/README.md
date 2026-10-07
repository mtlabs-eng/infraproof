# Provenance

Every fixture in this directory is **hand-authored** from the current
`azure` provider schema, not produced by Terraform.

That is a real limitation. Milestone 02 showed that hand-written fixtures can
misrepresent a format, and milestone 03 showed it again: three shapes absent
from these files were only found by generating real plans, and one of them hid a
bucket reported as private while being public.

Real plans covering the shapes that matter — repeated resources, nested blocks,
meta-argument references — live in `internal/providers/testdata`. The `azurerm` provider refuses to plan without
authenticating, so these fixtures cannot be replaced by generated ones without
credentials, which CLAUDE.md forbids this project from handling. Of the three
clouds, this one rests most heavily on the schema being read correctly.

## Database fixtures

Hand-authored from the authoritative provider schema, and this cloud is the only
one here where that is still true: azurerm acquires an AAD token before it
finishes building, so `terraform plan` fails at `building account: could not
acquire access token` before any resource is planned. AWS and GCP carry real plan
output for this family; Azure cannot, and what that costs is below.

Verified against `terraform providers schema -json`:

- `public_network_access_enabled` is `Optional` and **not** `Computed` on both
  `azurerm_mssql_server` and `azurerm_postgresql_flexible_server`, so a real plan
  would state it. **What it states when nobody writes it has not been measured
  here**, and this build applies no default because of that: guessing the
  direction that reads as private would hide a reachable database, and guessing
  the other would invent a finding. An absent switch is undetermined.
- A firewall rule is `start_ip_address` and `end_ip_address`, both `Required`,
  plus `server_id`, also `Required`. There is no prefix anywhere in this grammar.
- `azurerm_mysql_flexible_server` is a different shape -- `public_network_access_enabled`
  is `Computed` only and there is a separate `public_network_access` string -- and
  its rule resource has no `server_id`. It is out of scope for this milestone and
  the shape is why.
- There is no engine attribute: the engine is the resource type, so the port is
  read from the type with certainty rather than inferred from a value. AWS and
  GCP both write an engine and need a table.

| fixture | what it asks |
| --- | --- |
| `sql-reachable` | a public endpoint and a rule admitting every address |
| `sql-azure-services` | `0.0.0.0`-`0.0.0.0`, which is how Azure says "services inside Azure" and is one address |
| `sql-one-office` | a range of eleven addresses |
| `sql-split-halves` | two ranges each narrow and together the whole internet |
| `sql-no-endpoint` | a rule admitting everything in front of no public endpoint |
| `sql-no-rules` | a public endpoint and no rule in the plan, which cannot be shown closed |
| `sql-switch-absent` | the switch stated nowhere, which this build will not default |
| `sql-unreadable-range` | a range this build could not read, which could be the one that opens everything |
| `sql-open-beside-unreadable` | a proven grant beside an unreadable rule: the grant stands |
| `sql-with-resource-group` | a server referencing something that is not a rule, which must not reach its related set |
| `pg-reachable` | the other type in scope, and its own port |
