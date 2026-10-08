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
| `sql-switch-absent` | the switch stated nowhere, which this build will not default (see the caveat below) |
| `sql-unreadable-range` | a range this build could not read, which could be the one that opens everything |
| `sql-open-beside-unreadable` | a proven grant beside an unreadable rule: the grant stands |
| `sql-with-resource-group` | a server referencing something that is not a rule, which must not reach its related set |
| `pg-reachable` | the other type in scope, and its own port |
| `sql-server-destroyed` | a destroy-only change on the server itself, which permits nothing through it |
| `sql-server-replaced` | a replacement of the server, whose reachability is still the verdict |
| `sql-services-plus-rest` | the Azure-services sentinel beside `0.0.0.1`-`255.255.255.255`, which together are every IPv4 address |
| `sql-rule-being-replaced` | a firewall rule being replaced onto the whole internet, which is not a rule being removed |
| `sql-server-repeated` | a server under `count`, so the plan holds a rule that admits every address and that nothing could attach |

`sql-server-destroyed` and `sql-server-replaced` are shaped like the rest of this
cloud's fixtures, but the grammar they turn on is not guessed: `["delete"]` with
`after` null, and `["delete","create"]` with a full `after`, were both measured on
genuine `terraform show -json` output for AWS and GCP, where a plan could be
produced. The actions array is Terraform core rather than provider behaviour.

Two details in them are *not* faithful to real output, and nothing reads either:
`sql-server-destroyed` writes `after_sensitive: {}` where Terraform emits `false`
for a null side, and omits `before_sensitive`, which Terraform always emits. A
review measured both. They are left as they are rather than corrected by hand,
because correcting a hand-authored fixture towards real output one field at a time
is how a fixture comes to look authoritative without being so -- and the only
honest fix for this cloud is a plan, which needs a tenant.

`sql-switch-absent` is the one fixture here whose *shape* is unverified, not just
its values. `public_network_access_enabled` is Optional and not Computed, and on
AWS the analogous attribute was measured emitting a determined `false` when
unwritten -- so this provider may well state it too, and an absent switch may be
a shape no real plan carries. If that turns out to be so, the fixture defends a
path nothing reaches and this build's `UNKNOWN` is over-reporting rather than
hiding anything. Measuring it needs a tenant, which is the one thing this project
will not acquire to answer a question.

`sql-rule-being-replaced` and `sql-server-repeated` are derived from
`sql-reachable` -- a rule's actions set to `["delete","create"]` with a full
`after`, and a server split into two `count` instances. Both turn on Terraform
core rather than provider behaviour: the actions grammar was measured on AWS and
GCP, and a reference naming no instance is the correlator's own shape, pinned by
tests in `internal/providers/declared`.
