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
| `real-databases-ipv4-unwritten.json` | `ip_configuration` written with an allow list for everyone, `ipv4_enabled` not: the provider's public-IP default decides a finding. Real `terraform plan` output, Terraform 1.14, `hashicorp/google` v6, `-refresh=false`, placeholder credentials (the `credentials` argument removed afterwards). Measured: `ipv4_enabled` is KNOWN `true` in `after`, absent from `after_unknown`, and absent from the configuration, so only the configuration says the provider wrote it. |

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

## Hand-authored method fixtures

Milestone 10 records how each known value was established. Each of these pins one
method decision; `fw-*` rows are in `README-network.md`.

- `public-iam-policy-data.json`: a `google_storage_bucket_iam_policy` whose `policy_data` is a known document granting `allUsers`, so the grant is this build's reading of a document.
- `public-member-and-policy-data.json`: `public-iam-member.json` plus the same policy document on the same bucket, so the member grant outranks the interpreted one.
- `public-iam-member-prevention-written.json`, `public-iam-binding-prevention-written.json` and `public-member-and-policy-data-prevention-written.json`: the three above with `public_access_prevention = "inherited"` written in the bucket's configuration, `after` unchanged. A grant rests on prevention not being enforced, so only these make a member or binding grant stated; the originals are `provider-default`.

## Real plans added by milestone 10's adversarial review

Terraform 1.14.0, `hashicorp/google` 6.50.0, `plan -refresh=false`, placeholder
token removed afterwards; the update plans ran against a hand-written state.

- `real-sql-ip-configuration-from-state.json`: `settings` written with no `ip_configuration`, on an update whose state holds `ipv4_enabled = true` and `0.0.0.0/0`. Both are carried; the plan does not record `ip_configuration`, so both halves are `configuration-unrecorded`.
- `real-sql-dynamic-settings.json`: two instances, `settings` written as a block and as a resolvable `dynamic` block. The dynamic one records nothing about `settings`.
- `real-sql-dynamic-authorized-networks.json`: `ip_configuration` written as a block with `ipv4_enabled = true`, and `authorized_networks` as a `dynamic` block, which the configuration does not record: the switch is stated and the allow list `configuration-unrecorded`.
- `real-sql-ipv4-written.json` and `real-sql-ipv4-unwritten.json`: one instance whose configurations differ only in writing `ipv4_enabled = true`; `after` is identical. The criterion 3 pair.
- `real-bucket-prevention-pair.json`: two buckets with an `allUsers` member each, one writing `public_access_prevention = "inherited"`. Unwritten, the value is unknown in `after` and the grant is `provider-default`.
- `real-bucket-prevention-from-state.json`: the unwritten bucket on an update whose state holds `"inherited"`, which Terraform carries: `prior-state`.

## Real plans added by milestone 10's fourth review

Same tooling: Terraform 1.14.0, `hashicorp/google` 6.50.0, `plan -refresh=false`
against a hand-written state where the change is an update, nothing applied,
the placeholder token removed afterwards.

- `real-ignore-changes.json`: `lifecycle { ignore_changes }` on three resources,
  a plan of "no changes". The bucket writes `public_access_prevention =
  "enforced"` and the state holds `"inherited"` and `labels.environment =
  prod`; the member writes `user:alice@example.com` and the state holds
  `allUsers`; the firewall writes `source_ranges = ["10.0.0.0/8"]` and the state
  holds `0.0.0.0/0`. Every `after` is the state's, and the configuration does not
  record `lifecycle`: each value is `prior-state`.
- `real-firewall-source-ignored.json`: a firewall that writes no `source_ranges`,
  with `ignore_changes = [source_ranges]` and `0.0.0.0/0` in state.
- `real-firewall-priority-ignored.json`: a firewall that writes no `priority`,
  with `ignore_changes = [priority]` and 500 in state -- not the documented 1000.
- `real-bucket-prevention-null-variable.json`: a create writing
  `public_access_prevention = var.public_access_prevention`, the variable
  defaulting to `null`. The plan's `variables` records `null`, and `after`
  carries the argument as unknown exactly as when it is omitted: the provider's
  default.
- `real-policy-grant-beside-private-member.json`: a create of a bucket writing
  `public_access_prevention = "inherited"`, a member naming one user, and a
  `google_storage_bucket_iam_policy` whose `policy_data` grants `allUsers`.
- `real-carried-member-beside-private-policy.json`: the reverse, on an update: a
  member that writes one user with `ignore_changes = [member]` and `allUsers`
  in state, beside a policy document naming one user.
- `real-reference-write-ignored.json`: `real-ignore-changes`'s state and
  lifecycle blocks with each overridden value written by something the plan
  does not evaluate -- `public_access_prevention = var.prevention`
  (`enforced`), `member = var.member` (one user), `source_ranges =
  local.ranges` (`10.0.0.0/8`) -- beside firewall `blocks`, which writes its
  `allow` in constants (tcp 443) with `ignore_changes = [allow]` and tcp 22 in
  state. A plan of "no changes"; every `after` is the state's.
- `real-block-reference-unchanged.json`: no `ignore_changes`. Firewall `fw`
  writes `allow { ports = [var.port] }`, the variable holding the state's `22`;
  firewall `const` writes the same block in constants. A plan of "no changes".
- `real-sql-networks-carried.json`: three Cloud SQL instances whose state
  authorizes `0.0.0.0/0`: `ref` writes the network's `value = var.cidr`
  (`0.0.0.0/0`), `const` writes `"0.0.0.0/0"`, and `ignored` writes
  `"10.0.0.0/8"` with `ignore_changes` on
  `settings[0].ip_configuration[0].authorized_networks`. Each plan keeps the
  state's network.

## Real plans added by milestone 10's fifth review

Terraform 1.14.0 and `hashicorp/google` 6.50.0, `plan -refresh=false` against a
hand-written state, nothing applied; the placeholder access token was stripped
on import.

- `real-labels-partial-ignore.json`: bucket `b` writes
  `labels = { environment = "staging", team = "b" }` with
  `ignore_changes = [labels["environment"]]` against a state holding
  `{ environment = "prod", team = "a" }`: the update moves `team` and keeps the
  state's `environment`. Firewall `fw` writes `allow { protocol = "TCP",
  ports = [22] }` against a state holding `tcp` and `"22"`, a no-op. Firewall
  `fw2` writes `source_ranges = ["0.0.0.0/00"]` against a state holding
  `0.0.0.0/0`; the plan holds both.
- `real-blocks-unwritten-from-state.json`: firewall `fw2` writes
  `allow { protocol = "tcp" }` -- every TCP port -- with
  `ignore_changes = [allow]`, against a state whose `allow` holds
  `ports = ["22"]`; a no-op. Firewall `fw` writes one `allow` (udp/53) under
  `ignore_changes = [allow]` against a state holding a second block (tcp/22).
  Instance `db` writes one authorized network, `10.0.0.0/8`, with
  `ignore_changes` on `settings[0].ip_configuration[0].authorized_networks`
  against a state that also authorizes `0.0.0.0/0`, while `tier` moves.

## Real plans added by milestone 10's sixth review

Terraform 1.14.0 and `hashicorp/google` 6.50.0, `plan -refresh=false` against a
hand-written state, nothing applied; the placeholder access token was stripped
on import. No `lifecycle` block anywhere. `source_ranges` is a legacy-SDK set,
and the provider suppresses removing `0.0.0.0/0` from it: against a state of
exactly `["0.0.0.0/0"]`, one new range is planned beside the old one, so the
update moves the set and keeps the public element nobody wrote.

- `real-source-ranges-union-variable.json`: firewall `a` writes
  `source_ranges = var.a` (`["10.0.0.0/8"]`) and `f` writes `[var.f]`
  (`0.0.0.0/1`), each planned beside the state's `0.0.0.0/0`. `b` writes `[]`
  and `c` writes `null` (a no-op keeping `0.0.0.0/0`). Controls that replace the
  set: `d` writes two ranges, `[var.d, "10.1.0.0/16"]`; `e` holds
  `["0.0.0.0/0", "::/0"]` in state; `g` holds only `10.0.0.0/8`.
- `real-source-ranges-union-variable-element.json`: every firewall but `g`
  writes `[var.x]`, and `g` the constant `["10.0.0.0/08"]`, against
  `0.0.0.0/0` in state. `a` (`10.0.0.0/8`) and `f`
  (`10.0.0.1/8`) are planned beside it; `b`, `c`, `d`, `g` and `i` hold a
  spelling no parser here reads; `e` holds `["0.0.0.0/0", "10.0.0.0/8"]` in
  state and is narrowed to `10.0.0.0/8`; `h` moves `::/0` to `fd00::/8`.
- `real-source-ranges-union-local.json`: the same, with `c` writing
  `[local.c]` and `b` the constant `["10.0.0.0/8"]`, which the plan
  contradicts.

## Skipped-deny fixtures added by the fourth review

Hand-authored, by a script editing only the fields named here, from
`fw-deny-above-direction-omitted`: `web` writes everything at priority 1000, and
`block` denies everything at priority 100 on an update whose `before` equals its
`after`. Each pair makes the deny skip on one ground: `-egress-` (direction),
`-disabled-`, `-source-` (a source narrower than every address) and `-network-`
(a literal network other than `web`'s). In `-carried` the configuration does not
record that ground, or records a constant the state overrides, as
`ignore_changes` leaves it; in `-written` it writes it.
`fw-deny-disabled-written-egress-carried` skips on two grounds, a written
`disabled` and a carried direction.
`fw-deny-disabled-unwritten-create`, added by the fifth review, is
`fw-deny-disabled-written` with `block` a create and `disabled` removed from its
configuration: a new deny holding `true` that nothing records writing.

`fw-deny-network-subject-carried` is `fw-deny-network-written` with `web` an
update whose `before` equals its `after` while its configuration writes another
network. `fw-denied-lower-source-carried` is `fw-denied-lower-direction-omitted`
with the deny's direction written and the deny an update keeping
`0.0.0.0/0` while its configuration writes `10.0.0.0/8`; the deny is applied.
`fw-deny-source-tags-only` is `fw-deny-source-written` with the deny a create
scoped by `source_tags`, its `source_ranges` unwritten and `null`, which is what
a real create plan of such a firewall carries; `-empty` holds `[]` instead.
