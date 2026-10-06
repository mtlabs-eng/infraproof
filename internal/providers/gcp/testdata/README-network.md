# Network fixtures

`real-firewalls.json` and `real-undetermined.json` are genuine
`terraform show -json` output: Terraform 1.14.0, `hashicorp/google` v6,
`terraform plan` only. Never applied, no cloud contacted — a placeholder
credentials filename and a fake project. Each scenario in them sits on its own
network so the firewalls do not interact, because a firewall's rule set is scoped
to one network. They are this milestone's authority test; the fixtures cut from
them keep their shapes.

The rest are hand-authored, which is how this mapper came to produce no verdict on
real input. `direction` is Optional **and Computed**, so a create plan emits it as
unknown for every firewall that does not spell it out — and all 25 hand-written
fixtures wrote `direction = "INGRESS"`. Ten of eleven firewalls in a real plan
reported UNKNOWN, including SSH open to `0.0.0.0/0`. The note below that
`direction` "is Computed, so a plan may not state it" was treated as describing an
exception; it describes the rule.

What was verified against the authoritative provider schema
(`terraform providers schema -json`) or against a real plan, rather than assumed:

- Exactly one of `allow` or `deny` is required on a `google_compute_firewall`, so
  a firewall is an allow-rule or a deny-rule and never both.
- `priority` is 0–65535, **1000 when unstated**, lower is higher precedence, and
  **a deny takes precedence over an allow of equal priority**. That tie-break is
  this cloud's own: Azure forbids the tie and AWS has no denies.
- `direction` is Optional **and Computed** and defaults to `INGRESS`. A real create
  plan omits the key from `after` and marks it unknown in `after_unknown` unless
  the configuration writes it, so the unknown is the default rather than a gap.
  An interpolated `direction` is unknown and written, which is the only shape in
  which it is a gap — `real-undetermined.json` carries both.
- `priority` is emitted as `1000` when unstated rather than absent, `disabled`
  emits `null`, and an unset `ports` list emits `[]`. None of `null`, an absent
  key, or an absent `ports` field is a shape a real plan uses, which two
  hand-written fixtures claimed.
- The protocol is passed through verbatim: `"sctp"` and `"6"` are not normalized.
  `allow`/`deny` accept `tcp udp icmp esp ah sctp ipip all` or an IANA number, and
  note that **`sctp` carries ports**, so reporting an unnameable protocol as a
  port-less grant would be wrong in kind.
- `disabled` means the network behaves as if the rule did not exist.
- **Since provider version 4, an ingress firewall must state one of
  `source_ranges`, `source_tags` or `source_service_accounts`.** The old
  behaviour — empty meaning `0.0.0.0/0` — is gone, and assuming it would invent a
  grant on every tag-scoped rule in every plan.
- An `allow` or `deny` block with no `ports` is every port of that protocol.

Each fixture is one question:

| fixture | what it asks |
| --- | --- |
| `fw-public` | open to the world on 22 |
| `fw-closed` | the same shape, reachable only from inside |
| `fw-ipv6` | `::/0` alone |
| `fw-every-protocol` | `all`, every protocol on every port |
| `fw-no-ports` | a protocol with no ports listed, which is every port of it |
| `fw-ports-omitted` | the same with the key omitted rather than written null |
| `fw-icmp` | a protocol with no ports |
| `fw-icmp-with-ports` | ports on a protocol that has none, which cannot decide anything |
| `fw-port-range` | a range |
| `fw-disabled` | a rule the network behaves as if it did not have |
| `fw-egress` | egress, which says nothing about who can reach in |
| `fw-source-tags` | a source narrowed to tagged instances |
| `fw-source-omitted` | the same with the key omitted |
| `fw-denied-lower` | a deny in another firewall, below this one |
| `fw-denied-equal` | the same deny at an equal priority, where this cloud gives it precedence |
| `fw-deny-above` | the same deny above, where it changes nothing |
| `fw-denied-unknown-network` | both networks unknown until apply, so only the reference says which |
| `fw-deny-other-network` | a deny that cannot reach this network |
| `fw-deny-other-network-literal` | the same with no references, where only the names separate them |
| `fw-deny-covers-targets` | a deny on every instance against an allow on a few |
| `fw-deny-narrow-targets` | a deny on a few instances against an allow on all, which cannot be shown to cover it |
| `fw-deny-partial-ports` | a deny covering part of a range |
| `fw-deny-disjoint` | a deny that does not overlap at all |
| `fw-unknown-direction` | a direction the plan has not determined |
| `fw-unknown-source` | a source the plan has not determined |
