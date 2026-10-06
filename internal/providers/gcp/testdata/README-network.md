# Network fixtures

Hand-authored from the provider's own documentation, like the storage fixtures
beside them: there is no offline authority for a provider schema, and no provider
was downloaded to produce these.

What was verified against `hashicorp/terraform-provider-google` rather than
assumed:

- Exactly one of `allow` or `deny` is required on a `google_compute_firewall`, so
  a firewall is an allow-rule or a deny-rule and never both.
- `priority` is 0–65535, **1000 when unstated**, lower is higher precedence, and
  **a deny takes precedence over an allow of equal priority**. That tie-break is
  this cloud's own: Azure forbids the tie and AWS has no denies.
- `direction` defaults to `INGRESS` and is Computed, so a plan may not state it.
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
