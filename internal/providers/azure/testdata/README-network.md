# Network fixtures

Hand-authored, and the only cloud here where that is still true.

AWS and GCP carry real `terraform plan` output beside their hand-written
fixtures. Azure cannot: the provider acquires an AAD token before it finishes
building, so `terraform plan` fails at `clientCredentialsToken: AADSTS700038`
with no cloud to reach. Standing up something for it to authenticate against is
not work this project will do.

So these are shaped from the **authoritative provider schema**
(`terraform providers schema -json`, which settles every Required/Optional/Computed
question) rather than from documentation prose. The leaf spellings inside
`after`/`after_unknown` — `""` for an unset optional string, `[]` for an unset
set, per-element unknowns inside the `security_rule` set — are inferred from SDKv2
semantics and from the AWS set behaviour that was observed on a real plan. They
are not measured, and that is this cloud's weakest link.

What was verified against the schema or the provider's documentation, rather than
assumed:

- A `security_rule` block takes `name`, `description`, `protocol` (`Tcp`, `Udp`,
  `Icmp`, `Esp`, `Ah` or `*`), `source_port_range`/`source_port_ranges`,
  `destination_port_range`/`destination_port_ranges`,
  `source_address_prefix`/`source_address_prefixes`, the destination equivalents,
  the application security group lists, `access` (`Allow`/`Deny`), `priority`
  (100–4096, **lower number is higher precedence**) and `direction`
  (`Inbound`/`Outbound`).
- `security_rule` is a set of object, Optional **and Computed**, with 17 keys. An
  unset inline set is therefore emitted as unknown rather than as `[]`, which is
  what the fixtures here said until a review pointed at the schema. A group plus
  separate `azurerm_network_security_rule` resources — the most common Azure shape
  — reported UNKNOWN on the real shape where the fixture said KNOWN(true).
- A rule has a **destination** as well as a source:
  `destination_address_prefix`/`destination_address_prefixes`. It narrows what is
  reachable rather than whether ingress is permitted, which is sound for an allow
  and inverted for a deny — a deny scoped to one host is not a deny covering the
  subnet.
- Of the three service tags, only `Internet` is every public address.
  `VirtualNetwork` and `AzureLoadBalancer` are not reachable from the internet and
  are read as narrow. `AzureCloud` is Azure's own public IP space and is
  deliberately left in the unreadable case.
- `source_address_prefix` accepts a CIDR, an IP, `*`, or a service tag such as
  `Internet`, `VirtualNetwork` or `AzureLoadBalancer`. **`source_address_prefixes`
  may not carry tags.** That asymmetry is the provider's, not a simplification
  made here.
- Only one of each range/ranges pair may be set per rule.
- Inline `security_rule` blocks and `azurerm_network_security_rule` resources
  conflict. That is what makes an inline set a complete one.
- A priority must be unique within a set.

Each fixture is one question:

| fixture | what it asks |
| --- | --- |
| `nsg-public-inline` | a set the plan holds in full, open to the world on 22 |
| `nsg-closed-inline` | the same shape, reachable only from inside |
| `nsg-internet-tag` | the `Internet` service tag, which only the singular field may carry |
| `nsg-prefix-list` | `0.0.0.0/0` in the plural field, which may not carry a tag |
| `nsg-ipv6` | `::/0` alone |
| `nsg-every-protocol` | `*` on `*`, every protocol on every port |
| `nsg-icmp` | a protocol with no ports |
| `nsg-esp` | a real protocol this build does not interpret, which is not ICMP |
| `nsg-port-list` | `destination_port_ranges`, the plural form |
| `nsg-denied-below` | a deny at a **lower** number, which takes precedence |
| `nsg-deny-above` | the same deny at a **higher** number, which changes nothing |
| `nsg-equal-priority` | two rules at one priority, which Azure refuses; the grant stands |
| `nsg-deny-partial-ports` | a deny covering part of a range, leaving the rest exactly |
| `nsg-deny-disjoint` | a deny that does not overlap, leaving the range as it was |
| `nsg-deny-partial-protocol` | a deny narrower by protocol, which is not expressible as a remainder |
| `nsg-icmp-denied` | a deny reaching a protocol with no ports, which reaches all of it |
| `nsg-two-allows` | two allows, so the reported order is the set's own |
| `nsg-outbound-only` | outbound, which says nothing about who can reach in |
| `nsg-separate-open` | a separate rule resource that grants |
| `nsg-separate-closed` | a separate rule resource that does not, where the rest is elsewhere |
| `nsg-no-rules` | a group with no rules in the plan at all |
| `nsg-unreadable-priority` | a priority the plan has not determined, so nothing can be ordered |
