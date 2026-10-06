# Network fixtures

Two kinds of fixture live here.

`real-*.json` and the fixtures cut from them are genuine `terraform show -json`
output: Terraform 1.14.0, `hashicorp/aws` v6, `terraform plan` only. Never
applied, no cloud contacted — `skip_credentials_validation`,
`skip_metadata_api_check`, `skip_region_validation`, `skip_requesting_account_id`
and placeholder strings. One edit was made after generation: the two placeholder
credential arguments were deleted from the `provider_config` block. No resource
data was touched.

The rest are hand-authored. That was all of them until three independent reviews
found the consequence: `ingress` is Optional **and Computed**, so a group writing
no inline rules has the attribute emitted as unknown and not as `[]`, which is
what every hand-written fixture here said. The provider documentation claims the
blocks are "not computed attributes", which is exactly why reading the docs
instead of the schema failed. A real plan is the authority; where one exists, it
is committed.

What was verified against the authoritative provider schema
(`terraform providers schema -json`) or against a real plan, rather than assumed:

- `aws_security_group`'s inline `ingress` block takes `cidr_blocks`,
  `description`, `from_port`, `ipv6_cidr_blocks`, `prefix_list_ids`, `protocol`,
  `security_groups`, `self` and `to_port`. A block naming no source blocks
  traffic.
- `aws_vpc_security_group_ingress_rule` uses different names for the same
  questions: `cidr_ipv4`, `cidr_ipv6`, `prefix_list_id`,
  `referenced_security_group_id`, `ip_protocol`, `from_port`, `to_port`. Reading
  the inline names here finds nothing, which is the permissive direction.
- `ip_protocol = "-1"` is every protocol and every port, and `from_port` and
  `to_port` must not be set with it.
- `ingress` is a set of object, Optional **and Computed**. An unset inline set is
  emitted as unknown in `after_unknown` with the key absent from `after`; the same
  is true of `dynamic "ingress" { for_each = [] }`.
- `protocol` on an inline block is normalized by the provider (`6`→`tcp`,
  `17`→`udp`, `1`→`icmp`, `58`→`icmpv6`, `ALL`→`-1`), and `sctp`, `132` and `50`
  are passed through unchanged. `ip_protocol` on a standalone rule is **not**
  normalized at all: a real plan carries `"6"` verbatim.
- Combining standalone rule resources with inline rules on one group is **not**
  refused. A plan with both on one group reports four resources to add, with no
  error and no warning; the documentation only advises against it. The earlier
  claim here — that the refusal is what makes an inline set complete — was false,
  and the mapper now bounds its closure with a non-required unknown instead.
- A rule's sources are `cidr_blocks`, `ipv6_cidr_blocks`, `prefix_list_ids`,
  `security_groups` and `self`. The middle one is a list held outside the plan and
  may contain `0.0.0.0/0`; the last two name groups rather than addresses.
- A partially-unknown address list collapses: `["10.0.0.0/8", <unknown>]` emits
  `cidr_blocks: true`, not an element-wise `[false, true]`. `sg-unreadable-element`
  encodes a shape the format does not use; the mapper's element loop is kept as a
  defence rather than as a claim about real output.

Each fixture is one question:

| fixture | what it asks |
| --- | --- |
| `sg-public-inline` | a rule set the plan holds in full, open to the world on 22 |
| `sg-closed-inline` | the same shape, reachable only from inside |
| `sg-public-ipv6` | `::/0` alone, because a rule that opens one family and not the other is open |
| `sg-every-protocol` | `-1`, whose port fields are written as zero and mean every port |
| `sg-icmp` | a protocol with no ports, which a port declaration cannot describe |
| `sg-unreadable-port` | a port the plan has not determined |
| `sg-unreadable-address` | an address the plan has not determined, which could be `0.0.0.0/0` |
| `sg-unreadable-element` | one entry of a readable address list that the plan has not determined |
| `sg-public-rule` | a separate rule resource that grants, where the plan holds part of the set |
| `sg-partial-rule` | a separate rule resource that does not grant, where the rest of the set is elsewhere |
| `sg-no-rules` | a group with no rules in the plan at all |
| `sg-rule-every-protocol` | `-1` on a separate rule, with the ports absent by the provider's own rule |
