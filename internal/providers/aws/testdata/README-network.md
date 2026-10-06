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
| `sg-prefix-list-inline` | a rule whose only source is a managed prefix list, which may contain `0.0.0.0/0` |
| `sg-prefix-list-rule` | the same question on a separate rule resource, where the field is singular |
| `sg-group-sourced` | sources naming no address at all: another group, and the group itself |
| `sg-split-source` | a source written as two halves of IPv4, which together are every address |
| `sg-backwards-ports` | a range whose ends are the wrong way round, which the provider plans without complaint (real output) |
| `sg-unreadable-protocol` | a protocol spelling this build does not know, which could be any protocol |
| `real-groups` | real `terraform plan` output: 13 groups, 6 standalone rules and a VPC -- the authority the rest are checked against |

Two fixtures here are not producible by Terraform. `sg-malformed-port` holds
`"from_port": "twenty-two"`, a JSON string where the schema says a number, and
`sg-unreadable-element` holds a per-element unknown the format collapses into a
whole-attribute one. Both are kept because the guards they exercise are the right
ones to have, and both are labelled so nobody reads them as evidence about real
output.

A third was listed here as unproducible and is not: the provider plans
`from_port = 443, to_port = 22` with no error and no warning, so
`sg-backwards-ports` is real output and the mapper's answer -- undetermined,
because it cannot know which end was meant -- is about a shape authors can
actually write.

Besides `real-groups`, these are cut from real plan output and keep its shapes:
`sg-prefix-list-inline`, `sg-prefix-list-rule`, `sg-group-sourced`,
`sg-split-source`, `sg-explicitly-empty`, `sg-dynamic-block` and
`sg-backwards-ports`.
