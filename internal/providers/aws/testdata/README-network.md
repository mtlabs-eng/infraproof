# Network fixtures

Hand-authored from the provider's own documentation, like the storage fixtures
beside them and for the same reason: there is no offline authority for a provider
schema, and no provider was downloaded to produce these.

What was verified, against
`hashicorp/terraform-provider-aws` documentation rather than assumed:

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
- Combining standalone rule resources with inline rules on one group is a
  conflict the provider refuses. That is what makes an inline set a complete one.

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
