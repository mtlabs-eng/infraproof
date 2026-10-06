# Milestone 08: network exposure

## Objective

Detect provable ingress from the public internet across AWS, Azure and GCP
through one universal rule, as milestone 03 did for object storage — and find
out whether the architecture's central bet survives a family where the three
clouds disagree about more than vocabulary.

## Why this is 08 and not 07

It was written as 07 and moved. Asked what would make the tool useful to them,
the person who has to read its output said the findings name addresses and they
write files: `aws_s3_bucket_acl.assets["prod"]` is a true thing to say and not
where they go to fix it. Covering a second resource family makes the tool answer
more questions; naming the line makes it answer the one it already answers
usefully. Coverage is worth less than being actionable.

## Why this family

Today anything that is not object storage is `UNKNOWN`. That is the correct
answer and it is also the ceiling: a security group open to `0.0.0.0/0` on every
port is reported as a resource no mapper interpreted, which is honest and
useless.

Ingress asks the same question public storage asks — reachable by whom? — and
the three clouds answer it with different machinery. Storage was the easy case
for the normalization bet. This is the one that tests it.

## What makes this harder than storage

In storage each control says one thing and the mapper combines them. Here two of
the three clouds have **priority and deny rules**, so no single rule decides
anything:

| | Ordering | Deny rules | Applied to |
| --- | --- | --- | --- |
| AWS security group | none; rules are a union | none, allow-only | instances by attachment |
| Azure NSG | `priority`, lowest wins | yes, `access = "Deny"` | subnets and interfaces by association |
| GCP firewall | `priority`, lowest wins | yes, `deny` blocks | instances by network and target tags |

A permissive rule overridden by a higher-priority deny permits nothing. A deny
at a lower priority than the allow changes nothing. The verdict is about the
ordered set, not about any rule in it — and a plan that contains some of the set
cannot settle it.

AWS network ACLs have the same shape as Azure and GCP and are deliberately out
of scope below.

## Product decisions taken before implementation

- **The rule asserts that the change permits ingress from any address**, not
  that a resource becomes reachable. Reachability needs the attachment, which is
  usually in another resource, another module, or already exists; asserting it
  would make most real plans `UNKNOWN`. This is the choice milestone 03 made for
  storage, for the same reason.
- **The contract declares which ports may be public.** `0.0.0.0/0` on 443 is a
  web server and on 22 is an incident. A fixed list of sensitive ports in this
  build would be this build deciding someone else's security policy, and would
  age badly. A contract that declares nothing makes any public ingress a `WARN`,
  because silence is not permission.

Both are recorded here rather than left to be inferred from the code.

## Scope

- `aws_security_group` with inline `ingress`, and `aws_vpc_security_group_ingress_rule`.
- `azurerm_network_security_group` with inline `security_rule`, and
  `azurerm_network_security_rule`.
- `google_compute_firewall`.
- IPv4 and IPv6 as one question: `0.0.0.0/0` and `::/0` are both "any address",
  and a rule that opens one and not the other is still open.
- Port ranges, and the protocol spellings each provider uses for "all".
- The intent contract gains a network family: which ports may be reachable from
  any address.
- Priority and deny, modelled as the ordered set they are.

## Explicitly out of scope

- Network ACLs, Cloud Armor, WAF rules, and any other layer. One layer answered
  honestly is worth more than three answered partly.
- Egress. It is a different question with different consequences and deserves
  its own decision rather than being folded in because the schema is nearby.
- Reachability through a load balancer, gateway, or peering.
- Whether the thing behind an open port is dangerous. This build reports what
  the plan states, and what is listening is not in the plan.

## Safety semantics

- A rule opening a port to any address, with nothing in the plan denying it at a
  lower priority, is `Known(true)`.
- A rule denied by a lower-priority rule in the plan permits nothing, and is not
  a finding.
- A rule set the plan does not contain in full is `UNKNOWN`. An NSG whose rules
  are declared in a module this plan does not include cannot be settled, and
  saying so is the answer.
- A port range, protocol, or address the parser could not read is `UNKNOWN`, not
  absent.
- The attachment is reported as a non-required unknown when the plan does not
  state it, because it bounds what the finding means without preventing it.

## Acceptance criteria

- Equivalent public-ingress scenarios in all three clouds produce one finding
  with the same rule identifier, severity and disposition, and cloud-specific
  evidence.
- Equivalent closed scenarios produce none.
- A rule overridden by a lower-priority deny produces none, in both clouds that
  have priorities, and a test proves the ordering is read rather than assumed.
- A rule set the plan does not contain in full produces `UNKNOWN`.
- The contract's declared ports change the disposition and not the finding.
- The universal rule imports no provider-specific package.
- Adding a mapper does not require changing the universal rule.
- Every fact records the provider attribute it came from.
- Object-storage verdicts are unchanged: every committed fixture produces the
  same bundle it produced before this milestone.

## Limitations of this milestone, as built

- **The claim is about the change, not about reachability.** Nothing here reads
  an attachment: a security group's instances, an NSG's subnets, a firewall's
  target tags beyond comparing them with a deny's. The attachment is reported as
  a non-required unknown on every finding.
- **A grant is provable from part of a rule set; closure is not.** A security
  group or an NSG whose rules are separate resources is `UNKNOWN` unless one of
  the rules in the plan grants. Only an inline set can be shown closed, because
  the provider refuses to mix the two forms and an inline set is therefore the
  whole set.
- **One approximation, and it is upward.** A deny narrower by protocol than the
  allow it meets cannot be subtracted: a range carries one protocol and "every
  protocol except TCP" is not one. The wider range is reported and a missing
  control says so. Dropping the grant would hide that the other protocols are
  still open.
- **GCP target scopes are compared as sets, not resolved.** A deny whose
  `target_tags` do not cover the allow's is not applied, and the narrowing is
  reported. Whether any instance actually carries a tag is not in the firewall.
- **A protocol with no ports cannot be permitted by a port list.** ICMP, ESP, AH,
  a protocol number, a spelling this build does not know: each is reported and
  each needs a human, because a port declaration can neither permit nor forbid it
  and this build will not decide on its own that ping from the internet is a
  violation.
- **Source ports and destination addresses are not read.** A source port is the
  client's and says nothing; a destination address narrows what is reachable
  rather than whether ingress is permitted.
- **Azure's and GCP's platform defaults are relied on, not modelled.** Both deny
  inbound traffic no rule allows, which is what makes a readable set with no
  grant a proven closure. The default rules themselves are not in any plan.
- **Fixtures are hand-authored from provider documentation.** There is no offline
  authority for a provider schema, so milestone 07's agreement harness has no
  equivalent here. What was verified, and against which document, is recorded in
  a README beside each cloud's fixtures.
