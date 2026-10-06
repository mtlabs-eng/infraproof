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

Rewritten after three independent reviews, two of which generated real
`terraform plan` output and found several of the original statements false. What
changed is recorded in the commits; what follows is what the build actually does.

- **The claim is about the change, not about reachability.** Nothing here resolves
  an attachment: a security group's instances, an NSG's subnets, a firewall's
  network and target tags beyond comparing them with a deny's. Each cloud reports
  it as a non-required unknown on every finding — `AWS_SECURITY_GROUP_ATTACHMENT_UNKNOWN`,
  `AZURE_NSG_ASSOCIATION_UNKNOWN`, `GCP_FIREWALL_SCOPE_UNKNOWN`. The first version
  of this list claimed that and GCP reported nothing of the sort.
- **A grant is provable from part of a rule set; closure is not, and closure is
  never fully provable.** A security group or an NSG whose rules are separate
  resources is `UNKNOWN` unless a rule in the plan grants. An inline set can be
  shown closed, bounded by a non-required unknown: the earlier claim that "the
  provider refuses to mix the two forms" is false, and a review disproved it by
  planning inline `ingress` and a standalone rule on one group — four resources to
  add, no error and no warning. The documentation advises against mixing; nothing
  prevents it.
- **An Optional and Computed attribute that nobody wrote takes the provider's
  documented default.** `direction`, `ingress` and `security_rule` are the three,
  and all are emitted as unknown when the author leaves them out — the common case
  rather than an edge one. `priority` and `disabled` are Optional and *not*
  Computed, so an unknown value there is always author-written and no default
  applies; the code applied the mechanism to them too and its comments claimed
  they were Computed, which the authoritative schema disproves.
  - The question is whether the configuration **recorded this resource's
    arguments**, not whether it declares the resource. Terraform emits an entry
    with no `expressions` object — a body that is only a `dynamic` block does it,
    and a sanitizer stripping expressions does it to everything — and reading that
    as an author who wrote nothing produced `PASS`, exit 0, on a firewall opening
    SSH to `0.0.0.0/0`.
  - A `dynamic` block is absent from a resource's recorded arguments altogether,
    so an argument's **absence** never proves nothing writes it. Its **presence**
    does, because block and attribute syntax cannot both name one attribute, and
    that is the direction closure is decided in.
  - Without a configuration — a sanitized plan — nothing is assumed either way.
- **Correlation between two resources is by instance, not by address.** A
  reference carries its target with count and `for_each` keys stripped, and the
  keys are the only thing separating one instance from its sibling. Comparing the
  stripped addresses read a deny on `google_compute_network.vpc["b"]` as applying
  to a firewall on `vpc["a"]` and proved the grant closed. The question has three
  answers — one instance, no reference, or undecidable — and an undecidable deny
  is skipped and reported rather than allowed to settle anything. A reference
  naming no instance of a repeated target, or an attribute naming two targets, is
  undecidable.
- **A deny is only applied as far as it can be shown to reach.** Its source, its
  destination, its target scope, its protocol, its priority and **its ports** all
  bound it. The last was the one place a deny was applied without being read: a
  protocol with no ports has nothing to subtract, so a deny limited to port 80
  cancelled an ICMP-from-anywhere grant whole, in both ordered clouds.
- **Two approximations, both upward, each with its own identifier.** A deny
  narrower by protocol than the allow it meets cannot be subtracted: a range
  carries one protocol and "every protocol except TCP" is not one. A deny narrower
  by destination, or by target scope, cannot be shown to cover the allow at all.
  In each case the wider answer is reported with a missing control naming the
  reason, and the flag is raised only when something was actually approximated.
- **Address and port sets are arithmetic, not pattern-matching.** What a source
  field admits is the union of its entries, so `0.0.0.0/1, 128.0.0.0/1` is every
  address in IPv4; what a declaration permits is the union of its ranges, so 80
  and 81 declared is 80-81 declared. Both were wrong in the first version and both
  produced a definite answer that was the opposite of the truth.
- **A protocol with no ports cannot be permitted by a port list, and neither can
  every protocol at once.** ICMP, ESP, AH: each needs a human, because a port
  declaration can neither permit nor forbid it. A protocol written as its IANA
  number is read when this model can name it — the four assignments are closed and
  documented, and the providers pass the number through verbatim. Every other
  number and spelling is `UNKNOWN` in all three clouds.
- **A source this build cannot resolve is not a narrow source.** A managed prefix
  list may contain `0.0.0.0/0`, so a rule sourced from one is undetermined. A rule
  naming another security group, an application security group, or itself reaches
  no address and is read as opening nothing.
- **Source ports are not read, and a destination address is read only for a deny.**
  A source port is the client's and says nothing. A destination narrows what is
  reachable rather than whether ingress is permitted, which is sound for an allow
  and inverted for a deny — ignoring it made a deny scoped to one host look like a
  deny covering the subnet.
- **Azure's and GCP's platform defaults are relied on, not modelled.** Both deny
  inbound traffic no rule allows, which is what makes a readable set with no grant
  a proven closure. The default rules themselves are not in any plan.
- **A port range the provider plans is not a port range the API accepts.**
  `from_port = 443, to_port = 22` plans with no error and no warning. This build
  answers UNKNOWN because it cannot know which end was meant; the milestone first
  claimed the provider refused the shape, which a review disproved by planning it.
- **The fixtures now include real plans, for two clouds of three.** AWS and GCP
  carry genuine `terraform show -json` output committed as `real-*.json`, which is
  this milestone's authority test and what caught the Optional-and-Computed
  defects. Azure's are hand-authored from the authoritative provider schema:
  azurerm acquires an AAD token before building the provider, so it cannot be
  planned offline, and standing up something for it to authenticate against is not
  work this project will do. Azure's leaf spellings are therefore inferred from the
  schema and from the AWS set behaviour that was observed, not measured.
- **Out of scope, unchanged.** Network ACLs, Cloud Armor, WAF. Egress.
  Reachability through a load balancer, gateway or peering. Whether what is
  listening behind an open port is dangerous.
