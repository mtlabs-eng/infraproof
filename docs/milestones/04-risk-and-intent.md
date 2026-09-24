# Milestone 04: Risk and intent matching

## Objective

Load the structured Intent Contract and evaluate destructive actions, cloud mismatch, environment mismatch where evidence is explicit, and private-storage intent.

## Scope

- JSON Intent Contract loader; YAML deferred, see `docs/INTENT-CONTRACT.md`
- schema and semantic validation
- destructive-change rule
- allowed-cloud rule
- explicit environment-evidence rule
- integration with `STORAGE_PUBLIC`
- aggregate decision logic
- `infraproof check` command
- source admissibility, added during review; see below

## Source admissibility

This was not in the milestone as planned. It is recorded here rather than left
to be inferred from the code, because `docs/PRODUCT.md` describes the behaviour
and a product document should not be the place a scope change first appears.

Independent review of this milestone found that a data source decided a verdict:
an Azure container set to `blob` access, beside a `data.azurerm_storage_account`
reporting that its account forbids anonymous access, reported that the plan
proves prevention. A read describes state as it already is, which is not what a
change does, so it can prove neither exposure nor its prevention — and a plan
that reads the account gating a container is the ordinary way of putting a
container in an account that already exists.

The rule that follows: what a data source says is never evidence about another
resource, in either direction. A verdict reached by choosing among candidates
one of which was a read is not reached at all, and the report names what was
withheld.

Four review rounds were spent on it, each on the mechanism rather than the
rule. The alternative was measured before this was settled: refusing to
conclude about any subject correlated with a read costs two `BLOCK` verdicts on
plans that provably set `acl = "public-read"`, which is absence read as
permission at the level of a decision. That is the cost this scope buys out,
and it is why the rule stays in this milestone rather than waiting for its own.

Carried forward rather than solved here: admissibility is decided per source
and per capability, and a predicate about what may contribute to a verdict has
no general home in the model. A second such predicate — an unrecognized action,
a forbidden cloud — would need the same treatment written again.

## Safety semantics

- A destructive action forbidden by intent is `BLOCK`.
- A plan affecting a disallowed cloud is `BLOCK`.
- A provable environment mismatch is `BLOCK`.
- Weak environment hints are reported without claiming a mismatch.
- Private exposure plus unknown public-access evidence is `UNKNOWN`.
- What a data source reports is never evidence about another resource. A
  verdict that rested on choosing among candidates one of which was a read is
  `UNKNOWN`, and the withheld source is named.
- Operational errors remain distinct from verification decisions.

## Acceptance criteria

- The documented CLI flow works entirely offline.
- JSON output conforms to Evidence Bundle Version 1.
- Markdown represents the same decision and findings.
- Exit statuses match the contract.
- Each rule has positive, negative, unknown, and malformed-boundary tests where applicable.
- No natural-language model or cloud API is used.
