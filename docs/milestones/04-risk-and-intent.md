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

How it is decided went through six mechanisms in six review rounds. Four of
them inferred the role a source plays from its resource type, which fails in
both directions: two types can answer one question — ownership controls decide
whether an ACL applies at all — and one type answers for one subject and not
another, because an account-wide block governs the buckets in its own account
and no others. The mapper is now asked directly, through an optional `Roles`
interface, and a mapper that declines to answer has every source it may not use
treated as contesting.

The fifth mechanism compared a withheld source against the questions some
admissible resource *could* have answered. That is what was available to the
mapper rather than what the answer rested on, and it refused plans it had
settled: a bucket blocking every route is proved private by its own control,
and a read of the account baseline beside it answers a question the proof never
consulted. The comparison is against what the verdict **cited**.

A withheld source answering a question nothing cited is still named, unless the
verdict proved prevention. A proof from a control the change itself sets is not
weakened by what exists alongside it, so there is no open question left for the
read to bear on; a grant is another matter, because what else is in force is
exactly what a reader will ask about.

Carried forward rather than solved here:

- Admissibility is decided per source and per capability, and a predicate about
  what may contribute to a verdict has no general home in the model. A second
  such predicate — an unrecognized action, a forbidden cloud — would need the
  same treatment written again.
- Normalization is quadratic in subjects times scope-governed changes, because
  the mapper is handed the scope and scans it per subject. Measured at two
  thousand of each it is 0.86 seconds, against 307 seconds before this
  milestone's last commits, and the report is bounded by a stated source limit
  — but the growth is unchanged, and the tests bound a size rather than a rate.
- Contesting is decided against the questions the verdict cited. A verdict that
  rests on the absence of a control cites nothing for that question, so a
  withheld source can never contest it. Today that only ever fires in the
  direction of reporting more rather than less, because no shipped mapper
  reaches `Known(false)` from an absence — and a mapper that did would need this
  looked at again.
- That `Known(false)` is dominating — that no withheld source can rival a proof
  of prevention — is a per-mapper invariant no interface states and nothing
  checks. It holds for all three shipped mappers by inspection of the three
  places each reaches it.
- AWS provenance does not cite the account-wide public access block, even where
  that block is what decided a route is open. Nothing tests which control a
  verdict cites, in either direction.
- Which name a mapper gives a question is unobservable wherever a subject's
  candidates are homogeneous, which is every Azure subject: a container's
  candidates are accounts and an account's are containers. Renaming both
  consistently changes nothing, so the tests pin that distinct questions carry
  distinct names and not which names they are.
- A report escapes what would open Markdown structure and what a terminal acts
  on. It does not strip bidirectional or zero-width characters, which change
  what a reader sees without changing what the bytes say. Stripping them is a
  judgement about legitimate text in scripts this build has no opinion about.
- `evidence.Validate` reports violations in canonical order, so an index names
  the record a reader will count to. It does not check that a bundle it is
  given is in that order, so the ordering is a property of what this build
  emits rather than one it verifies on input.

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
