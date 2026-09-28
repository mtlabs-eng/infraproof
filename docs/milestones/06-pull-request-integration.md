# Milestone 06: pull-request integration

## Objective

Put the verdict where infrastructure changes are actually reviewed, without this
build gaining a single new capability.

## The rule this milestone had to resolve first

`CLAUDE.md` lists two things that cannot both be followed as written:

- "Never upload source code, state, plans, or evidence to an external service."
- "MCP, pull-request integrations, live cloud context, dashboards, and
  deployment are later milestones."

Posting a finding as a comment on a pull request *is* transmitting evidence to
an external service. The rule governs, and the milestone is shaped around it:

**InfraProof never speaks to a network.** It produces an artifact — the Evidence
Bundle, and a comment-shaped rendering of it — and the repository's own CI
publishes that artifact, with the repository's own credentials and the
platform's own tooling. Nothing in this module gains an HTTP client, a token, or
a hostname, and the test asserting that no package imports `net` stays true.

That is not a workaround. A verifier that holds a token to write on a pull
request is a verifier that can be made to write something else, and the reason
this build has no credentials is the same reason it has no network.

## Scope

- A rendering shaped for review rather than for a terminal: what changed, what
  it violates, and what is not known, short enough to read in a diff view.
- A stable marker in that rendering so a workflow can update one comment across
  pushes rather than appending a new one each time.
- A GitHub Actions definition that runs the command and hands the result to the
  platform's own tooling, with the posting expressed in the workflow rather than
  in this module.
- Documentation of the workflow a repository adds, including how the plan JSON
  is produced, which this build does not do.

## Explicitly out of scope

- Any network call from this module.
- Any credential, token, or secret read by this module.
- Running `terraform` or `tofu`, in this module or in the action definition.
  The workflow produces the plan; the action verifies it.
- Any platform other than GitHub Actions in this milestone. The rendering is
  platform-neutral; only the workflow definition is not.
- Inline annotations on changed lines. A finding is about a resource, and a plan
  has no line numbers; mapping one to the other needs the configuration and is
  its own milestone.

## Security requirements

- No network access, asserted as it is for the MCP adapter: a rule about imports
  over every package involved.
- No credentials, tokens, or environment secrets read.
- No raw sensitive plan value in the rendering, as everywhere else.
- The rendering is bounded: a plan with a thousand findings must not produce a
  comment no platform will accept, and what is omitted must be stated.
- The action definition grants the smallest permission that can post a comment,
  and states why it needs it.

## Acceptance criteria

- The review rendering carries the same decision, findings and unknowns as the
  JSON bundle for the same inputs, and a test asserts it rather than a reader
  comparing them.
- The rendering is stable: the same bundle produces the same bytes.
- The marker identifies one comment per subject and is documented.
- A repository can adopt it by copying one workflow file, and that file is in
  this repository and is tested for shape. It is a template rather than a live
  workflow: this repository has no Terraform to verify, and a template that
  fails on every pull request teaches a reader the wrong thing.

  **Met with a footnote, and the footnote is the repository being private.**
  The module does not resolve from the Go proxy, so no one can install the tool
  by naming it. The template checks the repository out and builds it, which
  needs a token that can read it — so adopting this is copying one file *and*
  adding one secret.

  That is the whole of the shortfall. It is not cover for a step that does not
  run: the build failed twice for reasons that had nothing to do with
  publication, and both are closed and tested. Publishing the module collapses
  the block to one `go install` line, removes the secret, and meets the
  criterion as written.
- Exit codes continue to gate the check: a `BLOCK` fails the job, an `UNKNOWN`
  fails it, and a `WARN` does not.
- No package involved imports a network, a process, or a credential.
