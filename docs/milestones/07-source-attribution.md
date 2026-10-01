# Milestone 07: source attribution

## Objective

Say where. A finding names `aws_s3_bucket_acl.assets["prod"]`; the person
reading it wrote `main.tf` and has to find the line. Close that gap without
guessing.

## The fact this milestone is shaped by

**Plan JSON carries no source positions.** Not on a resource change, not in the
configuration block, not anywhere — verified across every committed plan
including real Terraform 1.14 output. What it carries is the identity of each
declaration (`type` and `name`, per module) and the `source` string of each
module call.

So a location cannot be read out of the plan. It has to be found in the
configuration, which means this build reads `.tf` files for the first time.

## What that costs, and the rule it answers to

A located line is a claim, and the plan cannot support it. Nothing ties a plan
to the files that produced it: there is no source digest, and the files may have
changed since. A line number that is merely plausible is worse than none,
because it sends a reader to the wrong code with the tool's authority behind it.

So the rule this milestone is built on:

**A location is reported only when the declaration found at it matches the one
the finding is about.** The scan finds a candidate; the candidate is checked
against the type and name the plan states; a mismatch reports no location rather
than the closest thing. Absence of a location is an answer, and it is the safe
one.

## Product decisions taken before implementation

- **The configuration directory is given, not inferred.** A `--config` flag,
  with no default. Guessing it from the plan's own path would be a guess, and a
  wrong guess produces wrong lines — which is the failure this milestone is
  supposed to remove. Without the flag everything behaves exactly as it does
  today, and no output changes.
- **Locations are additional, never load-bearing.** A finding is what it was; a
  location is a field on it. No decision, disposition or exit code depends on
  whether a line was found, because a verdict that changed when a file moved
  would not be a verdict about the plan.
- **The resource block always; the attribute when it is written there.** A
  finding rests on an attribute — `acl`, `allow_nested_items_to_be_public` — and
  that is the line worth having. When the attribute is set from a variable, a
  local, a module input or a dynamic block, it is not in that block, and the
  answer is the block's line with the attribute reported as not written here.

## Scope

- Locate a resource declaration in a configuration directory by type and name,
  and verify it.
- Locate the attribute a finding's evidence names, within that declaration.
- Follow module calls whose `source` is a local path, recursively, so a finding
  inside `module.storage` lands in `modules/storage/main.tf`.
- Carry the location through the Evidence Bundle, the Markdown report and the
  review rendering, as a version 1.2 addition.
- Confine every file read to the configuration directory, using the guard
  milestone 05 built for exactly this.

## Explicitly out of scope

- **Evaluating HCL.** This locates declarations; it does not resolve
  expressions, interpolations, or values. The plan already answers what a value
  is, and answering it twice is how two answers come to disagree.
- Modules from a registry or a remote source. Their files live under
  `.terraform/modules` behind a manifest, which is a different input with a
  different lifetime. A local-path module is the common case and the honest
  start.
- Line numbers for anything but a resource declaration and its attributes: not
  for provider blocks, variables, outputs, or a module call itself.
- Any claim that the files read are the files the plan was made from. They may
  not be, and nothing here can tell.

## Security requirements

- Every read confined to the given configuration directory, by the same guard
  the MCP adapter uses: resolved through symbolic links, opened rather than
  approved by name, bounded in size and in count.
- No file read outside it, including through a module `source` that climbs out.
- No content from a configuration file in any output. A location is a path and a
  line; the line's text is not carried, because a `.tf` file holds secrets more
  often than a plan does.
- Bounded work: a configuration directory is walked once, and a directory too
  large or too deep is refused rather than walked.

## Acceptance criteria

- A finding about a resource declared in the root module carries the file and
  line of its declaration, and of the attribute the finding rests on when that
  attribute is written there.
- A finding about a resource inside a local-path module carries the file and
  line inside that module's directory.
- A declaration that has moved, been renamed, or been deleted since the plan was
  made produces no location, and a test proves the mismatch is detected rather
  than the nearest block reported.
- Without `--config` nothing is read and nothing is added. For every plan this
  repository ships, a verification against a configuration directory that
  declares nothing produces the same bytes as one with no directory at all, and
  no bundle carries a location.

  Written first as "every committed fixture produces the byte-identical bundle it
  produces today", which independent review showed is false as stated and for a
  reason that has nothing to do with locations: this milestone takes the Evidence
  Bundle to 1.2, so `schema_version` differs in every fixture. The comparison
  above is what a suite can hold, and the review also made the original
  comparison by hand across 65 fixtures and three formats: Markdown and review
  output are byte-identical, and JSON differs on that one line.
- A module `source` pointing outside the configuration directory reads nothing.
- No configuration file content appears in any rendering.
- The locator is exercised against a configuration this repository ships, so the
  scan is tested against real HCL rather than against strings in a test.

## Limitations of this milestone, as built

- **`.tf.json` is not read.** A configuration written in JSON is a different
  grammar, and lexing HCL while claiming to cover both is how a wrong line gets
  reported. A declaration written there has no location.
- **An argument is located only at the top level of its block.** An evidence
  path's first segment is looked for — `tags` of `tags.environment` — and what is
  inside it is not, because finding that out means evaluating the expression that
  produced it.
- **A nested block is located only when it carries no label.** `grant {` is an
  attribute path a plan can name; `dynamic "grant" {` and
  `provisioner "local-exec" {` are not, so no line is offered for them.
- **Only the configuration directory is an error.** A module whose source this
  build cannot resolve, a directory that is not there, a file past the size
  bound, a declaration that does not match: each produces no location and says
  nothing further. The bundle is not told that a scan was refused, so a reader
  who expected a line and sees none cannot tell "not written here" from "not
  read". That is the cost of keeping the addition unable to change a verdict.
- **MCP is unchanged.** `verify_plan` takes a contract and a plan, as before. Its
  guard confines the paths it is handed, and handing it a directory is a wider
  grant than this milestone examined.
- **Reading is bounded at 512 KiB per file and 8 MiB per run.** Past either, the
  whole directory is discarded rather than the one file: a declaration this build
  did not get to see could have been the second match that makes the answer
  ambiguous, so keeping the ones it did see would report a position for something
  it cannot know is unique.
- **A hard link is read.** The guard refuses a symbolic link out of the
  configuration directory, and a hard link is indistinguishable from the file it
  points at — the same residual risk `docs/THREAT-MODEL-MCP.md` records for the
  paths the adapter is given. No content reaches output either way, and a line is
  reported only if the linked file happens to declare what the plan names.
- **A symbolic link to a directory is not followed, even inside the directory.**
  A module whose path goes through one has no locations, and nothing in the
  bundle says why.
- **A directory cannot be enumerated past 1024 entries.** Past that it is refused
  rather than walked, and its declarations have no locations.
