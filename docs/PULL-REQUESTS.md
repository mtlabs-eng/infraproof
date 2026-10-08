# Verifying a change on a pull request

InfraProof produces a verdict; your repository's own automation publishes it.
This build reaches no network and holds no credential, so the comment is posted
by the workflow with the token GitHub already gives the run.

That division is the point rather than an inconvenience. A verifier holding a
token to write on a pull request is a verifier that can be made to write
something else, and the reason this build has no credentials is the same reason
it has no network.

## Adopting it

Copy [`docs/examples/infraproof-workflow.yml`](examples/infraproof-workflow.yml) to
`.github/workflows/infraproof.yml` in your repository and set the two paths at the top:

```yaml
env:
  WORKING_DIRECTORY: infra
  INTENT_CONTRACT: infra/intent.json
```

The workflow needs `contents: read` to see the change and `pull-requests: write`
to leave one comment. It asks for nothing else, and a test in this repository
fails if that block ever widens.

It needs no secret. The step that runs the verifier is given no credential at
all, and a test asserts that.

Pin the version. The template installs `@v0.4.0`; a verifier that changes under
you is a verdict you cannot reproduce, which is what `@latest` would be. Nothing
here can check that the version you name resolves, so check it once when you
change it.

## What appears on the pull request

One comment, replaced on each push rather than repeated — the workflow finds the
one it left last time by the marker prefix on the first line:

```markdown
<!-- infraproof:6627bf87e11348bd -->

### InfraProof: BLOCK

The requested private storage change enables public access.

| | Rule | Resource | Claim |
| --- | --- | --- | --- |
| CRITICAL | `STORAGE_PUBLIC` | `aws_s3_bucket.assets` | Object storage permits public access. |

Plan `000000000000`, verified offline against `infra/intent.json`.
```

The first line is a marker. Its prefix, `<!-- infraproof:`, is what the workflow
matches on to find its own comment; the rest is a fingerprint of the plan and
the contract, for a person or a tool comparing two verdicts.

The workflow matches the prefix rather than the whole marker, because
`terraform show -json` writes a timestamp into the plan and the fingerprint is
taken over the exact bytes — so the same change verified twice produces two
different fingerprints. Matching the prefix gives one comment per pull request,
which is what a reviewer wants; matching the fingerprint would give one per
run, which is what this is written to avoid.

The comment is short on purpose: a reviewer has a diff open and thirty seconds.
Everything it leaves out is in the Evidence Bundle, which the workflow attaches
as an artifact. A verdict with more findings than fit says how many are not
shown rather than trimming the list quietly.

## What decides the check

The exit code, unchanged from the command line:

| Exit | Meaning | The check |
| --- | --- | --- |
| 0 | `PASS` | passes |
| 2 | `WARN` — a human needs to decide | passes |
| 3 | `BLOCK` — deterministic evidence of a violation | fails |
| 4 | `UNKNOWN` — evidence required for a safe conclusion was unavailable | fails |
| 10 | invalid input or usage | fails |
| 11 | internal failure | fails |

`UNKNOWN` failing the check is deliberate. It is not a pass: the plan did not
say enough to conclude, and the comment names what was missing.

## The plan

The workflow runs `terraform plan` itself, because InfraProof does not and will
not. That step needs whatever credentials your providers need; InfraProof never
sees them, and the step that runs it is given no token at all — a test asserts
that too.

If you already produce a plan JSON somewhere in your pipeline, drop the
Terraform steps and point `--plan` at it.

## One workflow per repository

The workflow finds its own comment by the marker prefix, which is the same for
every InfraProof run. Two workflows in one repository — one per environment, say
— will therefore overwrite each other's comment and cancel each other through
the shared concurrency group. Run one, or give each its own marker and
concurrency group by editing both.

## Other platforms

The rendering is platform-neutral: `--format review` writes Markdown with a
marker, and any system that can run a binary and post a comment can use it. Only
the workflow file is GitHub-specific. What a GitLab or Azure DevOps equivalent
needs is the same three steps — produce a plan, run the check, post the output —
and this repository does not yet ship one.
