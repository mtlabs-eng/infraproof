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

## What appears on the pull request

One comment, replaced on each push rather than repeated:

```markdown
<!-- infraproof:6627bf87e11348bd -->

### InfraProof: BLOCK

The requested private storage change enables public access.

| | Rule | Resource | Claim |
| --- | --- | --- | --- |
| CRITICAL | `STORAGE_PUBLIC` | `aws_s3_bucket.assets` | Object storage permits public access. |

Plan `000000000000`, verified offline against `infra/intent.json`.
```

The first line is a marker naming the plan and the contract. The workflow reads
it to decide whether to edit the comment it left last time or write a new one,
so a pull request carries one comment per plan rather than one per push. Two
different plans get two comments; the same plan verified twice gets one.

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

## Other platforms

The rendering is platform-neutral: `--format review` writes Markdown with a
marker, and any system that can run a binary and post a comment can use it. Only
the workflow file is GitHub-specific. What a GitLab or Azure DevOps equivalent
needs is the same three steps — produce a plan, run the check, post the output —
and this repository does not yet ship one.
