# Using InfraProof from a coding agent

InfraProof speaks the Model Context Protocol over standard input and output, so
an agent can verify a plan without being given a shell.

The server offers two tools and nothing else. It reads two files, applies
nothing, contacts no cloud, runs no command, and reaches no network.

## Starting it

```sh
infraproof mcp --root /path/to/your/project
```

`--root` is required and may be repeated. There is no default: a server told
nowhere to read from would otherwise be told everywhere.

The server opens every file itself, through the directory it was given, so a
symbolic link out of a root is refused — including one installed while the file
is being opened. A path naming a parent directory is refused rather than
cleaned, because cleaning it away would silently read a different file.

## Configuring Claude Code

Add it to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "infraproof": {
      "command": "infraproof",
      "args": ["mcp", "--root", "."],
      "env": {}
    }
  }
}
```

`--root .` allows the project directory and nothing above it. Give a narrower
root if your plans live in one place: the root is the only thing standing
between a mistaken path and the rest of your disk.

No credentials are needed and none are read. If your environment holds cloud
credentials, this server does not look at them.

## The tools

### `analyze_change`

| Argument | Required | What it is |
| --- | --- | --- |
| `intent_path` | yes | a JSON intent contract, inside a root |
| `plan_path` | yes | a Terraform or OpenTofu plan JSON file, inside a root |

Returns the Evidence Bundle: a decision, the findings with the plan data each
rests on, and the facts that could not be determined. It is the same bundle
`infraproof check` writes for the same files — the two go through one
verification, so they cannot drift apart.

A decision is one of `PASS`, `WARN`, `BLOCK` or `UNKNOWN`. `UNKNOWN` is not a
pass: it means the plan did not say enough to conclude, and the unknowns list
says what was missing.

### `explain_finding`

| Argument | Required | What it is |
| --- | --- | --- |
| `intent_path` | yes | as above |
| `plan_path` | yes | as above |
| `rule_id` | yes | the `rule_id` of a finding, such as `STORAGE_PUBLIC` |

Returns that finding with the plan data it rests on and its remediation.

The verification runs again rather than being remembered, so the answer
describes the plan as it is now. If you change the plan and ask again, you get
the new answer — which is the point, and why there is nothing to invalidate.

A rule that reported nothing is an answer rather than an error: the response
says so and lists the rules that did report.

## Making a plan to verify

The server does not run Terraform, and will not. Produce the plan yourself:

```sh
terraform plan -out=tfplan.binary
terraform show -json tfplan.binary > tfplan.json
```

OpenTofu works the same way with `tofu`.

## What it will refuse

- A path outside every root, or one that reaches outside through a link. The
  refusal is the same whether or not the file exists, so it cannot be used to
  ask what is on your disk.
- A file larger than 64 MB, refused rather than truncated: half a plan parses
  into a different change.
- Anything that is not a regular file.
- A verification that takes longer than thirty seconds. You are told it was
  abandoned rather than left waiting. A plan near the 64 MB bound needs longer
  than that, so the two limits do not meet: see the residual risks.
- A path naming a parent directory, such as `../plan.json`. Give the path as it
  is, not as a route to it.
- A YAML contract. This build reads JSON, and says so rather than failing as a
  puzzle.

A refused tool call returns a result marked as an error with a sentence saying
what happened, not a protocol error — the model should see it and act on it.

## What it will not do

It does not write files, run commands, open sockets, load plugins, or read
anything outside the roots. Those are not policies; the packages it is built
from import nothing capable of them, and a test asserts it.

## Limits worth knowing

- One request at a time, answered in the order they arrive.
- The server holds no state between calls.
- A hard link inside a root reaches its target, which the path check cannot
  see. See `docs/THREAT-MODEL-MCP.md`.
