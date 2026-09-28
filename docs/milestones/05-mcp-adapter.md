# Milestone 05: MCP adapter

## Objective

Expose the stable local verifier to coding agents through MCP without duplicating product logic or broadening permissions.

## Prerequisites

- Milestones 01 through 04 complete and reviewed
- stable core API and Evidence Bundle
- threat review of file-path and output handling

## Initial tools

- `analyze_change`: accepts paths to a local intent and plan within an allowed project root and returns the Evidence Bundle.
- `explain_finding`: returns deterministic evidence and documented remediation for a finding already produced by the core.

`verify_remediation` is deferred until the interaction model and plan freshness contract are specified.

## Security requirements

- No arbitrary command execution
- No `terraform` execution by the MCP server
- No access outside explicitly allowed roots
- No network access
- No cloud credentials
- No raw sensitive plan values in tool output
- Bounded input size and execution time
- Schema-validated tool inputs and outputs

## Decisions taken while building this

- `explain_finding` holds no state. It re-runs the verification from the two
  files rather than answering from a remembered bundle, so there is no freshness
  contract to specify — the answer describes the plan as it is now. The
  milestone deferred that contract for `verify_remediation`; this avoids needing
  one at all here.
- The protocol is written to the standard library rather than taken from an SDK,
  so the module still declares no dependencies and the assertion that this build
  imports no MCP code into its core stays machine-checkable.
- `--root` is required and repeatable, with no default. A server told nowhere to
  read from would otherwise be told everywhere.
- Execution time is bounded by abandoning a verification that outlasts its
  deadline and telling the caller. Nothing is cancelled: the work is a
  computation over values already in memory. What that leaves is recorded in
  `docs/THREAT-MODEL-MCP.md`.

## Acceptance criteria

- MCP results are semantically identical to CLI results for the same files.
- The adapter imports the core; the core does not import MCP.
- Path traversal and symlink escape tests pass.
- Invalid input returns structured safe errors.
- Claude Code project configuration and usage instructions are documented.
