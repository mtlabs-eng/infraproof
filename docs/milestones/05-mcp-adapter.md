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

## Acceptance criteria

- MCP results are semantically identical to CLI results for the same files.
- The adapter imports the core; the core does not import MCP.
- Path traversal and symlink escape tests pass.
- Invalid input returns structured safe errors.
- Claude Code project configuration and usage instructions are documented.
