// Command infraproof is the InfraProof command-line entry point.
//
// The check command compares a plan with a declared intent contract and reports
// an Evidence Bundle. The inspect command reports what the parser understood and
// decides nothing. The mcp command serves the same verification to a coding
// agent over the Model Context Protocol.
//
// This is the only place in the program that terminates the process.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

// version identifies the build. It stays fixed until the CLI has behavior worth
// versioning independently of the Evidence Bundle contract.
const version = "0.3.0"

const usage = `InfraProof verifies Terraform and OpenTofu changes against declared intent.

Usage:
  infraproof check --intent <path> --plan <path> [--format json|markdown|review]
  infraproof inspect --plan <path>
  infraproof mcp --root <dir> [--root <dir> ...]
  infraproof --version
  infraproof --help

check compares a Terraform or OpenTofu plan with a declared intent contract and
reports an Evidence Bundle. It reads only the two files it is given, reaches no
network, and never applies anything. The intent contract must be JSON; YAML is
not supported in this build.

inspect parses a plan and reports what was understood — addresses, actions, and
which fields are unknown or redacted. It is a development aid, it reaches no
verdict, and it never prints a value the plan marked sensitive.

mcp serves the same verification to a coding agent over the Model Context
Protocol on standard input and output. It reads only files inside the roots it
is given and has no default root.

Exit codes:
  0   PASS
  2   WARN
  3   BLOCK
  4   UNKNOWN
  10  invalid input or usage
  11  internal failure
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the command and returns its exit code without terminating, so
// the exit behavior is directly testable. Diagnostics go to stderr; stdout
// carries only requested output.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "expected a command or a flag")
	}

	switch args[0] {
	case "--help", "-h":
		if len(args) != 1 {
			return usageError(stderr, "--help takes no arguments")
		}
		fmt.Fprint(stdout, usage)
		return evidence.ExitPass
	case "--version":
		if len(args) != 1 {
			return usageError(stderr, "--version takes no arguments")
		}
		fmt.Fprintf(stdout, "infraproof %s (evidence bundle schema %s)\n", version, evidence.SchemaVersion)
		return evidence.ExitPass
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "mcp":
		return runMCP(args[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unrecognized command or flag %q", args[0]))
	}
}

// usageError reports incorrect usage on stderr and returns the invalid-input
// exit code. Usage failure is an operational error, never a verification
// decision.
func usageError(stderr io.Writer, reason string) int {
	fmt.Fprintf(stderr, "infraproof: %s\n\n%s", reason, usage)
	return evidence.ExitInvalidInput
}
