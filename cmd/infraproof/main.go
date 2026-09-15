// Command infraproof is the InfraProof command-line entry point.
//
// This build implements the Evidence Bundle contract only. It can report its
// version and usage; it cannot yet read a plan or an intent contract, so no
// verification command is registered. It is the only place in the program that
// terminates the process.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

// version identifies the build. It stays fixed until the CLI has behavior worth
// versioning independently of the Evidence Bundle contract.
const version = "0.1.0"

const usage = `InfraProof verifies Terraform and OpenTofu changes against declared intent.

Usage:
  infraproof --version
  infraproof --help

Verification is not available in this build: plan and intent parsing are not
implemented yet, so no check command is registered.

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
	if len(args) != 1 {
		return usageError(stderr, "expected exactly one argument")
	}

	switch args[0] {
	case "--help", "-h":
		fmt.Fprint(stdout, usage)
		return evidence.ExitPass
	case "--version":
		fmt.Fprintf(stdout, "infraproof %s (evidence bundle schema %s)\n", version, evidence.SchemaVersion)
		return evidence.ExitPass
	default:
		return usageError(stderr, fmt.Sprintf("unrecognized argument %q", args[0]))
	}
}

// usageError reports incorrect usage on stderr and returns the invalid-input
// exit code. Usage failure is an operational error, never a verification
// decision.
func usageError(stderr io.Writer, reason string) int {
	fmt.Fprintf(stderr, "infraproof: %s\n\n%s", reason, usage)
	return evidence.ExitInvalidInput
}
