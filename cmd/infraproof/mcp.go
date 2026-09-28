package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/mcp"
)

// roots collects a repeatable --root flag.
type roots []string

func (r *roots) String() string { return strings.Join(*r, ", ") }

func (r *roots) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// runMCP serves the verifier over the Model Context Protocol on stdio.
//
// The server reads from stdin and writes to stdout, so nothing else may: a
// diagnostic on stdout would be read by the client as a malformed message. Every
// operational word this command has goes to stderr.
func runMCP(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("mcp", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {}

	var allowed roots
	flags.Var(&allowed, "root", "a directory the server may read from; repeat for more than one")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, mcpUsage)
			return evidence.ExitPass
		}
		return evidence.ExitInvalidInput
	}
	if flags.NArg() > 0 {
		return usageError(stderr, fmt.Sprintf("mcp takes no positional arguments, got %q", flags.Arg(0)))
	}
	if len(allowed) == 0 {
		// No default. A server told nowhere to read from would otherwise be
		// told everywhere, and a permission nobody wrote is the thing this
		// build refuses everywhere else.
		return usageError(stderr, "mcp requires at least one --root")
	}

	server, err := mcp.New(mcp.Options{Roots: allowed})
	if err != nil {
		return inputError(stderr, err)
	}

	if err := server.Serve(os.Stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "infraproof: internal error: serving: %v\n", err)
		return evidence.ExitInternal
	}
	return evidence.ExitPass
}

const mcpUsage = `Usage:
  infraproof mcp --root <dir> [--root <dir> ...]

  --root   a directory the server may read from; repeat for more than one

Serves the verifier to a coding agent over the Model Context Protocol on
standard input and output. It offers two tools:

  analyze_change    compare a plan with an intent contract and return the
                    Evidence Bundle
  explain_finding   return one finding of that verification, with the plan data
                    it rests on and its remediation

The server reads only files inside the roots it is given, follows no symbolic
link out of one, runs no command, reaches no network, and applies nothing. There
is no default root: without --root it does not start.

Exit codes:
  0   the stream ended
  10  invalid usage, or a root that is not a readable directory
  11  internal failure
`
