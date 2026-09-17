package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/policy"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/render"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// runCheck compares a plan with an intent contract and reports the verdict.
//
// Operational failure and verification decision are kept apart throughout: a
// missing file, a malformed contract and an unreadable plan all return
// ExitInvalidInput and print nothing to stdout, because a report emitted from
// inputs that could not be read would be a verdict about nothing. Only a
// completed evaluation writes a bundle, and only then does the exit code carry
// a decision.
func runCheck(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(stderr)
	intentPath := flags.String("intent", "", "path to an intent contract JSON file")
	planPath := flags.String("plan", "", "path to a Terraform or OpenTofu plan JSON file")
	format := flags.String("format", "json", "output format: json or markdown")

	if err := flags.Parse(args); err != nil {
		return evidence.ExitInvalidInput
	}
	if flags.NArg() > 0 {
		return usageError(stderr, fmt.Sprintf("check takes no positional arguments, got %q", flags.Arg(0)))
	}
	if *intentPath == "" {
		return usageError(stderr, "check requires --intent")
	}
	if *planPath == "" {
		return usageError(stderr, "check requires --plan")
	}

	renderer, ok := renderers[*format]
	if !ok {
		return usageError(stderr, fmt.Sprintf("--format is %q, want json or markdown", *format))
	}

	contract, err := intent.Load(*intentPath)
	if err != nil {
		return inputError(stderr, err)
	}

	raw, err := os.ReadFile(*planPath)
	if err != nil {
		return inputError(stderr, fmt.Errorf("reading plan %s: %w", *planPath, err))
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		return inputError(stderr, fmt.Errorf("reading plan %s: %w", *planPath, err))
	}

	bundle := policy.Evaluate(contract, providers.Normalize(plan, providers.Default()), policy.Subject{
		PlanFormatVersion: plan.FormatVersion,
		PlanDigest:        plan.Digest,
	})

	out, err := renderer(bundle)
	if err != nil {
		// The engine produced something the contract refuses. That is an
		// invariant this program broke, not a verdict about the change, and
		// reporting it as one would be worse than failing.
		fmt.Fprintf(stderr, "infraproof: internal error: rendering the evidence bundle: %v\n", err)
		return evidence.ExitInternal
	}

	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintf(stderr, "infraproof: internal error: writing output: %v\n", err)
		return evidence.ExitInternal
	}

	return evidence.ExitCode(bundle.Decision)
}

// renderers are the output formats. Both render the same bundle, so a reader
// and a pipeline cannot be told different things.
var renderers = map[string]func(evidence.Bundle) ([]byte, error){
	"json":     render.JSON,
	"markdown": render.Markdown,
}

// inputError reports unusable input. The message comes from the loader, which
// names the file the user supplied and never a value inside it.
func inputError(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "infraproof: %v\n", err)
	return evidence.ExitInvalidInput
}
