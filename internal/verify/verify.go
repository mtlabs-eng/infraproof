// Package verify runs one verification, so that every caller runs the same one.
//
// The command wired the five steps itself, and any second caller — an adapter,
// a test harness — would have wired them again. Two wirings agree until one of
// them changes, and the milestone's criterion is that results are identical for
// the same files, which is not a property a reviewer can check by reading two
// call sites. It is one function now, and identity follows from there being
// nothing else to call.
package verify

import (
	"fmt"
	"io"
	"os"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/policy"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
	"github.com/mtlabs-eng/infraproof/internal/tfconfig"
)

// FromFiles reads an intent contract and a plan and returns the Evidence
// Bundle.
//
// A caller that cannot read its inputs gets an error and the zero bundle, never
// a partial one: a report reached from inputs the parser refused to vouch for
// would be a verdict about nothing, and handing one back invites acting on it.
// Deciding what to do about the error — an exit code, a tool error — belongs to
// the caller, because the two interfaces answer differently.
//
// Opening the files is this function's job rather than the caller's so that
// both interfaces read them the same way. A caller that must constrain where it
// reads from resolves the path first and passes the result here.
func FromFiles(intentPath, planPath string, opts Options) (evidence.Bundle, error) {
	contract, err := intent.Load(intentPath)
	if err != nil {
		return evidence.Bundle{}, err
	}

	raw, err := os.ReadFile(planPath)
	if err != nil {
		return evidence.Bundle{}, fmt.Errorf("reading plan %s: %w", planPath, err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		return evidence.Bundle{}, fmt.Errorf("reading plan %s: %w", planPath, err)
	}

	bundle := Plan(contract, plan)
	if opts.ConfigRoot == "" {
		return bundle, nil
	}
	// A directory that cannot be read is the caller's mistake rather than a fact
	// about the change, so it is an error and not a verdict with nothing located
	// in it. Everything past the directory itself -- a declaration that has
	// moved, a module this build does not resolve -- is an absence, and absence
	// is an answer.
	return tfconfig.Annotate(bundle, plan, opts.ConfigRoot)
}

// Options are the parts of a verification a caller chooses.
type Options struct {
	// ConfigRoot is the directory holding the Terraform configuration, enabling
	// source locations. Empty means no file is read and no output changes.
	//
	// There is no default. Guessing the directory from the plan's own path would
	// be a guess, and a wrong guess reports lines from the wrong configuration --
	// which is the failure source attribution exists to remove.
	ConfigRoot string
}

// FromReaders verifies a contract and a plan the caller has already opened.
//
// A caller that must constrain where it reads from cannot hand over a path and
// expect it to still mean the same file: between approving a name and opening
// it, a regular file can become a symlink pointing anywhere. So it opens the
// files itself and passes them here, and the name it approved never leaves the
// package that approved it.
//
// Each source is named only so that a report can say what it was compared
// against. The name is the caller's, and this function never opens it.
func FromReaders(intentName string, contract io.Reader, planName string, plan io.Reader,
	limit int64) (evidence.Bundle, error) {

	contractRaw, err := readAtMost(contract, limit)
	if err != nil {
		return evidence.Bundle{}, fmt.Errorf("reading intent contract %s: %w", intentName, err)
	}
	loaded, err := intent.Parse(contractRaw, intentName)
	if err != nil {
		return evidence.Bundle{}, err
	}

	planRaw, err := readAtMost(plan, limit)
	if err != nil {
		return evidence.Bundle{}, fmt.Errorf("reading plan %s: %w", planName, err)
	}
	parsed, err := terraformplan.Parse(planRaw)
	if err != nil {
		return evidence.Bundle{}, fmt.Errorf("reading plan %s: %w", planName, err)
	}

	return Plan(loaded, parsed), nil
}

// readAtMost reads up to limit bytes and refuses anything longer.
//
// The bound is on the read rather than on a size reported beforehand, because
// what a file says about its length is another fact that can change between
// being asked and being used -- and a device or a pipe never said anything
// truthful about it in the first place. A limit of zero or less reads
// everything, which is what a caller with its own bound wants.
func readAtMost(source io.Reader, limit int64) ([]byte, error) {
	if limit <= 0 {
		return io.ReadAll(source)
	}

	raw, err := io.ReadAll(io.LimitReader(source, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("is longer than the %d bytes this build reads", limit)
	}
	return raw, nil
}

// Plan evaluates a contract against a plan that has already been read.
//
// It is separate from FromFiles because reading a file and judging a change are
// different failures with different answers, and a caller that already holds
// both should not have to write them to disk to ask the question.
func Plan(contract intent.Contract, plan terraformplan.Plan) evidence.Bundle {
	return policy.Evaluate(contract, providers.Normalize(plan, providers.Default()), policy.Subject{
		PlanFormatVersion: plan.FormatVersion,
		PlanDigest:        plan.Digest,
	})
}
