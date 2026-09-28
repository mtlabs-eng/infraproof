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
	"os"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/policy"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
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
func FromFiles(intentPath, planPath string) (evidence.Bundle, error) {
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

	return Plan(contract, plan), nil
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
