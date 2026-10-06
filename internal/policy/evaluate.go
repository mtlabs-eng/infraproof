package policy

import (
	"fmt"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// Subject identifies the plan a verdict was reached from. The contract carries
// its own identity, so only the plan's is passed in.
type Subject struct {
	// PlanFormatVersion is the format version of the supplied plan.
	PlanFormatVersion string
	// PlanDigest is a "sha256:"-prefixed digest of the exact plan bytes.
	PlanDigest string
}

// Evaluate runs every rule and assembles the Evidence Bundle.
//
// The rules are independent: each reads the contract and the graph and returns
// what it found, and none can see another's result. That is what keeps them
// deterministic and separately testable, and it is why the decision is derived
// here from what they collectively produced rather than negotiated between
// them.
func Evaluate(contract intent.Contract, graph model.Graph, subject Subject) evidence.Bundle {
	var result Result
	for _, produced := range []Result{
		StorageExposure(contract, graph),
		NetworkExposure(contract, graph),
		DestructiveChange(contract, graph),
		CloudAllowed(contract, graph),
		EnvironmentMatch(contract, graph),
		ContractUnevaluated(contract),
		ContractCoverage(contract, graph),
	} {
		result.Findings = append(result.Findings, produced.Findings...)
		result.Unknowns = append(result.Unknowns, produced.Unknowns...)
		result.Evaluated = append(result.Evaluated, produced.Evaluated...)
	}

	// Last, because it is the only rule that reads what the others reported:
	// it says which resources they left unjudged.
	coverage := ResourceCoverage(graph, result.Evaluated)
	result.Unknowns = append(result.Unknowns, coverage.Unknowns...)

	decision := decide(result)
	bundle := evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      decision,
		Summary:       summarize(decision, result),
		Subject: evidence.Subject{
			// The path is supplied by whoever ran this build, and a file name
			// may hold a line break on every platform this runs on.
			IntentSource:      inline(contract.Source),
			IntentDigest:      contract.Digest,
			PlanFormatVersion: subject.PlanFormatVersion,
			PlanDigest:        subject.PlanDigest,
		},
		Verification: []evidence.Verification{
			{Name: "intent_contract", Status: evidence.VerificationVerified, Method: "intent-contract-json"},
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"},
			// Every run of this build lacks live state. A reader who is not
			// told will read the verdict as broader than it is.
			{Name: "live_state", Status: evidence.VerificationNotAvailable, Method: "none"},
		},
		Findings: result.Findings,
		Unknowns: result.Unknowns,
	}

	// Canonical ordering makes the output a function of content alone, so two
	// runs over one plan produce identical bytes whatever order the rules
	// appended in.
	return evidence.Canonical(bundle)
}

// decide derives the verdict from what the rules produced.
//
// The precedence follows the documented semantics and is not a preference: a
// blocking finding is deterministic evidence of a violation and outranks
// everything; a required unknown means a question needed for a safe conclusion
// went unanswered, which outranks a warning about a question that was answered;
// PASS is what remains when every required check ran and found nothing.
func decide(result Result) evidence.Decision {
	var blocking, warning bool
	for _, finding := range result.Findings {
		switch finding.Disposition {
		case evidence.DispositionBlock:
			blocking = true
		case evidence.DispositionWarn:
			warning = true
		}
	}

	var required bool
	for _, unknown := range result.Unknowns {
		if unknown.Required {
			required = true
			break
		}
	}

	switch {
	case blocking:
		return evidence.DecisionBlock
	case required:
		return evidence.DecisionUnknown
	case warning:
		return evidence.DecisionWarn
	default:
		return evidence.DecisionPass
	}
}

// summarize states the verdict in one line.
//
// It is assembled from counts and fixed text only. The summary is the one
// free-form field in the bundle, and every other field reaches output through a
// structure that cannot carry a plan value; interpolating one here would be the
// only way a value could escape that guarantee.
func summarize(decision evidence.Decision, result Result) string {
	var blocking, warning int
	for _, finding := range result.Findings {
		switch finding.Disposition {
		case evidence.DispositionBlock:
			blocking++
		case evidence.DispositionWarn:
			warning++
		}
	}
	var required int
	for _, unknown := range result.Unknowns {
		if unknown.Required {
			required++
		}
	}

	switch decision {
	case evidence.DecisionBlock:
		return fmt.Sprintf("The change violates the intent contract in %s.", count(blocking, "way"))
	case evidence.DecisionUnknown:
		return fmt.Sprintf("The change could not be verified: %s required for a safe conclusion %s unavailable.",
			count(required, "fact"), were(required))
	case evidence.DecisionWarn:
		return fmt.Sprintf("The change needs a human decision in %s.", count(warning, "way"))
	default:
		return "The change is consistent with the intent contract in every supported check."
	}
}

func count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func were(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}
