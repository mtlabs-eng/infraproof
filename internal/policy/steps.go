package policy

import (
	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// factStep says how one plan fact a verdict rests on was established. The method
// is the fact's own, never recomputed here: the mapper that read the value is
// the only one that knows whether the plan stated it. A fact nobody gave a
// method converts to an empty method, which the bundle refuses.
//
// The method is never load-bearing: no decision, disposition or exit code reads
// it. It records how the verdict was reached, not what the verdict is.
func factStep[T any](path string, f model.Fact[T]) evidence.VerificationStep {
	return evidence.VerificationStep{Fact: path, Method: evidence.VerificationMethod(f.Method())}
}

// contractStep is the comparison with the intent contract. It is on every
// finding, including one where the contract declares nothing: silence is read,
// and is what made the finding a WARN.
func contractStep(field string) evidence.VerificationStep {
	return evidence.VerificationStep{Fact: "contract." + field, Method: evidence.MethodIntentComparison}
}
