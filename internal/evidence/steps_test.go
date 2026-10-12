package evidence

import (
	"strings"
	"testing"
)

// withSteps returns a block bundle declaring the given version whose finding
// carries the given steps.
func withSteps(version string, steps []VerificationStep) Bundle {
	b := blockBundle()
	b.SchemaVersion = version
	b.Findings[0].VerificationSteps = steps
	return b
}

func stated() []VerificationStep {
	return []VerificationStep{
		{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
		{Fact: "contract.object_storage.exposure", Method: MethodIntentComparison},
	}
}

func TestEveryMethodInTheClosedSetIsValid(t *testing.T) {
	for _, m := range []VerificationMethod{
		MethodPlanStatedValue, MethodProviderDefault, MethodPolicyDocumentInterpreted,
		MethodReferenceResolved, MethodDocumentedTable, MethodPlanAction, MethodIntentComparison,
	} {
		if !m.Valid() {
			t.Errorf("%q is in the closed set and was refused", m)
		}
	}
	for _, m := range []VerificationMethod{"", "plan", "PLAN-STATED-VALUE", " plan-stated-value"} {
		if m.Valid() {
			t.Errorf("%q is not in the closed set and was accepted", m)
		}
	}
}

func TestAVersionWithStepsRequiresThem(t *testing.T) {
	if err := withSteps("1.3", nil).Validate(); err == nil ||
		!strings.Contains(err.Error(), "verification_steps") {
		t.Errorf("a 1.3 finding with no step was accepted: %v", err)
	}
	if err := withSteps("1.3", stated()).Validate(); err != nil {
		t.Errorf("a well-formed 1.3 bundle was refused: %v", err)
	}
}

func TestAnEarlierVersionIsValidWithoutSteps(t *testing.T) {
	if err := withSteps("1.2", nil).Validate(); err != nil {
		t.Errorf("a 1.2 bundle predating the field was refused: %v", err)
	}
}

func TestAStepPresentIsValidatedWhateverTheVersion(t *testing.T) {
	cases := map[string]VerificationStep{
		"unknown method":  {Fact: "object_storage.public_access", Method: "guessed"},
		"empty method":    {Fact: "object_storage.public_access"},
		"empty fact":      {Fact: "  ", Method: MethodPlanStatedValue},
		"multi-line fact": {Fact: "object_storage\n# forged", Method: MethodPlanStatedValue},
		"control in fact": {Fact: "object\x1b[2Jstorage", Method: MethodPlanStatedValue},
	}
	for name, step := range cases {
		for _, version := range []string{"1.2", "1.3"} {
			if err := withSteps(version, []VerificationStep{step}).Validate(); err == nil {
				t.Errorf("%s at %s: accepted", name, version)
			}
		}
	}
}

func TestStepsAreOrderedByFactThenMethod(t *testing.T) {
	b := withSteps("1.3", []VerificationStep{
		{Fact: "database.port", Method: MethodDocumentedTable},
		{Fact: "contract.database.exposure", Method: MethodIntentComparison},
		{Fact: "database.admitted_by", Method: MethodReferenceResolved},
		{Fact: "database.admitted_by", Method: MethodPlanStatedValue},
	})
	got := Canonical(b).Findings[0].VerificationSteps
	want := []VerificationStep{
		{Fact: "contract.database.exposure", Method: MethodIntentComparison},
		{Fact: "database.admitted_by", Method: MethodPlanStatedValue},
		{Fact: "database.admitted_by", Method: MethodReferenceResolved},
		{Fact: "database.port", Method: MethodDocumentedTable},
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d = %v, want %v", i, got[i], want[i])
		}
	}
	if b.Findings[0].VerificationSteps[0].Fact != "database.port" {
		t.Error("Canonical reordered the caller's slice")
	}
}

func TestFindingsDifferingOnlyInStepsAreOrderedByContent(t *testing.T) {
	a := blockBundle().Findings[0]
	a.VerificationSteps = []VerificationStep{{Fact: "object_storage.public_access", Method: MethodPolicyDocumentInterpreted}}
	b := blockBundle().Findings[0]
	b.VerificationSteps = []VerificationStep{{Fact: "object_storage.public_access", Method: MethodPlanStatedValue}}

	if compareFindings(a, b) == 0 {
		t.Fatal("two findings differing in their steps compared equal")
	}
	if compareFindings(a, b) != -compareFindings(b, a) {
		t.Error("the order is not antisymmetric")
	}
}
