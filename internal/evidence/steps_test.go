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
		MethodPriorState, MethodConfigurationUnrecorded,
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
		"zero-width fact": {Fact: "object_storage.\u200bpublic_access", Method: MethodPlanStatedValue},
		"bidi in fact":    {Fact: "object_storage.\u202epublic_access", Method: MethodPlanStatedValue},
		"markup as fact":  {Fact: "<img src=x>", Method: MethodPlanStatedValue},
		"table as fact":   {Fact: "| a |", Method: MethodPlanStatedValue},
		"one segment":     {Fact: "public_access", Method: MethodPlanStatedValue},
		"upper case":      {Fact: "Object_Storage.public_access", Method: MethodPlanStatedValue},
		"empty segment":   {Fact: "object_storage..public_access", Method: MethodPlanStatedValue},
		// Added by the fourth review: each is one rule of the documented shape
		// that no case above isolates.
		"upper case inside":    {Fact: "object_storage.public_Access", Method: MethodPlanStatedValue},
		"upper case first":     {Fact: "object_storage.Public_access", Method: MethodPlanStatedValue},
		"leading digit":        {Fact: "object_storage.1public", Method: MethodPlanStatedValue},
		"leading underscore":   {Fact: "_object_storage.public_access", Method: MethodPlanStatedValue},
		"a hyphen":             {Fact: "object-storage.public_access", Method: MethodPlanStatedValue},
		"leading dot":          {Fact: ".object_storage.public_access", Method: MethodPlanStatedValue},
		"trailing dot":         {Fact: "object_storage.", Method: MethodPlanStatedValue},
		"a contract, trailing": {Fact: "contract.", Method: MethodIntentComparison},
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

// A fact the verdict rests on is established one way. The same step twice says
// nothing a reader can use, and one fact with two methods says two incompatible
// things about where a single value came from -- both are defects of whoever
// wrote the bundle, whatever version it declares.
func TestAFactIsEstablishedOnce(t *testing.T) {
	cases := map[string][]VerificationStep{
		"the same step twice": {
			{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
			{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
			{Fact: "contract.object_storage.exposure", Method: MethodIntentComparison},
		},
		"one fact, two methods": {
			{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
			{Fact: "object_storage.public_access", Method: MethodProviderDefault},
			{Fact: "contract.object_storage.exposure", Method: MethodIntentComparison},
		},
	}
	for name, steps := range cases {
		for _, version := range []string{"1.2", "1.3"} {
			if err := withSteps(version, steps).Validate(); err == nil ||
				!strings.Contains(err.Error(), "verification_steps") {
				t.Errorf("%s at %s: accepted (%v)", name, version, err)
			}
		}
	}
}

// Every finding is a comparison with the contract, and from 1.3 its steps say
// so. A 1.2 bundle that carries the field is held to its shape but not to this,
// because 1.2 never promised it.
func TestAVersionWithStepsRequiresTheContractStep(t *testing.T) {
	planOnly := []VerificationStep{{Fact: "object_storage.public_access", Method: MethodPlanStatedValue}}
	if err := withSteps("1.3", planOnly).Validate(); err == nil ||
		!strings.Contains(err.Error(), "contract.") {
		t.Errorf("a 1.3 finding with no contract step was accepted: %v", err)
	}
	if err := withSteps("1.2", planOnly).Validate(); err != nil {
		t.Errorf("a 1.2 bundle carrying steps without the contract step was refused: %v", err)
	}
	// A contract step is a contract path, not any fact that happens to carry
	// the comparison's method.
	wrongMethod := []VerificationStep{
		{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
		{Fact: "object_storage.exposure", Method: MethodIntentComparison},
	}
	if err := withSteps("1.3", wrongMethod).Validate(); err == nil {
		t.Error("a comparison step outside contract. was taken for the contract step")
	}
	// Nor is any contract. fact the comparison, whatever method it claims.
	notCompared := []VerificationStep{
		{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
		{Fact: "contract.object_storage.exposure", Method: MethodPlanStatedValue},
	}
	if err := withSteps("1.3", notCompared).Validate(); err == nil {
		t.Error("a contract. fact not established by intent-comparison was taken for the contract step")
	}
	// The prefix is the segment, dot included: a fact that merely begins with
	// the word is not a contract path.
	notTheSegment := []VerificationStep{
		{Fact: "object_storage.public_access", Method: MethodPlanStatedValue},
		{Fact: "contractual.exposure", Method: MethodIntentComparison},
	}
	if err := withSteps("1.3", notTheSegment).Validate(); err == nil {
		t.Error("a fact beginning with contract but not the contract. segment was taken for the contract step")
	}
	// Digits and underscores after the first letter are part of the shape.
	shaped := []VerificationStep{
		{Fact: "object_storage.public_access2", Method: MethodPlanStatedValue},
		{Fact: "contract.object_storage.exposure", Method: MethodIntentComparison},
	}
	if err := withSteps("1.3", shaped).Validate(); err != nil {
		t.Errorf("a well-formed bundle was refused: %v", err)
	}
}
