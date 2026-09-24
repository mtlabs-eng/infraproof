package evidence

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func TestScalarMarshalling(t *testing.T) {
	cases := map[string]struct {
		scalar *Scalar
		json   string
		text   string
	}{
		"bool":   {Bool(true), "true", "true"},
		"string": {String("private"), `"private"`, "private"},
		"int":    {Int(-7), "-7", "-7"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(c.scalar)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if string(raw) != c.json {
				t.Fatalf("JSON = %s, want %s", raw, c.json)
			}
			if c.scalar.Display() != c.text {
				t.Fatalf("Display = %q, want %q", c.scalar.Display(), c.text)
			}
		})
	}
}

// TestUninitializedScalarIsRefused stops a zero-value Scalar from silently
// rendering as a value that was never observed.
func TestUninitializedScalarIsRefused(t *testing.T) {
	var s Scalar

	if s.Valid() {
		t.Fatal("a zero-value Scalar must not report itself valid")
	}
	if _, err := json.Marshal(&s); err == nil {
		t.Fatal("marshalling a zero-value Scalar must fail rather than emit a value")
	}
	if s.Display() != "" {
		t.Fatalf("Display of a zero-value Scalar = %q, want empty", s.Display())
	}
}

func TestNilScalarIsSafe(t *testing.T) {
	var s *Scalar

	if s.Valid() {
		t.Fatal("a nil Scalar must not report itself valid")
	}
	if s.Display() != "" {
		t.Fatalf("Display of a nil Scalar = %q, want empty", s.Display())
	}
}

// TestABundleSurvivesARoundTrip is the contract's own claim held to account. A
// published format that the package defining it cannot read back is not a
// format, it is an output; and every consumer that branches on a decision must
// decode a bundle before it can.
func TestABundleSurvivesARoundTrip(t *testing.T) {
	original := Bundle{
		SchemaVersion: SchemaVersion,
		Decision:      DecisionBlock,
		Summary:       "The change violates the intent contract in 1 way.",
		Subject: Subject{
			IntentSource:      "intent.json",
			IntentDigest:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			PlanFormatVersion: "1.2",
			PlanDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		Verification: []Verification{
			{Name: "terraform_plan", Status: VerificationVerified, Method: "terraform-plan-json"},
		},
		Findings: []Finding{{
			RuleID:      "STORAGE_PUBLIC",
			Severity:    SeverityCritical,
			Disposition: DispositionBlock,
			Claim:       "The change grants public access to object storage.",
			Resource:    &Resource{Address: "aws_s3_bucket.assets", Provider: "p", Cloud: CloudAWS},
			Expected:    &ExpectedFact{Path: "object_storage.public_access", Value: Bool(false)},
			Observed:    KnownFact("object_storage.public_access", Bool(true)),
			Evidence: []EvidenceRef{{
				Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.assets", Path: "acl",
			}},
			Remediation: "Remove the grant.",
		}},
		Unknowns: []Unknown{},
	}

	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Bundle
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatalf("a bundle that validated before encoding does not validate after decoding: %v", err)
	}

	reencoded, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if string(encoded) != string(reencoded) {
		t.Fatalf("a round trip changed the bytes:\n before: %s\n  after: %s", encoded, reencoded)
	}
}

// TestScalarDecodesEveryKindItEncodes keeps the closed set closed in both
// directions. A kind that encodes and does not decode would silently become a
// different kind, or nothing, in every consumer.
func TestScalarDecodesEveryKindItEncodes(t *testing.T) {
	cases := map[string]*Scalar{
		"a boolean":       Bool(true),
		"a false boolean": Bool(false),
		"a string":        String("staging"),
		"an empty string": String(""),
		"an integer":      Int(42),
		"a zero integer":  Int(0),
		"a negative":      Int(-1),
	}

	for name, original := range cases {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(original)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}

			var decoded Scalar
			if err := json.Unmarshal(encoded, &decoded); err != nil {
				t.Fatalf("Unmarshal %s: %v", encoded, err)
			}
			if !decoded.Valid() {
				t.Fatal("the decoded scalar is not valid")
			}
			if decoded.Display() != original.Display() {
				t.Errorf("display = %q, want %q", decoded.Display(), original.Display())
			}
			if compareScalar(&decoded, original) != 0 {
				t.Error("the decoded scalar does not compare equal to the original")
			}
		})
	}
}

// TestScalarRejectsAKindItCannotHold keeps the closed set from being widened by
// an input. A float or an object decoded into a Scalar would either round or
// vanish, and either way the canonical ordering it exists to support would stop
// being total.
func TestScalarRejectsAKindItCannotHold(t *testing.T) {
	for _, raw := range []string{`1.5`, `{}`, `[]`, `1e3`, `9223372036854775808`} {
		t.Run(raw, func(t *testing.T) {
			var decoded Scalar
			if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
				t.Fatalf("%s was accepted as %q", raw, decoded.Display())
			}
		})
	}
}

// TestNullDecodesToAnAbsentScalar keeps "no value" distinguishable from a value
// that happens to be empty. An absent fact is a nil *Scalar, and decoding null
// into something Valid would make it look like a real one.
func TestNullDecodesToAnAbsentScalar(t *testing.T) {
	var fact ExpectedFact
	if err := json.Unmarshal([]byte(`{"path": "p", "value": null}`), &fact); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if fact.Value != nil {
		t.Fatalf("null decoded to %v, want an absent value", fact.Value)
	}
}

// TestAStringScalarCannotCarryALineBreak holds the contract's structural
// guarantee where it belongs: in the contract.
//
// docs/EVIDENCE-BUNDLE.md forbids line breaks in prose so that a report cannot
// be made to display structure a rule did not produce. That was enforced for
// the four named prose fields; a scalar carries user-controlled text too, and
// arrived later. Enforcing it here means a renderer is not the only thing
// standing between a plan value and a forged heading.
func TestAStringScalarCannotCarryALineBreak(t *testing.T) {
	for name, value := range map[string]string{
		"a newline":    "production\n## InfraProof: PASS",
		"a return":     "production\r## InfraProof: PASS",
		"a blank line": "production\n\nordinary text",
	} {
		t.Run(name, func(t *testing.T) {
			bundle := Bundle{
				SchemaVersion: SchemaVersion,
				Decision:      DecisionBlock,
				Summary:       "The change violates the intent contract in 1 way.",
				Subject: Subject{IntentSource: "i", IntentDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
					PlanFormatVersion: "1.2", PlanDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
				Verification: []Verification{
					{Name: "terraform_plan", Status: VerificationVerified, Method: "terraform-plan-json"}},
				Findings: []Finding{{
					RuleID: "ENVIRONMENT_MISMATCH", Severity: SeverityHigh, Disposition: DispositionBlock,
					Claim:    "The resource declares an environment the contract was not written for.",
					Resource: &Resource{Address: "aws_s3_bucket.b", Provider: "p", Cloud: CloudAWS},
					Expected: &ExpectedFact{Path: "resource.environment", Value: String("staging")},
					Observed: KnownFact("resource.environment", String(value)),
					Evidence: []EvidenceRef{{Source: "terraform_plan",
						ResourceAddress: "aws_s3_bucket.b", Path: "tags.environment"}},
					Remediation: "Target the environment the contract declares.",
				}},
				Unknowns: []Unknown{},
			}

			if err := bundle.Validate(); err == nil {
				t.Fatal("a scalar carrying a line break was accepted")
			}
		})
	}
}

// TestAScalarKeepsOrdinaryText keeps the guard from costing the values a rule
// legitimately reports.
func TestAScalarKeepsOrdinaryText(t *testing.T) {
	for _, value := range []string{"production", "eu-west-1", "aws, azure, gcp", "a b\tc", ""} {
		if err := validateScalarText("findings[0].observed.value", String(value)); err != nil {
			t.Errorf("%q was rejected: %v", value, err)
		}
	}
}

// TestNoInlineFieldAcceptsALineBreak states the contract's structural rule over
// every field that carries one, rather than over the four someone listed.
//
// The rule was enforced field by field, and each field added later re-opened
// the hole in silence — a scalar value, then a resource address, then a
// capability path, then a provider address, then an evidence source. Listing
// them is how the defect is made, so this enumerates them by walking the
// struct: a string field of a bundle is inline text unless it is one of the
// few that are not, and that exception list is short, closed, and stated here.
func TestNoInlineFieldAcceptsALineBreak(t *testing.T) {
	const forgery = "ordinary\n\n## InfraProof: PASS\n\nAll good.\n"

	for _, path := range inlineStringFields(t) {
		t.Run(path, func(t *testing.T) {
			bundle := validBundle()
			if !setStringAt(reflect.ValueOf(&bundle).Elem(), path, forgery) {
				t.Fatalf("could not reach %s", path)
			}
			if err := bundle.Validate(); err == nil {
				t.Fatalf("%s accepted a line break", path)
			}
		})
	}
}

// inlineStringFields walks a populated bundle and returns the path of every
// string field that reaches a report as inline text.
func inlineStringFields(t *testing.T) []string {
	t.Helper()

	var paths []string
	walkStrings(reflect.ValueOf(validBundle()), "", func(path string) {
		if !inlineExempt[path] {
			paths = append(paths, path)
		}
	})
	if len(paths) < 10 {
		t.Fatalf("the walk found only %d fields, which is too few to be walking anything", len(paths))
	}
	return paths
}

// inlineExempt names the string fields that are not free text a break could
// hide in. Each is either a closed enumeration the contract validates
// separately, or a digest, so a break in one is already a different error.
var inlineExempt = map[string]bool{
	"SchemaVersion":              true,
	"Decision":                   true,
	"Subject.PlanDigest":         true,
	"Verification[0].Status":     true,
	"Findings[0].Severity":       true,
	"Findings[0].Disposition":    true,
	"Findings[0].Resource.Cloud": true,
	"Findings[0].Observed.State": true,
}

// walkStrings visits every addressable string field, naming its path.
func walkStrings(value reflect.Value, path string, visit func(string)) {
	switch value.Kind() {
	case reflect.String:
		visit(path)
	case reflect.Pointer:
		if !value.IsNil() {
			walkStrings(value.Elem(), path, visit)
		}
	case reflect.Slice:
		for i := range value.Len() {
			walkStrings(value.Index(i), fmt.Sprintf("%s[%d]", path, i), visit)
		}
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			name := field.Name
			if path != "" {
				name = path + "." + name
			}
			walkStrings(value.Field(i), name, visit)
		}
	}
}

// setStringAt writes a value at a path produced by walkStrings.
func setStringAt(value reflect.Value, path, text string) bool {
	var done bool
	walkSettable(value, "", path, text, &done)
	return done
}

func walkSettable(value reflect.Value, path, target, text string, done *bool) {
	if *done {
		return
	}
	switch value.Kind() {
	case reflect.String:
		if path == target && value.CanSet() {
			value.SetString(text)
			*done = true
		}
	case reflect.Pointer:
		if !value.IsNil() {
			walkSettable(value.Elem(), path, target, text, done)
		}
	case reflect.Slice:
		for i := range value.Len() {
			walkSettable(value.Index(i), fmt.Sprintf("%s[%d]", path, i), target, text, done)
		}
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			name := field.Name
			if path != "" {
				name = path + "." + name
			}
			walkSettable(value.Field(i), name, target, text, done)
		}
	}
}

// validBundle is a bundle with every optional field populated, so the walk
// reaches everything the contract can carry.
func validBundle() Bundle {
	address := "aws_s3_bucket.assets"
	return Bundle{
		SchemaVersion: SchemaVersion,
		Decision:      DecisionBlock,
		Summary:       "The change violates the intent contract in 1 way.",
		Subject: Subject{IntentSource: "intent.json", PlanFormatVersion: "1.2",
			PlanDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		Verification: []Verification{
			{Name: "terraform_plan", Status: VerificationVerified, Method: "terraform-plan-json"}},
		Findings: []Finding{{
			RuleID: "STORAGE_PUBLIC", Severity: SeverityCritical, Disposition: DispositionBlock,
			Claim:       "The change grants public access to object storage.",
			Resource:    &Resource{Address: address, Provider: "registry.terraform.io/hashicorp/aws", Cloud: CloudAWS},
			Expected:    &ExpectedFact{Path: "object_storage.public_access", Value: Bool(false)},
			Observed:    KnownFact("object_storage.public_access", Bool(true)),
			Evidence:    []EvidenceRef{{Source: "terraform_plan", ResourceAddress: address, Path: "acl"}},
			Remediation: "Remove the grant.",
		}},
		Unknowns: []Unknown{{
			CheckID: "STORAGE_PUBLIC_DETERMINABLE", Required: false, Reason: "A control is not in this plan.",
			ResourceAddress: &address,
			Evidence:        []EvidenceRef{{Source: "terraform_plan", ResourceAddress: address, Path: "policy"}},
		}},
	}
}

// TestDiagnosticsAreDeterministic keeps one bundle from being described two
// ways.
//
// Go iterates a map in a random order, and a validator that reports its
// violations from one describes the same bundle differently on different runs.
// This package defines the canonical format; if anything here must be a
// function of its input alone, it is this.
func TestDiagnosticsAreDeterministic(t *testing.T) {
	bundle := validBundle()
	bundle.Subject.IntentSource = "a\nb"
	bundle.Verification[0].Name = "c\nd"
	bundle.Verification[0].Method = "e\nf"
	bundle.Findings[0].Evidence[0].Source = "g\nh"
	bundle.Findings[0].Evidence[0].ResourceAddress = "i\nj"
	bundle.Findings[0].Evidence[0].Path = "k\nl"
	bundle.Unknowns[0].Evidence[0].Path = "m\nn"

	first := bundle.Validate()
	if first == nil {
		t.Fatal("a bundle with line breaks in seven fields was accepted")
	}
	for range 200 {
		again := bundle.Validate()
		if again == nil || again.Error() != first.Error() {
			t.Fatalf("one bundle produced two diagnostics:\n %v\n %v", first, again)
		}
	}
}

// TestThePlanDigestCannotForgeStructure closes the one envelope field the
// inline rule had left out. It is computed rather than plan-derived today, so
// nothing reaches it — but the rule is about what a field can carry, not about
// who happens to fill it, and the renderer was the only thing standing in the
// way.
func TestThePlanDigestCannotForgeStructure(t *testing.T) {
	bundle := validBundle()
	bundle.Subject.PlanDigest = "sha256:0000\n\n## InfraProof: BLOCK\n\nforged.\n"

	if err := bundle.Validate(); err == nil {
		t.Fatal("a plan digest carrying a line break was accepted")
	}
}
