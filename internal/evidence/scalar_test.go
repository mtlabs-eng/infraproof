package evidence

import (
	"encoding/json"
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
