package evidence

import (
	"strings"
	"testing"
)

// blockBundle returns the smallest bundle that legitimately supports a BLOCK
// decision. Tests mutate a copy of it to construct invalid variants.
func blockBundle() Bundle {
	return Bundle{
		SchemaVersion: SchemaVersion,
		Decision:      DecisionBlock,
		Summary:       "The requested private storage change enables public access.",
		Subject: Subject{
			IntentSource:      "intent.yaml",
			PlanFormatVersion: "1.x",
			PlanDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			IntentDigest:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		Verification: []Verification{
			{Name: "terraform_plan", Status: VerificationVerified, Method: "terraform-plan-json"},
		},
		Findings: []Finding{
			{
				RuleID:      "STORAGE_PUBLIC",
				Severity:    SeverityCritical,
				Disposition: DispositionBlock,
				Claim:       "Object storage permits public access.",
				Resource: &Resource{
					Address:  "aws_s3_bucket.assets",
					Provider: "registry.terraform.io/hashicorp/aws",
					Cloud:    CloudAWS,
				},
				Expected: &ExpectedFact{Path: "object_storage.public_access", Value: Bool(false)},
				Observed: &ObservedFact{Path: "object_storage.public_access", State: FactKnown, Value: Bool(true)},
				Evidence: []EvidenceRef{{
					Source:          "terraform_plan",
					ResourceAddress: "aws_s3_bucket.assets",
					Path:            "resource_changes[].change.after",
				}},
				Remediation: "Disable public access using the provider-supported controls.",
			},
		},
		Unknowns: []Unknown{},
	}
}

func warnFinding() Finding {
	return Finding{
		RuleID:      "STORAGE_VERSIONING_ABSENT",
		Severity:    SeverityMedium,
		Disposition: DispositionWarn,
		Claim:       "Object storage versioning is not declared.",
		Observed:    &ObservedFact{Path: "object_storage.versioning", State: FactAbsent},
		Evidence: []EvidenceRef{{
			Source: "terraform_plan",
			Path:   "resource_changes[].change.after",
		}},
		Remediation: "Declare versioning explicitly.",
	}
}

func infoFinding() Finding {
	return Finding{
		RuleID:      "STORAGE_SCOPE_NOTE",
		Severity:    SeverityInfo,
		Disposition: DispositionInfo,
		Claim:       "One object storage resource was evaluated.",
		Evidence: []EvidenceRef{{
			Source: "terraform_plan",
			Path:   "resource_changes[]",
		}},
		Remediation: "No remediation required; this finding is informational.",
	}
}

func optionalUnknown() Unknown {
	return Unknown{
		CheckID:  "LIVE_STATE_AVAILABLE",
		Required: false,
		Reason:   "InfraProof was run without a live-state collector.",
		Evidence: []EvidenceRef{},
	}
}

func requiredUnknown() Unknown {
	return Unknown{
		CheckID:  "STORAGE_PUBLIC_DETERMINABLE",
		Required: true,
		Reason:   "Public access could not be determined from the supplied plan.",
		Evidence: []EvidenceRef{},
	}
}

func passBundle() Bundle {
	b := blockBundle()
	b.Decision = DecisionPass
	b.Summary = "The change matches the declared intent."
	b.Findings = []Finding{infoFinding()}
	b.Unknowns = []Unknown{optionalUnknown()}
	return b
}

func warnBundle() Bundle {
	b := blockBundle()
	b.Decision = DecisionWarn
	b.Summary = "The change requires an explicit human decision."
	b.Findings = []Finding{warnFinding()}
	b.Unknowns = []Unknown{optionalUnknown()}
	return b
}

func unknownBundle() Bundle {
	b := blockBundle()
	b.Decision = DecisionUnknown
	b.Summary = "Required evidence for a safe conclusion is unavailable."
	b.Findings = []Finding{infoFinding()}
	b.Unknowns = []Unknown{requiredUnknown()}
	return b
}

func TestValidBundlePerDecision(t *testing.T) {
	cases := map[string]Bundle{
		"PASS":    passBundle(),
		"WARN":    warnBundle(),
		"BLOCK":   blockBundle(),
		"UNKNOWN": unknownBundle(),
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			if err := b.Validate(); err != nil {
				t.Fatalf("expected valid bundle, got error: %v", err)
			}
		})
	}
}

func TestInvalidBundles(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Bundle)
		want   string
	}{
		{
			name:   "block without blocking finding",
			mutate: func(b *Bundle) { b.Findings = []Finding{infoFinding()} },
			want:   "disposition",
		},
		{
			name:   "block with unevidenced blocking finding",
			mutate: func(b *Bundle) { b.Findings[0].Evidence = nil },
			want:   "evidence",
		},
		{
			name: "warn without warning finding",
			mutate: func(b *Bundle) {
				*b = warnBundle()
				b.Findings = []Finding{infoFinding()}
			},
			want: "WARN",
		},
		{
			name: "warn carrying a required unknown",
			mutate: func(b *Bundle) {
				*b = warnBundle()
				b.Unknowns = append(b.Unknowns, requiredUnknown())
			},
			want: "required unknown",
		},
		{
			name: "warn containing a blocking finding",
			mutate: func(b *Bundle) {
				*b = warnBundle()
				b.Findings = append(b.Findings, blockBundle().Findings[0])
			},
			want: "BLOCK",
		},
		{
			name: "unknown without a required unknown",
			mutate: func(b *Bundle) {
				*b = unknownBundle()
				b.Unknowns = []Unknown{optionalUnknown()}
			},
			want: "required unknown",
		},
		{
			name: "unknown containing a blocking finding",
			mutate: func(b *Bundle) {
				*b = unknownBundle()
				b.Findings = append(b.Findings, blockBundle().Findings[0])
			},
			want: "BLOCK",
		},
		{
			name: "pass containing a blocking finding",
			mutate: func(b *Bundle) {
				*b = passBundle()
				b.Findings = append(b.Findings, blockBundle().Findings[0])
			},
			want: "BLOCK",
		},
		{
			name: "pass containing a warning finding",
			mutate: func(b *Bundle) {
				*b = passBundle()
				b.Findings = append(b.Findings, warnFinding())
			},
			want: "WARN",
		},
		{
			name: "pass containing a required unknown",
			mutate: func(b *Bundle) {
				*b = passBundle()
				b.Unknowns = append(b.Unknowns, requiredUnknown())
			},
			want: "required unknown",
		},
		{
			name:   "empty summary",
			mutate: func(b *Bundle) { b.Summary = "" },
			want:   "summary",
		},
		{
			name:   "missing plan digest prefix",
			mutate: func(b *Bundle) { b.Subject.PlanDigest = "example" },
			want:   "plan_digest",
		},
		{
			name:   "empty verification",
			mutate: func(b *Bundle) { b.Verification = nil },
			want:   "verification",
		},
		{
			name: "duplicate verification name",
			mutate: func(b *Bundle) {
				b.Verification = append(b.Verification, b.Verification[0])
			},
			want: "duplicate",
		},
		{
			name:   "invalid verification status",
			mutate: func(b *Bundle) { b.Verification[0].Status = "MAYBE" },
			want:   "status",
		},
		{
			name:   "invalid decision",
			mutate: func(b *Bundle) { b.Decision = "MAYBE" },
			want:   "decision",
		},
		{
			name:   "invalid severity",
			mutate: func(b *Bundle) { b.Findings[0].Severity = "SEVERE" },
			want:   "severity",
		},
		{
			name:   "invalid cloud",
			mutate: func(b *Bundle) { b.Findings[0].Resource.Cloud = "ibm" },
			want:   "cloud",
		},
		{
			name:   "lowercase rule id",
			mutate: func(b *Bundle) { b.Findings[0].RuleID = "storage_public" },
			want:   "rule_id",
		},
		{
			name:   "missing remediation",
			mutate: func(b *Bundle) { b.Findings[0].Remediation = "" },
			want:   "remediation",
		},
		{
			name:   "evidence without a path",
			mutate: func(b *Bundle) { b.Findings[0].Evidence[0].Path = "" },
			want:   "path",
		},
		{
			name:   "expected fact without a value",
			mutate: func(b *Bundle) { b.Findings[0].Expected.Value = nil },
			want:   "expected",
		},
		{
			name:   "unknown without a reason",
			mutate: func(b *Bundle) { *b = passBundle(); b.Unknowns[0].Reason = "" },
			want:   "reason",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := blockBundle()
			c.mutate(&b)
			err := b.Validate()
			if err == nil {
				t.Fatalf("expected a validation error mentioning %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), c.want)
			}
		})
	}
}

func TestObservedValueRequiresKnownState(t *testing.T) {
	for _, state := range []FactState{FactUnknown, FactAbsent, FactRedacted} {
		t.Run(string(state), func(t *testing.T) {
			b := blockBundle()
			b.Findings[0].Observed = &ObservedFact{
				Path:  "object_storage.public_access",
				State: state,
				Value: Bool(true),
			}
			err := b.Validate()
			if err == nil {
				t.Fatal("expected a non-KNOWN fact carrying a value to be rejected")
			}
			if !strings.Contains(err.Error(), "KNOWN") {
				t.Fatalf("error %q does not explain the KNOWN requirement", err.Error())
			}
		})
	}
}

func TestValidationErrorOmitsFactValues(t *testing.T) {
	b := blockBundle()
	b.Findings[0].Observed = &ObservedFact{
		Path:  "database.master_password",
		State: FactRedacted,
		Value: String("hunter2"),
	}
	err := b.Validate()
	if err == nil {
		t.Fatal("expected a validation error")
	}
	if !strings.Contains(err.Error(), "database.master_password") {
		t.Fatalf("error %q does not locate the offending field", err.Error())
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("error %q leaked the fact value", err.Error())
	}
}

func TestRedactedFactCarriesNoValue(t *testing.T) {
	f := RedactedFact("database.master_password")
	if f.State != FactRedacted {
		t.Fatalf("state = %q, want %q", f.State, FactRedacted)
	}
	if f.Value != nil {
		t.Fatal("RedactedFact must not carry a value")
	}
}

func TestSchemaVersionAcceptance(t *testing.T) {
	cases := map[string]bool{
		"1.0":   true,
		"1.7":   true,
		"1.12":  true,
		"":      false,
		"1":     false,
		"2.0":   false,
		"0.9":   false,
		"abc":   false,
		"1.x":   false,
		"1.0.1": false,
	}
	for version, valid := range cases {
		t.Run(version, func(t *testing.T) {
			b := blockBundle()
			b.SchemaVersion = version
			err := b.Validate()
			if valid && err != nil {
				t.Fatalf("schema version %q should be accepted, got %v", version, err)
			}
			if !valid && err == nil {
				t.Fatalf("schema version %q should be rejected", version)
			}
			if !valid && !strings.Contains(err.Error(), "schema_version") {
				t.Fatalf("error %q does not mention schema_version", err.Error())
			}
		})
	}
}

func TestValidateReportsEveryViolation(t *testing.T) {
	b := blockBundle()
	b.Summary = ""
	b.Subject.IntentSource = ""
	err := b.Validate()
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{"summary", "intent_source"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("aggregated error %q is missing %q", err.Error(), want)
		}
	}
}

func TestUnknownCheckIDMustBeAStableIdentifier(t *testing.T) {
	for _, checkID := range []string{"", "live state", "liveState", "1_CHECK", "LIVE-STATE"} {
		t.Run(checkID, func(t *testing.T) {
			b := passBundle()
			b.Unknowns[0].CheckID = checkID
			err := b.Validate()
			if err == nil {
				t.Fatalf("check_id %q should be rejected", checkID)
			}
			if !strings.Contains(err.Error(), "check_id") {
				t.Fatalf("error %q does not mention check_id", err.Error())
			}
		})
	}
}

func TestKnownFactMustCarryAValue(t *testing.T) {
	b := blockBundle()
	b.Findings[0].Observed = &ObservedFact{Path: "object_storage.public_access", State: FactKnown}

	err := b.Validate()
	if err == nil {
		t.Fatal("a KNOWN fact without a value should be rejected")
	}
	if !strings.Contains(err.Error(), "KNOWN") {
		t.Fatalf("error %q does not explain the KNOWN requirement", err.Error())
	}
}

func TestSchemaVersionMinorMustBeAPlainNumber(t *testing.T) {
	for _, version := range []string{"1.+1", "1.-1", "1.007", "1. 1", "1.1 "} {
		t.Run(version, func(t *testing.T) {
			b := blockBundle()
			b.SchemaVersion = version
			err := b.Validate()
			if err == nil {
				t.Fatalf("schema version %q should be rejected", version)
			}
			if !strings.Contains(err.Error(), "schema_version") {
				t.Fatalf("error %q does not mention schema_version", err.Error())
			}
		})
	}
}

func TestPlanDigestRemainderMustNotBeBlank(t *testing.T) {
	for _, digest := range []string{"sha256:", "sha256: ", "sha256:   "} {
		t.Run(digest, func(t *testing.T) {
			b := blockBundle()
			b.Subject.PlanDigest = digest
			err := b.Validate()
			if err == nil {
				t.Fatalf("plan digest %q should be rejected", digest)
			}
			if !strings.Contains(err.Error(), "plan_digest") {
				t.Fatalf("error %q does not mention plan_digest", err.Error())
			}
		})
	}
}

func TestDuplicateVerificationNameIgnoresSurroundingSpace(t *testing.T) {
	b := blockBundle()
	b.Verification = append(b.Verification, Verification{
		Name:   " terraform_plan ",
		Status: VerificationVerified,
		Method: "terraform-plan-json",
	})

	err := b.Validate()
	if err == nil {
		t.Fatal("a duplicate check name that differs only in surrounding space should be rejected")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("error %q does not report a duplicate", err.Error())
	}
}

// TestProseFieldsRejectLineBreaks keeps single-line prose single-line. A line
// break in prose would let a claim or remediation forge document structure in
// the Markdown rendering.
func TestProseFieldsRejectLineBreaks(t *testing.T) {
	cases := map[string]func(*Bundle){
		"summary":     func(b *Bundle) { b.Summary = "Line one.\nLine two." },
		"claim":       func(b *Bundle) { b.Findings[0].Claim = "Line one.\nLine two." },
		"remediation": func(b *Bundle) { b.Findings[0].Remediation = "Line one.\r\nLine two." },
		"reason":      func(b *Bundle) { *b = passBundle(); b.Unknowns[0].Reason = "Line one.\nLine two." },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := blockBundle()
			mutate(&b)
			err := b.Validate()
			if err == nil {
				t.Fatalf("a line break in %s should be rejected", name)
			}
			if !strings.Contains(err.Error(), "single line") {
				t.Fatalf("error %q does not explain the single-line requirement", err.Error())
			}
		})
	}
}

// TestADigestMustBeADigest closes a field that accepted anything after its
// prefix.
//
// The contract calls these fields a sha256 digest over the exact input bytes,
// and a reader correlating a report with an input has only this to correlate
// on. "sha256:probably-the-same-plan" satisfied a prefix check, and a field
// that accepts prose is a field a later producer will fill with prose.
func TestADigestMustBeADigest(t *testing.T) {
	const good = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	bad := map[string]string{
		"no prefix":        "0000000000000000000000000000000000000000000000000000000000000000",
		"prose":            "sha256:the same plan as yesterday",
		"too short":        "sha256:00",
		"too long":         good + "00",
		"upper case":       "sha256:" + strings.Repeat("A", 64),
		"not hexadecimal":  "sha256:" + strings.Repeat("g", 64),
		"another function": "sha512:" + strings.Repeat("0", 64),
	}

	for _, field := range []struct {
		name string
		set  func(*Bundle, string)
	}{
		{"plan_digest", func(b *Bundle, v string) { b.Subject.PlanDigest = v }},
		{"intent_digest", func(b *Bundle, v string) { b.Subject.IntentDigest = v }},
	} {
		t.Run(field.name, func(t *testing.T) {
			for name, digest := range bad {
				t.Run(name, func(t *testing.T) {
					b := blockBundle()
					field.set(&b, digest)
					err := b.Validate()
					if err == nil {
						t.Fatalf("%s %q should be rejected", field.name, digest)
					}
					if !strings.Contains(err.Error(), field.name) {
						t.Fatalf("error %q does not name the field", err.Error())
					}
				})
			}

			b := blockBundle()
			field.set(&b, good)
			if err := b.Validate(); err != nil {
				t.Fatalf("a well-formed digest was rejected: %v", err)
			}
		})
	}
}

// TestAnErrorNamesThePositionAReaderWillSee closes a gap between the two
// halves of rendering.
//
// A bundle is validated and then canonically ordered, so an error naming
// findings[1] named the position a producer happened to write, and the reader
// looking for it counted to a different record. The order is part of the
// contract; the diagnostics have to speak it.
func TestAnErrorNamesThePositionAReaderWillSee(t *testing.T) {
	b := blockBundle()
	high := b.Findings[0]

	low := high
	low.RuleID = "AAA_LOW_SEVERITY"
	low.Severity = SeverityLow
	low.Claim = "" // the violation

	// Written low first; canonical order puts the critical finding first, so
	// the offending record is findings[1] to a reader and findings[0] here.
	b.Findings = []Finding{low, high}

	err := b.Validate()
	if err == nil {
		t.Fatal("a finding with no claim was accepted")
	}
	if !strings.Contains(err.Error(), "findings[1]") {
		t.Errorf("the error names a position the reader never sees: %v", err)
	}
}
