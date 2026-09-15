package evidence

import (
	"reflect"
	"testing"
)

func findingAt(ruleID string, sev Severity, address string) Finding {
	f := Finding{
		RuleID:      ruleID,
		Severity:    sev,
		Disposition: DispositionInfo,
		Claim:       "claim for " + ruleID,
		Remediation: "none required",
		Evidence:    []EvidenceRef{},
	}
	if address != "" {
		f.Resource = &Resource{Address: address, Provider: "registry.terraform.io/hashicorp/aws", Cloud: CloudAWS}
	}
	return f
}

func findingOrder(b Bundle) []string {
	order := make([]string, 0, len(b.Findings))
	for _, f := range b.Findings {
		address := ""
		if f.Resource != nil {
			address = f.Resource.Address
		}
		order = append(order, string(f.Severity)+"/"+f.RuleID+"/"+address)
	}
	return order
}

func TestFindingsSortBySeverityThenRuleThenAddress(t *testing.T) {
	b := blockBundle()
	b.Findings = []Finding{
		findingAt("B_RULE", SeverityLow, "aws_s3_bucket.b"),
		findingAt("A_RULE", SeverityCritical, "aws_s3_bucket.z"),
		findingAt("A_RULE", SeverityCritical, "aws_s3_bucket.a"),
		findingAt("A_RULE", SeverityCritical, ""),
		findingAt("C_RULE", SeverityInfo, "aws_s3_bucket.c"),
		findingAt("A_RULE", SeverityHigh, "aws_s3_bucket.h"),
	}

	want := []string{
		"CRITICAL/A_RULE/",
		"CRITICAL/A_RULE/aws_s3_bucket.a",
		"CRITICAL/A_RULE/aws_s3_bucket.z",
		"HIGH/A_RULE/aws_s3_bucket.h",
		"LOW/B_RULE/aws_s3_bucket.b",
		"INFO/C_RULE/aws_s3_bucket.c",
	}
	got := findingOrder(Canonical(b))
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("finding order =\n%v\nwant\n%v", got, want)
	}
}

func TestCanonicalIsOrderIndependent(t *testing.T) {
	forward := blockBundle()
	forward.Findings = []Finding{
		findingAt("A_RULE", SeverityHigh, "aws_s3_bucket.a"),
		findingAt("B_RULE", SeverityHigh, "aws_s3_bucket.b"),
		findingAt("C_RULE", SeverityMedium, "aws_s3_bucket.c"),
	}
	reversed := blockBundle()
	reversed.Findings = []Finding{
		findingAt("C_RULE", SeverityMedium, "aws_s3_bucket.c"),
		findingAt("B_RULE", SeverityHigh, "aws_s3_bucket.b"),
		findingAt("A_RULE", SeverityHigh, "aws_s3_bucket.a"),
	}

	if !reflect.DeepEqual(findingOrder(Canonical(forward)), findingOrder(Canonical(reversed))) {
		t.Fatal("canonical ordering depends on input order")
	}
}

func TestEvidenceSorts(t *testing.T) {
	b := blockBundle()
	b.Findings[0].Evidence = []EvidenceRef{
		{Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.b", Path: "change.after"},
		{Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.a", Path: "change.before"},
		{Source: "intent", ResourceAddress: "aws_s3_bucket.a", Path: "resources[0]"},
		{Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.a", Path: "change.after"},
	}

	want := []EvidenceRef{
		{Source: "intent", ResourceAddress: "aws_s3_bucket.a", Path: "resources[0]"},
		{Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.a", Path: "change.after"},
		{Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.a", Path: "change.before"},
		{Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.b", Path: "change.after"},
	}
	got := Canonical(b).Findings[0].Evidence
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence order =\n%v\nwant\n%v", got, want)
	}
}

func TestUnknownsSortByCheckIDThenAddress(t *testing.T) {
	addressB := "aws_s3_bucket.b"
	addressA := "aws_s3_bucket.a"
	b := passBundle()
	b.Unknowns = []Unknown{
		{CheckID: "B_CHECK", Reason: "r", Evidence: []EvidenceRef{}},
		{CheckID: "A_CHECK", Reason: "r", ResourceAddress: &addressB, Evidence: []EvidenceRef{}},
		{CheckID: "A_CHECK", Reason: "r", ResourceAddress: &addressA, Evidence: []EvidenceRef{}},
		{CheckID: "A_CHECK", Reason: "r", Evidence: []EvidenceRef{}},
	}

	want := []string{"A_CHECK/", "A_CHECK/aws_s3_bucket.a", "A_CHECK/aws_s3_bucket.b", "B_CHECK/"}
	got := make([]string, 0, len(want))
	for _, u := range Canonical(b).Unknowns {
		address := ""
		if u.ResourceAddress != nil {
			address = *u.ResourceAddress
		}
		got = append(got, u.CheckID+"/"+address)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unknown order = %v, want %v", got, want)
	}
}

func TestVerificationOrderIsPreserved(t *testing.T) {
	b := blockBundle()
	b.Verification = []Verification{
		{Name: "terraform_plan", Status: VerificationVerified, Method: "terraform-plan-json"},
		{Name: "live_state", Status: VerificationNotAvailable, Method: "none"},
	}
	got := Canonical(b).Verification
	if !reflect.DeepEqual(got, b.Verification) {
		t.Fatalf("verification order = %v, want it preserved as %v", got, b.Verification)
	}
}

func TestCanonicalDoesNotMutateInput(t *testing.T) {
	b := blockBundle()
	b.Findings = []Finding{
		findingAt("C_RULE", SeverityInfo, "aws_s3_bucket.c"),
		findingAt("A_RULE", SeverityCritical, "aws_s3_bucket.a"),
	}
	b.Findings[0].Evidence = []EvidenceRef{
		{Source: "terraform_plan", Path: "z"},
		{Source: "terraform_plan", Path: "a"},
	}
	before := findingOrder(b)
	beforeEvidence := append([]EvidenceRef(nil), b.Findings[0].Evidence...)

	_ = Canonical(b)

	if !reflect.DeepEqual(findingOrder(b), before) {
		t.Fatal("Canonical reordered the caller's findings")
	}
	if !reflect.DeepEqual(b.Findings[0].Evidence, beforeEvidence) {
		t.Fatal("Canonical reordered the caller's evidence")
	}
}

// TestFindingOrderIsTotalOverContent guards the guarantee that canonical output
// depends only on bundle content, never on the order the producer happened to
// append findings in. Each case differs in exactly one field that the primary
// sort keys do not cover.
func TestFindingOrderIsTotalOverContent(t *testing.T) {
	base := func() Finding { return findingAt("SAME_RULE", SeverityHigh, "aws_s3_bucket.assets") }

	cases := map[string]func() (Finding, Finding){
		"remediation": func() (Finding, Finding) {
			a, b := base(), base()
			a.Remediation, b.Remediation = "AAA remediation.", "ZZZ remediation."
			return a, b
		},
		"disposition": func() (Finding, Finding) {
			a, b := base(), base()
			a.Disposition, b.Disposition = DispositionInfo, DispositionWarn
			return a, b
		},
		"observed value": func() (Finding, Finding) {
			a, b := base(), base()
			a.Observed = KnownFact("object_storage.public_access", Bool(false))
			b.Observed = KnownFact("object_storage.public_access", Bool(true))
			return a, b
		},
		"observed state": func() (Finding, Finding) {
			a, b := base(), base()
			a.Observed = AbsentFact("object_storage.public_access")
			b.Observed = RedactedFact("object_storage.public_access")
			return a, b
		},
		"expected value": func() (Finding, Finding) {
			a, b := base(), base()
			a.Expected = &ExpectedFact{Path: "object_storage.public_access", Value: Bool(false)}
			b.Expected = &ExpectedFact{Path: "object_storage.public_access", Value: Bool(true)}
			return a, b
		},
		"resource provider": func() (Finding, Finding) {
			a, b := base(), base()
			a.Resource.Provider = "registry.terraform.io/hashicorp/aws"
			b.Resource.Provider = "registry.terraform.io/hashicorp/google"
			return a, b
		},
		"observed scalar kind": func() (Finding, Finding) {
			a, b := base(), base()
			a.Observed = KnownFact("object_storage.exposure", Bool(true))
			b.Observed = KnownFact("object_storage.exposure", String("true"))
			return a, b
		},
		"observed string value": func() (Finding, Finding) {
			a, b := base(), base()
			a.Observed = KnownFact("object_storage.exposure", String("private"))
			b.Observed = KnownFact("object_storage.exposure", String("public-read"))
			return a, b
		},
		"observed int value": func() (Finding, Finding) {
			a, b := base(), base()
			a.Observed = KnownFact("object_storage.retention_days", Int(1))
			b.Observed = KnownFact("object_storage.retention_days", Int(30))
			return a, b
		},
		"resource cloud": func() (Finding, Finding) {
			a, b := base(), base()
			a.Resource.Cloud, b.Resource.Cloud = CloudAWS, CloudGCP
			return a, b
		},
		"evidence redaction": func() (Finding, Finding) {
			a, b := base(), base()
			a.Evidence = []EvidenceRef{{Source: "terraform_plan", Path: "change.after", Redacted: false}}
			b.Evidence = []EvidenceRef{{Source: "terraform_plan", Path: "change.after", Redacted: true}}
			return a, b
		},
		"evidence": func() (Finding, Finding) {
			a, b := base(), base()
			a.Evidence = []EvidenceRef{{Source: "terraform_plan", Path: "change.after"}}
			b.Evidence = []EvidenceRef{{Source: "terraform_plan", Path: "change.before"}}
			return a, b
		},
		"evidence count": func() (Finding, Finding) {
			a, b := base(), base()
			a.Evidence = []EvidenceRef{{Source: "terraform_plan", Path: "change.after"}}
			b.Evidence = []EvidenceRef{
				{Source: "terraform_plan", Path: "change.after"},
				{Source: "terraform_plan", Path: "change.before"},
			}
			return a, b
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			a, b := build()

			forward := blockBundle()
			forward.Findings = []Finding{a, b}
			reversed := blockBundle()
			reversed.Findings = []Finding{b, a}

			if !reflect.DeepEqual(Canonical(forward).Findings, Canonical(reversed).Findings) {
				t.Fatalf("findings differing only in %s order by input position, not by content", name)
			}
		})
	}
}

// TestUnknownOrderIsTotalOverContent guards the same property for unknowns.
// The required flag matters most: it is what gates a PASS decision.
func TestUnknownOrderIsTotalOverContent(t *testing.T) {
	address := "aws_s3_bucket.assets"
	base := func() Unknown {
		return Unknown{
			CheckID:         "SAME_CHECK",
			Reason:          "The same reason.",
			ResourceAddress: &address,
			Evidence:        []EvidenceRef{},
		}
	}

	cases := map[string]func() (Unknown, Unknown){
		"required": func() (Unknown, Unknown) {
			a, b := base(), base()
			a.Required, b.Required = false, true
			return a, b
		},
		"evidence": func() (Unknown, Unknown) {
			a, b := base(), base()
			a.Evidence = []EvidenceRef{{Source: "terraform_plan", Path: "change.after"}}
			b.Evidence = []EvidenceRef{{Source: "terraform_plan", Path: "change.before"}}
			return a, b
		},
	}

	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			a, b := build()

			forward := passBundle()
			forward.Unknowns = []Unknown{a, b}
			reversed := passBundle()
			reversed.Unknowns = []Unknown{b, a}

			if !reflect.DeepEqual(Canonical(forward).Unknowns, Canonical(reversed).Unknowns) {
				t.Fatalf("unknowns differing only in %s order by input position, not by content", name)
			}
		})
	}
}

func TestCanonicalNormalizesNilCollections(t *testing.T) {
	b := blockBundle()
	b.Findings[0].Evidence = nil
	b.Unknowns = nil

	c := Canonical(b)
	if c.Unknowns == nil {
		t.Fatal("canonical unknowns must be an empty slice, not nil")
	}
	if c.Findings[0].Evidence == nil {
		t.Fatal("canonical evidence must be an empty slice, not nil")
	}

	empty := Canonical(Bundle{})
	if empty.Findings == nil || empty.Unknowns == nil || empty.Verification == nil {
		t.Fatal("canonical collections must never be nil")
	}
}

func TestUnrecognizedSeveritySortsBelowInfo(t *testing.T) {
	b := blockBundle()
	b.Findings = []Finding{
		findingAt("A_RULE", "SEVERE", "aws_s3_bucket.a"),
		findingAt("B_RULE", SeverityInfo, "aws_s3_bucket.b"),
	}

	got := Canonical(b).Findings
	if got[0].Severity != SeverityInfo {
		t.Fatalf("an unrecognized severity must not outrank INFO, got order %q then %q", got[0].Severity, got[1].Severity)
	}
}

// TestEqualSeverityFindingsSortByRuleID pins the documented primary key order
// from docs/EVIDENCE-BUNDLE.md: severity, then rule ID, then resource address.
// Order-independence alone does not pin it, because any total comparator is
// order-independent regardless of which key it reads first.
func TestEqualSeverityFindingsSortByRuleID(t *testing.T) {
	b := blockBundle()
	b.Findings = []Finding{
		findingAt("C_RULE", SeverityHigh, "aws_s3_bucket.a"),
		findingAt("A_RULE", SeverityHigh, "aws_s3_bucket.z"),
		findingAt("B_RULE", SeverityHigh, "aws_s3_bucket.m"),
	}

	want := []string{"A_RULE", "B_RULE", "C_RULE"}
	got := make([]string, 0, len(want))
	for _, f := range Canonical(b).Findings {
		got = append(got, f.RuleID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rule ID order = %v, want %v", got, want)
	}
}

// TestFindingsWithEqualPrimaryKeysSortByClaim pins the claim as the tiebreak
// that follows severity, rule ID, and resource address.
func TestFindingsWithEqualPrimaryKeysSortByClaim(t *testing.T) {
	b := blockBundle()
	first := findingAt("SAME_RULE", SeverityHigh, "aws_s3_bucket.assets")
	first.Claim = "A claim that sorts first."
	second := findingAt("SAME_RULE", SeverityHigh, "aws_s3_bucket.assets")
	second.Claim = "Z claim that sorts last."
	b.Findings = []Finding{second, first}

	got := Canonical(b).Findings
	if got[0].Claim != first.Claim {
		t.Fatalf("claim order = [%q %q], want the A claim first", got[0].Claim, got[1].Claim)
	}
}

// TestUnknownsWithEqualCheckIDSortByReason pins the reason as the tiebreak that
// follows the check ID and resource address.
func TestUnknownsWithEqualCheckIDSortByReason(t *testing.T) {
	b := passBundle()
	b.Unknowns = []Unknown{
		{CheckID: "SAME_CHECK", Reason: "Z reason.", Evidence: []EvidenceRef{}},
		{CheckID: "SAME_CHECK", Reason: "A reason.", Evidence: []EvidenceRef{}},
	}

	got := Canonical(b).Unknowns
	if got[0].Reason != "A reason." {
		t.Fatalf("reason order = [%q %q], want the A reason first", got[0].Reason, got[1].Reason)
	}
}

// TestResourceAddressOutranksClaim pins the resource address ahead of the claim
// in the key order. The claims here sort opposite to the addresses, so a
// comparator that reads the claim first would produce the reverse order.
func TestResourceAddressOutranksClaim(t *testing.T) {
	b := blockBundle()
	early := findingAt("SAME_RULE", SeverityHigh, "aws_s3_bucket.a")
	early.Claim = "Z claim on the first address."
	late := findingAt("SAME_RULE", SeverityHigh, "aws_s3_bucket.z")
	late.Claim = "A claim on the second address."
	b.Findings = []Finding{late, early}

	got := Canonical(b).Findings
	if got[0].Resource.Address != "aws_s3_bucket.a" {
		t.Fatalf("address order = [%q %q], want aws_s3_bucket.a first",
			got[0].Resource.Address, got[1].Resource.Address)
	}
}

// TestFindingWithoutResourceSortsFirst pins where an unaddressed finding lands
// among findings that share its severity and rule.
func TestFindingWithoutResourceSortsFirst(t *testing.T) {
	b := blockBundle()
	b.Findings = []Finding{
		findingAt("SAME_RULE", SeverityHigh, "aws_s3_bucket.a"),
		findingAt("SAME_RULE", SeverityHigh, ""),
	}

	if got := Canonical(b).Findings[0]; got.Resource != nil {
		t.Fatalf("a finding without a resource must sort first, got %q", got.Resource.Address)
	}
}
