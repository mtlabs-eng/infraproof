package policy_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
)

func private(address string) model.NormalizedResource {
	return model.NormalizedResource{
		Address: address, Provider: "registry.terraform.io/hashicorp/aws",
		Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
		Environment: model.Known("staging",
			model.Provenance{ResourceAddress: address, AttributePath: "tags.environment"}),
		ObjectStorage: &model.ObjectStorageCapabilities{
			PublicAccess: model.Known(false,
				model.Provenance{ResourceAddress: address, AttributePath: "block_public_acls"})},
	}
}

func bundleFor(t *testing.T, c intent.Contract, resources ...model.NormalizedResource) evidence.Bundle {
	t.Helper()
	bundle := policy.Evaluate(c, model.Graph{Resources: resources}, policy.Subject{
		PlanFormatVersion: "1.2",
		PlanDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	})
	// Every bundle this engine produces must satisfy the contract it claims to
	// speak. A decision the renderer refuses is a decision nobody will read.
	if err := bundle.Validate(); err != nil {
		t.Fatalf("the engine produced an invalid bundle: %v", err)
	}
	return bundle
}

// TestACleanChangePasses is the baseline every other case is measured against.
// If this does not pass, the cases below pass for the wrong reason.
func TestACleanChangePasses(t *testing.T) {
	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"))

	if bundle.Decision != evidence.DecisionPass {
		t.Fatalf("decision = %q, want PASS: findings=%v unknowns=%v",
			bundle.Decision, bundle.Findings, bundle.Unknowns)
	}
	if evidence.ExitCode(bundle.Decision) != evidence.ExitPass {
		t.Errorf("exit = %d, want %d", evidence.ExitCode(bundle.Decision), evidence.ExitPass)
	}
}

// TestDecisionPrecedence fixes the order the documented semantics imply. A
// blocking finding outranks everything, a required unknown outranks a warning,
// and PASS is what is left when nothing else applies. The order matters most
// in the case it is easiest to get wrong: a plan that both violates something
// and leaves something undetermined must report the violation.
func TestDecisionPrecedence(t *testing.T) {
	public := private("aws_s3_bucket.public")
	public.ObjectStorage.PublicAccess = model.Known(true,
		model.Provenance{ResourceAddress: "aws_s3_bucket_acl.public", AttributePath: "acl"})

	undetermined := private("aws_s3_bucket.undetermined")
	undetermined.ObjectStorage.PublicAccess = model.Unknown[bool]()

	destroyed := private("aws_s3_bucket.destroyed")
	destroyed.Destructive = true

	cases := []struct {
		name      string
		contract  intent.Contract
		resources []model.NormalizedResource
		want      evidence.Decision
	}{
		{"a violation alone", contract(nil), []model.NormalizedResource{public}, evidence.DecisionBlock},
		{"an undetermined answer alone", contract(nil), []model.NormalizedResource{undetermined}, evidence.DecisionUnknown},
		{"a warning alone", contract(func(c *intent.Contract) {
			c.DestructiveChanges = intent.DestructiveAllowedWithWarning
		}), []model.NormalizedResource{destroyed}, evidence.DecisionWarn},
		{"a violation outranks an undetermined answer", contract(nil),
			[]model.NormalizedResource{public, undetermined}, evidence.DecisionBlock},
		{"an undetermined answer outranks a warning", contract(func(c *intent.Contract) {
			c.DestructiveChanges = intent.DestructiveAllowedWithWarning
		}), []model.NormalizedResource{destroyed, undetermined}, evidence.DecisionUnknown},
		{"a violation outranks both", contract(func(c *intent.Contract) {
			c.DestructiveChanges = intent.DestructiveAllowedWithWarning
		}), []model.NormalizedResource{public, destroyed, undetermined}, evidence.DecisionBlock},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bundle := bundleFor(t, tc.contract, tc.resources...)
			if bundle.Decision != tc.want {
				t.Fatalf("decision = %q, want %q: findings=%v unknowns=%v",
					bundle.Decision, tc.want, bundle.Findings, bundle.Unknowns)
			}
		})
	}
}

// TestEveryBlockRestsOnEvidence is CLAUDE.md's rule made mechanical. A BLOCK
// that cannot point at the data it came from is an opinion.
func TestEveryBlockRestsOnEvidence(t *testing.T) {
	public := private("aws_s3_bucket.public")
	public.ObjectStorage.PublicAccess = model.Known(true,
		model.Provenance{ResourceAddress: "aws_s3_bucket_acl.public", AttributePath: "acl"})

	wrongEnvironment := private("aws_s3_bucket.prod")
	wrongEnvironment.Environment = model.Known("production",
		model.Provenance{ResourceAddress: "aws_s3_bucket.prod", AttributePath: "tags.environment"})

	otherCloud := private("google_storage_bucket.g")
	otherCloud.Cloud = model.CloudGCP

	destroyed := private("aws_s3_bucket.gone")
	destroyed.Destructive = true

	bundle := bundleFor(t, contract(nil), public, wrongEnvironment, otherCloud, destroyed)

	if bundle.Decision != evidence.DecisionBlock {
		t.Fatalf("decision = %q, want BLOCK", bundle.Decision)
	}
	var blocking int
	for _, finding := range bundle.Findings {
		if finding.Disposition != evidence.DispositionBlock {
			continue
		}
		blocking++
		if len(finding.Evidence) == 0 {
			t.Errorf("%s blocks without evidence", finding.RuleID)
		}
		if finding.Remediation == "" {
			t.Errorf("%s blocks without telling the reader what to do", finding.RuleID)
		}
	}
	if blocking != 4 {
		t.Errorf("blocking findings = %d, want one per rule", blocking)
	}
}

// TestTheSubjectIdentifiesBothInputs keeps the bundle traceable to what was
// actually compared. A report that does not say which contract and which plan
// it read cannot be checked by anyone later.
func TestTheSubjectIdentifiesBothInputs(t *testing.T) {
	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"))

	if bundle.Subject.IntentSource != "intent.json" {
		t.Errorf("intent source = %q", bundle.Subject.IntentSource)
	}
	if bundle.Subject.PlanFormatVersion != "1.2" {
		t.Errorf("plan format version = %q", bundle.Subject.PlanFormatVersion)
	}
	if bundle.Subject.PlanDigest == "" {
		t.Error("the plan digest is missing")
	}
}

// TestUnevaluatedConstraintsAreReported keeps a restriction the contract states
// and nothing enforces from sitting silently beside a PASS.
func TestUnevaluatedConstraintsAreReported(t *testing.T) {
	withConstraints := contract(func(c *intent.Contract) {
		c.Constraints = &intent.Constraints{
			AllowedRegions: []string{"eu-west-1"},
			RequiredTags:   map[string]string{"owner": "checkout"},
		}
	})

	bundle := bundleFor(t, withConstraints, private("aws_s3_bucket.a"))

	var reported int
	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID == policy.CheckContractUnevaluated {
			reported++
			if unknown.Required {
				t.Error("a constraint this build cannot check limits the report; it does not invalidate it")
			}
		}
	}
	if reported != 2 {
		t.Fatalf("unevaluated constraints reported = %d, want 2: %v", reported, bundle.Unknowns)
	}
	// It still passes: the checks that ran, ran.
	if bundle.Decision != evidence.DecisionPass {
		t.Errorf("decision = %q, want PASS", bundle.Decision)
	}
}

// TestVerificationRecordsWhatDidNotRun keeps the absence of live state visible.
// Every run of this build lacks it, and a reader who does not know that will
// read the verdict as broader than it is.
func TestVerificationRecordsWhatDidNotRun(t *testing.T) {
	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"))

	byName := map[string]evidence.Verification{}
	for _, check := range bundle.Verification {
		byName[check.Name] = check
	}

	plan, ok := byName["terraform_plan"]
	if !ok || plan.Status != evidence.VerificationVerified {
		t.Errorf("terraform_plan = %v, want VERIFIED", plan)
	}
	live, ok := byName["live_state"]
	if !ok || live.Status != evidence.VerificationNotAvailable {
		t.Errorf("live_state = %v, want NOT_AVAILABLE", live)
	}
	if intentCheck, ok := byName["intent_contract"]; !ok || intentCheck.Status != evidence.VerificationVerified {
		t.Errorf("intent_contract = %v, want VERIFIED", intentCheck)
	}
}

// TestEvaluateIsDeterministic keeps the output a function of the input alone.
// Two runs over the same graph must produce the same bytes, whatever order the
// rules happened to append in.
func TestEvaluateIsDeterministic(t *testing.T) {
	public := private("aws_s3_bucket.public")
	public.ObjectStorage.PublicAccess = model.Known(true,
		model.Provenance{ResourceAddress: "aws_s3_bucket_acl.public", AttributePath: "acl"})
	undetermined := private("aws_s3_bucket.undetermined")
	undetermined.ObjectStorage.PublicAccess = model.Unknown[bool]()

	first := bundleFor(t, contract(nil), public, undetermined, private("aws_s3_bucket.a"))
	second := bundleFor(t, contract(nil), public, undetermined, private("aws_s3_bucket.a"))

	if len(first.Findings) != len(second.Findings) || len(first.Unknowns) != len(second.Unknowns) {
		t.Fatal("two runs over one graph disagreed on how much they found")
	}
	for i := range first.Findings {
		if first.Findings[i].RuleID != second.Findings[i].RuleID ||
			first.Findings[i].Resource.Address != second.Findings[i].Resource.Address {
			t.Fatalf("finding %d differs between runs", i)
		}
	}
	for i := range first.Unknowns {
		if first.Unknowns[i].CheckID != second.Unknowns[i].CheckID {
			t.Fatalf("unknown %d differs between runs", i)
		}
	}
}

// TestTheSummaryNeverCarriesAPlanValue keeps the one free-text field in the
// bundle from becoming a leak. The summary is assembled by this engine, and it
// is the only place a value could reach output without passing the contract's
// structural guarantees.
func TestTheSummaryNeverCarriesAPlanValue(t *testing.T) {
	secret := private("aws_s3_bucket.secret")
	secret.Environment = model.Known("hunter2-the-environment",
		model.Provenance{ResourceAddress: "aws_s3_bucket.secret", AttributePath: "tags.environment"})

	bundle := bundleFor(t, contract(nil), secret)

	if bundle.Summary == "" {
		t.Fatal("the bundle has no summary")
	}
	if strings.Contains(bundle.Summary, "hunter2") {
		t.Fatalf("the summary carries a plan value: %q", bundle.Summary)
	}
}
