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

// TestAResourceNoRuleEvaluatedCannotPass closes the hole the review named as
// the next place this project's recurring defect would live.
//
// Today every resource is either opaque — which raises a required unknown
// because its cloud is not established — or object storage, which the exposure
// rule evaluates. Coverage therefore holds by accident, not by construction.
// The moment a second family is mapped, a resource with a known cloud and no
// rule for its family is reached by nothing: it produces no finding, raises no
// unknown, and the PASS beside it means "not checked" while reading as
// "checked and fine".
//
// That is reading absence as permission at the coverage level, and it is the
// one level above where the last review looked. The engine now derives what
// was evaluated from what the rules report, rather than from a list of
// families that would go stale the moment someone forgot to add to it.
func TestAResourceNoRuleEvaluatedCannotPass(t *testing.T) {
	// A mapped resource of a family this build has no rule for. It is
	// constructed rather than parsed because no mapper produces one yet —
	// which is the point: the guarantee must exist before the mapper does.
	unevaluated := model.NormalizedResource{
		Address:     "aws_sqs_queue.orders",
		Provider:    "registry.terraform.io/hashicorp/aws",
		Cloud:       model.CloudAWS,
		Family:      model.Family("message_queue"),
		Interpreted: true,
		Environment: model.Known("staging",
			model.Provenance{ResourceAddress: "aws_sqs_queue.orders", AttributePath: "tags.environment"}),
	}

	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"), unevaluated)

	if bundle.Decision == evidence.DecisionPass {
		t.Fatalf("a resource no rule evaluated reported a pass:\nfindings=%v\nunknowns=%v",
			bundle.Findings, bundle.Unknowns)
	}

	var reported bool
	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID != policy.CheckResourceEvaluated {
			continue
		}
		reported = true
		if unknown.ResourceAddress == nil || *unknown.ResourceAddress != "aws_sqs_queue.orders" {
			t.Errorf("the unknown names %v, want the unevaluated resource", unknown.ResourceAddress)
		}
		if unknown.Reason == "" {
			t.Error("the gap is named but not explained")
		}
	}
	if !reported {
		t.Fatalf("the unevaluated resource was not reported: %v", bundle.Unknowns)
	}
}

// TestAnEvaluatedResourceIsNotReportedAsUnevaluated keeps the guarantee from
// costing every clean run a note about work that was done.
func TestAnEvaluatedResourceIsNotReportedAsUnevaluated(t *testing.T) {
	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"), private("aws_s3_bucket.b"))

	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID == policy.CheckResourceEvaluated {
			t.Fatalf("an evaluated resource was reported as unevaluated: %v", unknown)
		}
	}
	if bundle.Decision != evidence.DecisionPass {
		t.Fatalf("decision = %q, want PASS", bundle.Decision)
	}
}

// TestAControlResourceIsEvaluatedThroughItsSubject keeps the guarantee from
// firing on resources that have no verdict of their own. A public-access block
// is understood, and its meaning belongs to the bucket it governs; reporting it
// as unevaluated would make every correct plan noisy and teach a reader to skip
// the section.
func TestAControlResourceIsEvaluatedThroughItsSubject(t *testing.T) {
	control := model.NormalizedResource{
		Address:     "aws_s3_bucket_public_access_block.a",
		Provider:    "registry.terraform.io/hashicorp/aws",
		Cloud:       model.CloudAWS,
		Family:      model.FamilyObjectStorage,
		Interpreted: true,
		// No ObjectStorage: its meaning belongs to the resource it controls,
		// which is named here so that the claim can be checked rather than
		// believed.
		DefersTo: []string{"aws_s3_bucket.a"},
	}

	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"), control)

	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID == policy.CheckResourceEvaluated {
			t.Fatalf("a control resource was reported as unevaluated: %v", unknown)
		}
	}
	if bundle.Decision != evidence.DecisionPass {
		t.Fatalf("decision = %q, want PASS", bundle.Decision)
	}
}

// TestAnOpaqueResourceIsReportedOnceNotTwice keeps the two coverage gaps
// distinct. A resource no mapper claimed already raises a required unknown
// saying its cloud is not established; adding a second saying no rule evaluated
// it tells the reader the same thing in different words.
func TestAnOpaqueResourceIsReportedOnceNotTwice(t *testing.T) {
	opaque := model.NormalizedResource{
		Address: "vendor_thing.x",
		Cloud:   model.CloudUnknown,
		Family:  model.FamilyUnknown,
	}

	bundle := bundleFor(t, contract(nil), opaque)

	var evaluated, determinable int
	for _, unknown := range bundle.Unknowns {
		switch unknown.CheckID {
		case policy.CheckResourceEvaluated:
			evaluated++
		case policy.CheckCloudDeterminable:
			determinable++
		}
	}
	if determinable != 1 {
		t.Errorf("CLOUD_DETERMINABLE raised %d times, want 1", determinable)
	}
	if evaluated != 0 {
		t.Errorf("an opaque resource was also reported as unevaluated %d times", evaluated)
	}
}

// TestAControlWhoseSubjectIsAbsentCannotPass is the defect a review found in
// the fix for the defect before it.
//
// StorageExposure marked a control resource as judged "through the subject it
// governs". When the subject is not in the plan, its meaning went nowhere and
// nothing judged it — and a rule's claim to have judged something is an
// unstated fact in exactly this project's sense. Adding a policy or an IAM
// binding to a bucket managed elsewhere is the ordinary shape of the change,
// and it reported PASS with no findings at all.
//
// Coverage now resolves the deferral against the graph rather than believing
// the claim: a control is covered when a subject it defers to is present and
// was itself judged.
func TestAControlWhoseSubjectIsAbsentCannotPass(t *testing.T) {
	orphan := model.NormalizedResource{
		Address:     "google_storage_bucket_iam_member.public",
		Provider:    "registry.terraform.io/hashicorp/google",
		Cloud:       model.CloudGCP,
		Family:      model.FamilyObjectStorage,
		Interpreted: true,
		// No ObjectStorage, and no subject in this plan to defer to.
	}

	bundle := bundleFor(t, contract(nil), orphan)

	if bundle.Decision == evidence.DecisionPass {
		t.Fatalf("a control whose subject is absent reported a pass:\nfindings=%v\nunknowns=%v",
			bundle.Findings, bundle.Unknowns)
	}

	var reported bool
	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID != policy.CheckResourceEvaluated {
			continue
		}
		reported = true
		if unknown.ResourceAddress == nil || *unknown.ResourceAddress != orphan.Address {
			t.Errorf("the unknown names %v, want the orphan control", unknown.ResourceAddress)
		}
	}
	if !reported {
		t.Fatalf("the orphan control was not reported: %v", bundle.Unknowns)
	}
}

// TestAControlDefersOnlyToASubjectThatWasJudged keeps the deferral honest in
// the other direction. Naming a subject is not enough: the subject must be in
// the graph, and it must itself have been judged, or the deferral passes the
// question to something that never answered it.
func TestAControlDefersOnlyToASubjectThatWasJudged(t *testing.T) {
	cases := map[string]struct {
		defersTo []string
		resource []model.NormalizedResource
		covered  bool
	}{
		"a subject that was judged": {
			defersTo: []string{"aws_s3_bucket.a"},
			resource: []model.NormalizedResource{private("aws_s3_bucket.a")},
			covered:  true,
		},
		"a subject not in the graph": {
			defersTo: []string{"aws_s3_bucket.elsewhere"},
			resource: nil,
			covered:  false,
		},
		"a subject that was itself unjudged": {
			defersTo: []string{"aws_sqs_queue.orders"},
			resource: []model.NormalizedResource{{
				Address: "aws_sqs_queue.orders", Provider: "p", Cloud: model.CloudAWS,
				Family: model.Family("message_queue"), Interpreted: true}},
			covered: false,
		},
		"no subject at all": {
			defersTo: nil,
			resource: nil,
			covered:  false,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			control := model.NormalizedResource{
				Address: "aws_s3_bucket_policy.c", Provider: "p", Cloud: model.CloudAWS,
				Family: model.FamilyObjectStorage, Interpreted: true, DefersTo: tc.defersTo,
			}

			bundle := bundleFor(t, contract(nil), append(tc.resource, control)...)

			var reported bool
			for _, unknown := range bundle.Unknowns {
				if unknown.CheckID == policy.CheckResourceEvaluated &&
					unknown.ResourceAddress != nil && *unknown.ResourceAddress == control.Address {
					reported = true
				}
			}
			if reported == tc.covered {
				t.Fatalf("control reported as unevaluated = %v, want %v: %v",
					reported, !tc.covered, bundle.Unknowns)
			}
		})
	}
}

// TestADataSourceNeitherBlocksNorBlocksAPass keeps a read from deciding
// anything about a change, in either direction.
func TestADataSourceNeitherBlocksNorBlocksAPass(t *testing.T) {
	read := model.NormalizedResource{
		Address: "data.aws_s3_bucket.existing", Provider: "p",
		Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
		ReadOnly: true,
	}

	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"), read)

	if bundle.Decision != evidence.DecisionPass {
		t.Fatalf("decision = %q, want PASS: findings=%v unknowns=%v",
			bundle.Decision, bundle.Findings, bundle.Unknowns)
	}
	for _, finding := range bundle.Findings {
		if finding.Resource != nil && finding.Resource.Address == read.Address {
			t.Errorf("a data source produced a finding: %s", finding.RuleID)
		}
	}
	for _, unknown := range bundle.Unknowns {
		if unknown.Required && unknown.ResourceAddress != nil &&
			*unknown.ResourceAddress == read.Address {
			t.Errorf("a data source prevented a pass: %s", unknown.CheckID)
		}
	}
}

// TestAContradictoryReadCannotPass keeps the disagreement visible in the
// bundle, not only in the model. A plan that says one thing in its mode and
// another in its actions has not been read, and a run that could not read it
// has not established that it is safe.
func TestAContradictoryReadCannotPass(t *testing.T) {
	contradictory := model.NormalizedResource{
		Address: "data.aws_s3_bucket.existing", Provider: "p",
		Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
		Destructive: true, // its actions say delete
		// ReadOnly deliberately false: the mode said read and was not believed.
	}

	bundle := bundleFor(t, contract(nil), private("aws_s3_bucket.a"), contradictory)

	if bundle.Decision == evidence.DecisionPass {
		t.Fatalf("a plan whose mode and actions disagree reported a pass:\nfindings=%v\nunknowns=%v",
			bundle.Findings, bundle.Unknowns)
	}
}
