package policy_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
)

func contract(mutate func(*intent.Contract)) intent.Contract {
	c := intent.Contract{
		SchemaVersion:      "1.0",
		ChangeID:           "change",
		Environment:        "staging",
		AllowedClouds:      []string{"aws"},
		DestructiveChanges: intent.DestructiveForbidden,
		Resources:          []intent.ResourceIntent{{Family: "object_storage", Exposure: intent.ExposurePrivate}},
		Digest:             "sha256:abc",
		Source:             "intent.json",
	}
	if mutate != nil {
		mutate(&c)
	}
	return c
}

func findingsFor(result policy.Result, ruleID string) []evidence.Finding {
	var out []evidence.Finding
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func unknownsFor(result policy.Result, checkID string) []evidence.Unknown {
	var out []evidence.Unknown
	for _, u := range result.Unknowns {
		if u.CheckID == checkID {
			out = append(out, u)
		}
	}
	return out
}

// ---------------------------------------------------------------- destructive

func TestDestructiveChangeIsBlockedWhenForbidden(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.gone", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
			Interpreted: true, Destructive: true},
	}}

	result := policy.DestructiveChange(contract(nil), graph)

	found := findingsFor(result, policy.RuleDestructiveChange)
	if len(found) != 1 {
		t.Fatalf("findings = %v, want one", result.Findings)
	}
	if found[0].Disposition != evidence.DispositionBlock {
		t.Errorf("disposition = %q, want BLOCK", found[0].Disposition)
	}
	if len(found[0].Evidence) == 0 {
		t.Error("a blocking finding must locate its source data")
	}
	if found[0].Resource == nil || found[0].Resource.Address != "aws_s3_bucket.gone" {
		t.Errorf("resource = %v", found[0].Resource)
	}
}

// TestDestructiveChangeWarnsWhenAllowedWithWarning keeps severity and
// enforcement apart. The same destruction is equally destructive under both
// policies; only what the contract permits differs.
func TestDestructiveChangeWarnsWhenAllowedWithWarning(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.gone", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
			Interpreted: true, Destructive: true},
	}}

	result := policy.DestructiveChange(contract(func(c *intent.Contract) {
		c.DestructiveChanges = intent.DestructiveAllowedWithWarning
	}), graph)

	found := findingsFor(result, policy.RuleDestructiveChange)
	if len(found) != 1 {
		t.Fatalf("findings = %v, want one", result.Findings)
	}
	if found[0].Disposition != evidence.DispositionWarn {
		t.Errorf("disposition = %q, want WARN", found[0].Disposition)
	}
	if found[0].Severity != evidence.SeverityHigh {
		t.Errorf("severity = %q; the impact does not change with the policy", found[0].Severity)
	}
}

// TestADestructiveChangeIsReportedWhateverTheMapperUnderstood is the rule the
// M03 review rounds converged on, at the level of a policy. Destruction is
// visible in the plan's actions and needs no mapper, so a resource no mapper
// claimed must still be reported destroyed.
func TestADestructiveChangeIsReportedWhateverTheMapperUnderstood(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "some_unknown_thing.gone", Cloud: model.CloudUnknown, Family: model.FamilyUnknown,
			Destructive: true},
	}}

	if got := findingsFor(policy.DestructiveChange(contract(nil), graph), policy.RuleDestructiveChange); len(got) != 1 {
		t.Fatalf("findings = %v, want the destruction reported", got)
	}
}

func TestANonDestructiveChangeIsSilent(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.kept", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
			Interpreted: true},
	}}

	result := policy.DestructiveChange(contract(nil), graph)
	if len(result.Findings) != 0 || len(result.Unknowns) != 0 {
		t.Fatalf("findings = %v, unknowns = %v, want neither", result.Findings, result.Unknowns)
	}
}

// ---------------------------------------------------------------------- cloud

func TestADisallowedCloudIsBlocked(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "google_storage_bucket.b", Cloud: model.CloudGCP, Family: model.FamilyObjectStorage,
			Interpreted: true},
	}}

	found := findingsFor(policy.CloudAllowed(contract(nil), graph), policy.RuleCloudNotAllowed)
	if len(found) != 1 {
		t.Fatalf("findings = %v, want one", found)
	}
	if found[0].Disposition != evidence.DispositionBlock {
		t.Errorf("disposition = %q, want BLOCK", found[0].Disposition)
	}
	if len(found[0].Evidence) == 0 {
		t.Error("a blocking finding must locate its source data")
	}
}

func TestAnAllowedCloudIsSilent(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
			Interpreted: true},
	}}

	result := policy.CloudAllowed(contract(nil), graph)
	if len(result.Findings) != 0 || len(result.Unknowns) != 0 {
		t.Fatalf("findings = %v, unknowns = %v, want neither", result.Findings, result.Unknowns)
	}
}

// TestAnUninterpretedCloudIsUnknownNotAllowed is this milestone's form of the
// defect nine rounds of M03 kept finding. A resource no mapper claimed has no
// stated cloud, and an unstated cloud is not evidence that the cloud is one the
// contract allows. Reading it as allowed would let an entire provider the
// contract forbids pass unremarked, simply by being one this build cannot read.
func TestAnUninterpretedCloudIsUnknownNotAllowed(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "oci_objectstorage_bucket.b", Cloud: model.CloudUnknown, Family: model.FamilyUnknown},
	}}

	result := policy.CloudAllowed(contract(nil), graph)

	if len(findingsFor(result, policy.RuleCloudNotAllowed)) != 0 {
		t.Error("an unstated cloud is not proof of a disallowed one either")
	}

	unknowns := unknownsFor(result, policy.CheckCloudDeterminable)
	if len(unknowns) != 1 {
		t.Fatalf("unknowns = %v, want the undetermined cloud reported", result.Unknowns)
	}
	if !unknowns[0].Required {
		t.Error("a cloud that cannot be determined must prevent a PASS, not qualify one")
	}
	if unknowns[0].ResourceAddress == nil || *unknowns[0].ResourceAddress != "oci_objectstorage_bucket.b" {
		t.Errorf("resource address = %v", unknowns[0].ResourceAddress)
	}
}

// TestEachDisallowedCloudIsReportedOnce keeps a plan with fifty buckets in one
// forbidden cloud from producing fifty identical findings. The violation is the
// cloud, not the resource.
func TestEachDisallowedCloudIsReportedOnce(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "google_storage_bucket.a", Cloud: model.CloudGCP, Interpreted: true},
		{Address: "google_storage_bucket.b", Cloud: model.CloudGCP, Interpreted: true},
		{Address: "azurerm_storage_account.c", Cloud: model.CloudAzure, Interpreted: true},
	}}

	found := findingsFor(policy.CloudAllowed(contract(nil), graph), policy.RuleCloudNotAllowed)
	if len(found) != 2 {
		t.Fatalf("findings = %d, want one per disallowed cloud", len(found))
	}
}

// ---------------------------------------------------------------- environment

func TestAProvableEnvironmentMismatchIsBlocked(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Interpreted: true,
			Environment: model.Known("production",
				model.Provenance{ResourceAddress: "aws_s3_bucket.b", AttributePath: "tags.environment", Cloud: model.CloudAWS})},
	}}

	found := findingsFor(policy.EnvironmentMatch(contract(nil), graph), policy.RuleEnvironmentMismatch)
	if len(found) != 1 {
		t.Fatalf("findings = %v, want one", found)
	}
	if found[0].Disposition != evidence.DispositionBlock {
		t.Errorf("disposition = %q, want BLOCK", found[0].Disposition)
	}
	if len(found[0].Evidence) == 0 {
		t.Error("a blocking finding must locate its source data")
	}
}

func TestAMatchingEnvironmentIsSilent(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Interpreted: true,
			Environment: model.Known("staging",
				model.Provenance{ResourceAddress: "aws_s3_bucket.b", AttributePath: "tags.environment"})},
	}}

	result := policy.EnvironmentMatch(contract(nil), graph)
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %v, want none", result.Findings)
	}
}

// TestAnAbsentEnvironmentClaimsNoMismatch is the milestone's own instruction:
// weak hints are reported without claiming a mismatch. A resource carrying no
// environment declaration says nothing about which environment it is in, and
// blocking on that would make every untagged plan a violation.
func TestAnAbsentEnvironmentClaimsNoMismatch(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Interpreted: true},
	}}

	result := policy.EnvironmentMatch(contract(nil), graph)

	if len(result.Findings) != 0 {
		t.Fatalf("findings = %v; absence is not a mismatch", result.Findings)
	}
	unknowns := unknownsFor(result, policy.CheckEnvironmentEvidence)
	if len(unknowns) != 1 {
		t.Fatalf("unknowns = %v, want the missing evidence reported", result.Unknowns)
	}
	if unknowns[0].Required {
		t.Error("an unverifiable environment bounds the evidence; it does not prevent every conclusion")
	}
}

// TestARedactedEnvironmentIsNotAMismatch keeps a sensitive tag from being read
// as a disagreement with the contract. The value was not compared, because it
// was never available to compare.
func TestARedactedEnvironmentIsNotAMismatch(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Interpreted: true,
			Environment: model.Redacted[string](
				model.Provenance{ResourceAddress: "aws_s3_bucket.b", AttributePath: "tags.environment"})},
	}}

	result := policy.EnvironmentMatch(contract(nil), graph)
	if len(result.Findings) != 0 {
		t.Fatalf("findings = %v; a value that was never readable cannot disagree", result.Findings)
	}
	if len(unknownsFor(result, policy.CheckEnvironmentEvidence)) != 1 {
		t.Fatalf("unknowns = %v, want the unreadable evidence reported", result.Unknowns)
	}
}

// ------------------------------------------------------------------- exposure

func TestPrivateIntentBlocksProvablePublicStorage(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{
				PublicAccess: model.Known(true,
					model.Provenance{ResourceAddress: "aws_s3_bucket_acl.b", AttributePath: "acl"})}},
	}}

	found := findingsFor(policy.StorageExposure(contract(nil), graph), policy.RuleStoragePublic)
	if len(found) != 1 {
		t.Fatalf("findings = %v, want one", found)
	}
	if found[0].Disposition != evidence.DispositionBlock {
		t.Errorf("disposition = %q, want BLOCK", found[0].Disposition)
	}
}

// TestPrivateIntentWithUnknownExposureIsUnknown is the milestone's safety
// semantic stated verbatim: private exposure plus unknown public-access
// evidence is UNKNOWN. It is the case that separates this tool from one that
// reports what it happened to understand.
func TestPrivateIntentWithUnknownExposureIsUnknown(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{PublicAccess: model.Unknown[bool]()}},
	}}

	result := policy.StorageExposure(contract(nil), graph)

	if len(result.Findings) != 0 {
		t.Fatalf("findings = %v; an undetermined exposure proves no violation", result.Findings)
	}
	unknowns := unknownsFor(result, policy.CheckStoragePublicDeterminable)
	if len(unknowns) != 1 {
		t.Fatalf("unknowns = %v, want one", result.Unknowns)
	}
	if !unknowns[0].Required {
		t.Error("a private intent whose exposure cannot be determined must not pass")
	}
}

// TestPublicIntentAcceptsPublicStorage keeps the contract meaningful in both
// directions. Exposure the author declared is not a violation.
func TestPublicIntentAcceptsPublicStorage(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{
				PublicAccess: model.Known(true,
					model.Provenance{ResourceAddress: "aws_s3_bucket_acl.b", AttributePath: "acl"})}},
	}}

	result := policy.StorageExposure(contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: "object_storage", Exposure: intent.ExposurePublic}}
	}), graph)

	if len(findingsFor(result, policy.RuleStoragePublic)) != 0 {
		t.Fatalf("findings = %v; declared public exposure is not a violation", result.Findings)
	}
}

// TestPublicIntentWithUnknownExposureDoesNotRequireAnUnknown keeps the required
// unknown tied to what the contract needs proved. An author who declared public
// exposure is not waiting on evidence that it is private.
func TestPublicIntentWithUnknownExposureDoesNotRequireAnUnknown(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{PublicAccess: model.Unknown[bool]()}},
	}}

	result := policy.StorageExposure(contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: "object_storage", Exposure: intent.ExposurePublic}}
	}), graph)

	for _, u := range result.Unknowns {
		if u.Required {
			t.Fatalf("a required unknown was raised for exposure the contract did not require: %v", u)
		}
	}
}

// TestUnspecifiedExposureStillReportsPublicAccess keeps explicit uncertainty
// from silencing the evidence. The author declined to commit to an exposure;
// they did not ask not to be told what the change does.
func TestUnspecifiedExposureStillReportsPublicAccess(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{
				PublicAccess: model.Known(true,
					model.Provenance{ResourceAddress: "aws_s3_bucket_acl.b", AttributePath: "acl"})}},
	}}

	result := policy.StorageExposure(contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: "object_storage", Exposure: intent.ExposureUnspecified}}
	}), graph)

	found := findingsFor(result, policy.RuleStoragePublic)
	if len(found) != 1 {
		t.Fatalf("findings = %v, want the exposure reported", result.Findings)
	}
	if found[0].Disposition != evidence.DispositionWarn {
		t.Errorf("disposition = %q; unspecified exposure needs a human, not a verdict", found[0].Disposition)
	}
}

// TestAFamilyTheContractNeverMentionedIsReportedNotJudged covers a plan that
// does more than the contract described.
//
// The contract here declares a family, and the plan contains a different one.
// An earlier form of this test passed a contract that did mention object
// storage, which made it a weaker duplicate of the test above it and left the
// branch it names untested in both directions: reading an unmentioned family as
// private, and reading it as public — which silences every public-storage
// finding — both survived.
//
// The rule is that silence in the contract is neither permission nor
// prohibition. The exposure is reported so a reader sees what the change does,
// and it is not a violation, because no intent was stated to violate.
func TestAFamilyTheContractNeverMentionedIsReportedNotJudged(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{
				PublicAccess: model.Known(true,
					model.Provenance{ResourceAddress: "aws_s3_bucket_acl.b", AttributePath: "acl"})}},
	}}

	// A contract that addresses some other family, so object storage is a
	// subject it never mentioned.
	unmentioned := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: "message_queue", Exposure: intent.ExposurePrivate}}
	})

	result := policy.StorageExposure(unmentioned, graph)

	found := findingsFor(result, policy.RuleStoragePublic)
	if len(found) != 1 {
		t.Fatalf("findings = %v; a plan doing more than the contract described must still be reported",
			result.Findings)
	}
	if found[0].Disposition != evidence.DispositionWarn {
		t.Errorf("disposition = %q; silence in the contract is not a violation to block on",
			found[0].Disposition)
	}
}

// TestAnUnmentionedFamilyRaisesNoRequiredUnknown keeps the other direction of
// the same branch honest. A contract that never asked for private storage is
// not waiting on evidence that it is private, so an undetermined exposure there
// bounds the report rather than preventing a conclusion.
func TestAnUnmentionedFamilyRaisesNoRequiredUnknown(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{PublicAccess: model.Unknown[bool]()}},
	}}

	unmentioned := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: "message_queue", Exposure: intent.ExposurePrivate}}
	})

	result := policy.StorageExposure(unmentioned, graph)
	for _, unknown := range result.Unknowns {
		if unknown.Required {
			t.Fatalf("a required unknown was raised for an exposure the contract never asked about: %v", unknown)
		}
	}
	if len(result.Unknowns) == 0 {
		t.Fatal("the undetermined exposure must still be recorded")
	}
}

// TestADeclarationThatCannotBeReadPreventsAPass draws the line this rule turns
// on, and it is not where "absent" sits.
//
// A resource carrying no environment tag says nothing about which environment
// it is in. That is the common case, requiring it would make every untagged
// plan UNKNOWN, and docs/INTENT-CONTRACT.md is explicit that it must not block.
//
// A resource that declares an environment this run could not read is a
// different fact. The plan asserts something bearing directly on the question,
// and the run could not evaluate it — which is what a required unknown is for.
// Reading the two the same way would let a resource tagged production, twice
// and contradictorily, report that the change was consistent in every check.
func TestADeclarationThatCannotBeReadPreventsAPass(t *testing.T) {
	source := model.Provenance{ResourceAddress: "aws_s3_bucket.b", AttributePath: "tags.environment"}

	cases := map[string]struct {
		environment model.Fact[string]
		required    bool
	}{
		"no declaration at all": {model.Fact[string]{}, false},
		"declared nothing":      {model.Absent[string](source), false},
		"not yet known":         {model.Unknown[string](source), true},
		"marked sensitive":      {model.Redacted[string](source), true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			graph := model.Graph{Resources: []model.NormalizedResource{
				{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Interpreted: true,
					Environment: tc.environment},
			}}

			result := policy.EnvironmentMatch(contract(nil), graph)
			if len(result.Findings) != 0 {
				t.Fatalf("findings = %v; nothing here proves a mismatch", result.Findings)
			}

			unknowns := unknownsFor(result, policy.CheckEnvironmentEvidence)
			if len(unknowns) != 1 {
				t.Fatalf("unknowns = %v, want one", result.Unknowns)
			}
			if unknowns[0].Required != tc.required {
				t.Errorf("required = %v, want %v: %q",
					unknowns[0].Required, tc.required, unknowns[0].Reason)
			}
			if unknowns[0].Reason == "" {
				t.Error("the gap is named but not explained")
			}
		})
	}
}

// TestTheEnvironmentValueIsComparedExactly pins a choice that was made
// silently and could go either way.
//
// The tag key is matched without regard to case because its capitalization is a
// convention, not a name. The value is a name the author chose, and two
// spellings of it are two names: folding them would let a resource tagged
// Production satisfy a contract written for production, and where those are
// deliberately distinct environments the mismatch this rule exists to find
// would go unreported.
func TestTheEnvironmentValueIsComparedExactly(t *testing.T) {
	cases := map[string]struct {
		declared string
		mismatch bool
	}{
		"the same spelling":     {"staging", false},
		"a different case":      {"Staging", true},
		"a different name":      {"production", true},
		"surrounding space":     {" staging ", false},
		"a different case only": {"STAGING", true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			graph := model.Graph{Resources: []model.NormalizedResource{
				{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Interpreted: true,
					Environment: model.Known(tc.declared, model.Provenance{
						ResourceAddress: "aws_s3_bucket.b", AttributePath: "tags.environment"})},
			}}

			found := findingsFor(policy.EnvironmentMatch(contract(nil), graph), policy.RuleEnvironmentMismatch)
			if got := len(found) == 1; got != tc.mismatch {
				t.Fatalf("mismatch reported = %v, want %v for %q", got, tc.mismatch, tc.declared)
			}
		})
	}
}

// TestAPlanWithNothingToCheckSaysSo closes the one case that produced an
// unqualified PASS with no findings and no unknowns at all.
//
// A contract declaring private object storage, evaluated against a plan
// containing no object storage, reported that the change was consistent in
// every supported check. Nothing was checked. That is the product-level form of
// reading absence as permission: the reader is told the contract held, when in
// truth it never applied to anything.
func TestAPlanWithNothingToCheckSaysSo(t *testing.T) {
	result := policy.ContractCoverage(contract(nil), model.Graph{})

	unknowns := unknownsFor(result, policy.CheckContractFamilyAbsent)
	if len(unknowns) != 1 {
		t.Fatalf("unknowns = %v, want the unexercised declaration reported", result.Unknowns)
	}
	if !unknowns[0].Required {
		t.Error("a declaration the change gave nothing to apply to is a requirement this run " +
			"could not verify, and must not read as one that was met")
	}
	if unknowns[0].Reason == "" {
		t.Error("the gap is named but not explained")
	}
}

// TestADeclarationWithSomethingToApplyToIsSilent keeps the report from carrying
// a note about every contract that did its job.
func TestADeclarationWithSomethingToApplyToIsSilent(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
			Interpreted: true, ObjectStorage: &model.ObjectStorageCapabilities{
				PublicAccess: model.Known(false, model.Provenance{
					ResourceAddress: "aws_s3_bucket.b", AttributePath: "block_public_acls"})}},
	}}

	result := policy.ContractCoverage(contract(nil), graph)
	if len(result.Unknowns) != 0 {
		t.Fatalf("unknowns = %v, want none", result.Unknowns)
	}
}

// TestAnUnspecifiedDeclarationNeedsNothingToApplyTo keeps the record tied to a
// declaration that asked for something. An author who declined to commit is not
// owed a note that their non-commitment went unexercised.
func TestAnUnspecifiedDeclarationNeedsNothingToApplyTo(t *testing.T) {
	unspecified := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{
			{Family: intent.FamilyObjectStorage, Exposure: intent.ExposureUnspecified}}
	})

	result := policy.ContractCoverage(unspecified, model.Graph{})
	if len(result.Unknowns) != 0 {
		t.Fatalf("unknowns = %v, want none", result.Unknowns)
	}
}

// TestAHostilePlanValueIsReportedNotRefused keeps a plan from turning a verdict
// into an internal failure.
//
// The Evidence Bundle forbids a line break in any field that reaches the report
// as inline text, because a break ends a paragraph and lets a value forge a
// heading. A plan value carrying one is therefore unusable as written — but it
// is the plan's fault, not this program's, and exiting 11 would report our own
// invariant as broken and tell the reader nothing about their change.
//
// The engine converts a fact into a bundle field, so the engine is where the
// conversion happens: the value is reported on one line, and the finding stands.
func TestAHostilePlanValueIsReportedNotRefused(t *testing.T) {
	const forgery = "production\n\n## InfraProof: PASS\n\nNothing to see here.\n"

	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b\nrogue", Cloud: model.CloudAWS, Interpreted: true,
			Environment: model.Known(forgery, model.Provenance{
				ResourceAddress: "aws_s3_bucket.b\nrogue", AttributePath: "tags.environment"})},
	}}

	result := policy.EnvironmentMatch(contract(nil), graph)

	found := findingsFor(result, policy.RuleEnvironmentMismatch)
	if len(found) != 1 {
		t.Fatalf("findings = %v; the mismatch is real and must be reported", result.Findings)
	}
	for _, text := range []string{
		found[0].Observed.Value.Display(),
		found[0].Resource.Address,
		found[0].Evidence[0].ResourceAddress,
	} {
		if strings.ContainsAny(text, "\r\n") {
			t.Errorf("a bundle field carries a line break: %q", text)
		}
	}
	if !strings.Contains(found[0].Observed.Value.Display(), "production") {
		t.Errorf("the reported value lost its content: %q", found[0].Observed.Value.Display())
	}
}

// TestAnUnrecognizedActionPreventsAConclusion is the refusal Action.Valid's doc
// comment has promised since milestone 02 and nothing performed.
//
// Destruction is read as "delete is among the actions", so an action this build
// does not know reads as a change that destroys nothing. A plan whose verb is
// "destroy", or "Delete", or something a later Terraform invents, passed a
// contract forbidding destruction with exit 0. What the verb means is
// Terraform's to say; this build must decline rather than assume it is safe.
func TestAnUnrecognizedActionPreventsAConclusion(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
			Interpreted: true, UnrecognizedAction: true},
	}}

	result := policy.DestructiveChange(contract(nil), graph)

	if len(result.Findings) != 0 {
		t.Fatalf("findings = %v; an action this build cannot read proves nothing", result.Findings)
	}
	unknowns := unknownsFor(result, policy.CheckActionRecognized)
	if len(unknowns) != 1 {
		t.Fatalf("unknowns = %v, want the unreadable action reported", result.Unknowns)
	}
	if !unknowns[0].Required {
		t.Error("a change this build cannot read must not pass")
	}
	if unknowns[0].ResourceAddress == nil || *unknowns[0].ResourceAddress != "aws_s3_bucket.b" {
		t.Errorf("the unknown names %v", unknowns[0].ResourceAddress)
	}
}

// TestARecognizedActionIsJudgedNormally keeps the refusal off every ordinary
// change.
func TestARecognizedActionIsJudgedNormally(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.gone", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
			Interpreted: true, Destructive: true},
	}}

	result := policy.DestructiveChange(contract(nil), graph)
	if len(findingsFor(result, policy.RuleDestructiveChange)) != 1 {
		t.Fatalf("findings = %v, want the destruction reported", result.Findings)
	}
	if len(unknownsFor(result, policy.CheckActionRecognized)) != 0 {
		t.Errorf("unknowns = %v, want none", result.Unknowns)
	}
}
