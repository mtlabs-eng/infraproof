package policy_test

import (
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

// TestAFamilyTheContractNeverMentionedIsReportedNotJudged keeps the tool honest
// about a plan that does more than the contract described.
func TestAFamilyTheContractNeverMentionedIsReportedNotJudged(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{
		{Address: "aws_s3_bucket.b", Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Interpreted: true,
			ObjectStorage: &model.ObjectStorageCapabilities{
				PublicAccess: model.Known(true,
					model.Provenance{ResourceAddress: "aws_s3_bucket_acl.b", AttributePath: "acl"})}},
	}}

	result := policy.StorageExposure(contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: "object_storage", Exposure: intent.ExposureUnspecified}}
	}), graph)

	if len(result.Findings) == 0 {
		t.Fatal("a plan doing more than the contract described must still be reported")
	}
}
