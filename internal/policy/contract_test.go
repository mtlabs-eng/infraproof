package policy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// evaluate runs a provider fixture through the whole pipeline: parse, normalize
// with every registered mapper, and apply the universal rule.
func evaluate(t *testing.T, cloud, fixture string) policy.Result {
	t.Helper()

	path := filepath.Join("..", "providers", cloud, "testdata", fixture+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return policy.StorageExposure(privateStorage, providers.Normalize(plan, providers.Default()))
}

// privateStorage is the contract these tests evaluate against: the one that
// requires private object storage. It is what makes a proven public grant a
// block rather than a warning, and it is stated once here so that every
// scenario below compares the same declared intent.
var privateStorage = intent.Contract{
	SchemaVersion:      "1.0",
	ChangeID:           "contract-test",
	Environment:        "test",
	AllowedClouds:      []string{"aws", "azure", "gcp"},
	DestructiveChanges: intent.DestructiveForbidden,
	Resources: []intent.ResourceIntent{
		{Family: intent.FamilyObjectStorage, Exposure: intent.ExposurePrivate},
	},
}

// scenario names one situation, and where each cloud expresses it.
type scenario struct {
	aws, azure, gcp string
}

// TestOneRuleCoversThreeClouds is the milestone's whole claim. Equivalent
// situations in AWS, Azure and GCP reach the same verdict through one rule that
// names no cloud, and differ only in the evidence the mappers attached.
func TestOneRuleCoversThreeClouds(t *testing.T) {
	public := scenario{"public-acl", "public-blob", "public-iam-member"}
	private := scenario{"private", "private-container", "private-enforced"}
	undetermined := scenario{"unknown-no-controls", "unknown-account-absent", "unknown-inherited-no-grant"}

	t.Run("public everywhere produces one finding", func(t *testing.T) {
		for cloud, fixture := range map[string]string{"aws": public.aws, "azure": public.azure, "gcp": public.gcp} {
			t.Run(cloud, func(t *testing.T) {
				result := evaluate(t, cloud, fixture)

				if len(result.Findings) != 1 {
					t.Fatalf("findings = %d, want 1", len(result.Findings))
				}
				finding := result.Findings[0]
				if finding.RuleID != policy.RuleStoragePublic {
					t.Fatalf("rule id = %q, want %q", finding.RuleID, policy.RuleStoragePublic)
				}
				if finding.Severity != evidence.SeverityCritical {
					t.Fatalf("severity = %q, want %q", finding.Severity, evidence.SeverityCritical)
				}
				if finding.Disposition != evidence.DispositionBlock {
					t.Fatalf("disposition = %q, want %q", finding.Disposition, evidence.DispositionBlock)
				}
				if len(finding.Evidence) == 0 {
					t.Fatal("a blocking finding must carry evidence")
				}
				if string(finding.Resource.Cloud) != cloud {
					t.Fatalf("resource cloud = %q, want %q", finding.Resource.Cloud, cloud)
				}
			})
		}
	})

	t.Run("private everywhere produces none", func(t *testing.T) {
		for cloud, fixture := range map[string]string{"aws": private.aws, "azure": private.azure, "gcp": private.gcp} {
			t.Run(cloud, func(t *testing.T) {
				result := evaluate(t, cloud, fixture)

				if len(result.Findings) != 0 {
					t.Fatalf("findings = %v, want none", result.Findings)
				}
				for _, unknown := range result.Unknowns {
					if unknown.Required {
						t.Fatalf("a private scenario produced a required unknown: %+v", unknown)
					}
				}
			})
		}
	})

	t.Run("a missing control produces a required unknown everywhere", func(t *testing.T) {
		for cloud, fixture := range map[string]string{"aws": undetermined.aws, "azure": undetermined.azure, "gcp": undetermined.gcp} {
			t.Run(cloud, func(t *testing.T) {
				result := evaluate(t, cloud, fixture)

				if len(result.Findings) != 0 {
					t.Fatalf("an undetermined scenario must not produce a finding: %v", result.Findings)
				}
				var required int
				for _, unknown := range result.Unknowns {
					if unknown.Required {
						required++
						if unknown.CheckID != policy.CheckStoragePublicDeterminable {
							t.Fatalf("check id = %q", unknown.CheckID)
						}
					}
				}
				if required != 1 {
					t.Fatalf("required unknowns = %d, want 1", required)
				}
			})
		}
	})
}

// TestEvidenceDiffersPerCloud is the other half of the claim: the verdict is
// shared, the reasoning is not. A finding that pointed at the same attribute in
// all three clouds would mean the normalization had flattened away the thing
// that makes it useful.
func TestEvidenceDiffersPerCloud(t *testing.T) {
	seen := map[string]string{}

	for cloud, fixture := range map[string]string{"aws": "public-acl", "azure": "public-blob", "gcp": "public-iam-member"} {
		result := evaluate(t, cloud, fixture)
		var paths []string
		for _, ref := range result.Findings[0].Evidence {
			paths = append(paths, ref.ResourceAddress+"."+ref.Path)
		}
		seen[cloud] = strings.Join(paths, ",")
		if seen[cloud] == "" {
			t.Fatalf("%s produced no evidence paths", cloud)
		}
	}

	if seen["aws"] == seen["azure"] || seen["azure"] == seen["gcp"] || seen["aws"] == seen["gcp"] {
		t.Fatalf("evidence is identical across clouds, so it explains nothing: %v", seen)
	}
}

// TestAnUnresolvedControlNeverForcesUnknown keeps the two kinds of gap apart. A
// control outside the plan bounds the evidence; it does not prevent a
// conclusion, and must not turn a provable private bucket into an unknown one.
func TestAnUnresolvedControlNeverForcesUnknown(t *testing.T) {
	result := evaluate(t, "aws", "private")

	if len(result.Unknowns) != 1 {
		t.Fatalf("unknowns = %v, want the account-level block alone", result.Unknowns)
	}
	if result.Unknowns[0].Required {
		t.Fatal("an out-of-plan control must be reported without preventing a conclusion")
	}
	if result.Unknowns[0].CheckID != "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK" {
		t.Fatalf("check id = %q", result.Unknowns[0].CheckID)
	}
}

// TestFindingsSatisfyTheEvidenceContract closes the loop with milestone 01: a
// rule's output has to be placeable into a bundle that validates, or the
// contract was never real.
func TestFindingsSatisfyTheEvidenceContract(t *testing.T) {
	result := evaluate(t, "aws", "public-acl")

	bundle := evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionBlock,
		Summary:       "The change grants public access to object storage.",
		Subject: evidence.Subject{
			IntentSource:      "intent.yaml",
			PlanFormatVersion: "1.2",
			PlanDigest:        "sha256:example",
		},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"},
		},
		Findings: result.Findings,
		Unknowns: result.Unknowns,
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("a rule produced findings the Evidence Bundle rejects: %v", err)
	}
}

// TestTheRuleReadsOnlyTheModel is the acceptance criterion made mechanical: the
// rule is given a graph built by hand, with no plan and no mapper anywhere.
func TestTheRuleReadsOnlyTheModel(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{{
		Address:     "invented.resource",
		Provider:    "registry.example.com/vendor/vendor",
		Cloud:       model.Cloud("newcloud"),
		Family:      model.FamilyObjectStorage,
		Interpreted: true,
		ObjectStorage: &model.ObjectStorageCapabilities{
			PublicAccess: model.Known(true, model.Provenance{
				ResourceAddress: "invented.resource",
				AttributePath:   "exposed",
				Cloud:           model.Cloud("newcloud"),
			}),
		},
	}}}

	result := policy.StorageExposure(privateStorage, graph)
	if len(result.Findings) != 1 || result.Findings[0].RuleID != policy.RuleStoragePublic {
		t.Fatalf("a cloud this build has never heard of should still be judged: %v", result.Findings)
	}
}

// TestAFindingFromAnUnknownCloudStillValidates closes the gap between the
// model, which deliberately does not constrain its clouds, and the Evidence
// Bundle, whose cloud enumeration is closed. A finding the bundle refuses is a
// finding that cannot be rendered, so an unrecognized cloud is reported as
// unknown rather than smuggled through.
func TestAFindingFromAnUnknownCloudStillValidates(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{{
		Address:     "invented.resource",
		Provider:    "registry.example.com/vendor/vendor",
		Cloud:       model.Cloud("newcloud"),
		Family:      model.FamilyObjectStorage,
		Interpreted: true,
		ObjectStorage: &model.ObjectStorageCapabilities{
			PublicAccess: model.Known(true, model.Provenance{
				ResourceAddress: "invented.resource",
				AttributePath:   "exposed",
				Cloud:           model.Cloud("newcloud"),
			}),
		},
	}}}

	result := policy.StorageExposure(privateStorage, graph)
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(result.Findings))
	}
	if got := result.Findings[0].Resource.Cloud; got != evidence.CloudUnknown {
		t.Fatalf("cloud = %q, want %q", got, evidence.CloudUnknown)
	}

	bundle := evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionBlock,
		Summary:       "The change grants public access to object storage.",
		Subject: evidence.Subject{
			IntentSource: "intent.yaml", PlanFormatVersion: "1.2", PlanDigest: "sha256:example",
		},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"},
		},
		Findings: result.Findings,
		Unknowns: result.Unknowns,
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("a finding from an unrecognized cloud must still render: %v", err)
	}
}

// TestEveryRegisteredCloudIsCoveredHere keeps this table honest as the registry
// grows. Adding a mapper must not require editing the universal rule — but it
// must require proving the rule still covers it, and a silently skipped cloud
// would let that slide.
func TestEveryRegisteredCloudIsCoveredHere(t *testing.T) {
	covered := map[string]bool{"aws": true, "azure": true, "gcp": true}

	for _, mapper := range providers.Default() {
		cloud := string(mapper.Cloud())
		if !covered[cloud] {
			t.Fatalf("mapper for %q is registered but has no scenarios in this contract test", cloud)
		}
		if _, err := os.Stat(filepath.Join("..", "providers", cloud, "testdata")); err != nil {
			t.Fatalf("mapper for %q has no fixtures: %v", cloud, err)
		}
	}
	if len(providers.Default()) != len(covered) {
		t.Fatalf("registry has %d mappers, this test covers %d", len(providers.Default()), len(covered))
	}
}
