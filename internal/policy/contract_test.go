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
			PlanDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			IntentDigest:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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
			IntentSource: "intent.yaml", PlanFormatVersion: "1.2", PlanDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			IntentDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
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

// evaluateNetwork runs a provider fixture through the whole pipeline and applies
// the universal ingress rule to it.
func evaluateNetwork(t *testing.T, cloud, fixture string, declared intent.Contract) policy.Result {
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
	return policy.NetworkExposure(declared, providers.Normalize(plan, providers.Default()))
}

// declaringPort is the contract these tests evaluate against: the one that
// declares a single public port. It is what makes an open 22 a block rather than
// a warning, and it is stated once so every cloud below is compared against the
// same declared intent.
func declaringPort() intent.Contract {
	ports := []model.PortRange{{From: 443, To: 443}}
	return intent.Contract{
		SchemaVersion:      "1.1",
		ChangeID:           "contract-test",
		Environment:        "test",
		AllowedClouds:      []string{"aws", "azure", "gcp"},
		DestructiveChanges: intent.DestructiveForbidden,
		Resources: []intent.ResourceIntent{
			{Family: intent.FamilyNetwork, PublicPorts: &ports},
		},
	}
}

// TestOneRuleCoversThreeCloudsForIngress is this milestone's whole claim, and the
// harder half of the architecture's bet.
//
// Storage was the easy case: each control said one thing and the mapper combined
// them. Here two of the three clouds have priority and deny rules, so no single
// rule decides anything and the verdict is about an ordered set — and the three
// disagree about the ordering itself. GCP gives a deny precedence at equal
// priority, Azure forbids the tie, AWS has no denies at all.
//
// If the bet holds, none of that reaches the rule. Equivalent situations produce
// one finding with the same identifier, severity and disposition, and differ only
// in the evidence the mappers attached.
func TestOneRuleCoversThreeCloudsForIngress(t *testing.T) {
	open := scenario{"sg-public-inline", "nsg-public-inline", "fw-public"}
	closed := scenario{"sg-closed-inline", "nsg-closed-inline", "fw-closed"}
	// The same situation in each cloud: a rule that permits ingress from any
	// address, and a deny below it that takes it away.
	denied := scenario{"", "nsg-denied-below", "fw-denied-lower"}
	undetermined := scenario{"sg-no-rules", "nsg-no-rules", "fw-unknown-source"}

	clouds := func(s scenario) map[string]string {
		out := map[string]string{"azure": s.azure, "gcp": s.gcp}
		if s.aws != "" {
			out["aws"] = s.aws
		}
		return out
	}

	t.Run("public everywhere produces one finding", func(t *testing.T) {
		var seen []evidence.Finding
		for cloud, fixture := range clouds(open) {
			t.Run(cloud, func(t *testing.T) {
				result := evaluateNetwork(t, cloud, fixture, declaringPort())

				findings := findingsFor(result, policy.RuleNetworkPublicIngress)
				if len(findings) != 1 {
					t.Fatalf("findings = %d, want 1: %+v", len(findings), findings)
				}
				finding := findings[0]
				if finding.Severity != evidence.SeverityHigh {
					t.Errorf("severity = %q, want HIGH", finding.Severity)
				}
				if finding.Disposition != evidence.DispositionBlock {
					t.Errorf("disposition = %q, want BLOCK", finding.Disposition)
				}
				if finding.Observed == nil || finding.Observed.Value.Display() != "tcp/22" {
					t.Errorf("observed = %+v, want tcp/22 in every cloud", finding.Observed)
				}
				// The evidence is the part that must differ: each cloud names
				// its own attributes, and a rule that produced identical
				// evidence everywhere would be one that read nothing.
				if len(finding.Evidence) == 0 {
					t.Fatal("the finding cites nothing")
				}
				for _, ref := range finding.Evidence {
					if ref.ResourceAddress == "" || ref.Path == "" {
						t.Errorf("a reference locates nothing: %+v", ref)
					}
				}
				seen = append(seen, finding)
			})
		}

		if len(seen) < 3 {
			t.Fatalf("only %d clouds were compared", len(seen))
		}
		for _, finding := range seen {
			if finding.RuleID != seen[0].RuleID || finding.Severity != seen[0].Severity ||
				finding.Disposition != seen[0].Disposition {
				t.Fatalf("the clouds reached different verdicts: %+v and %+v", seen[0], finding)
			}
		}
		// And the evidence genuinely differs, or "cloud-specific evidence" is a
		// claim nothing checks.
		if seen[0].Evidence[0].ResourceAddress == seen[1].Evidence[0].ResourceAddress {
			t.Fatalf("two clouds cited the same resource: %q", seen[0].Evidence[0].ResourceAddress)
		}
	})

	t.Run("closed everywhere produces none", func(t *testing.T) {
		for cloud, fixture := range clouds(closed) {
			t.Run(cloud, func(t *testing.T) {
				result := evaluateNetwork(t, cloud, fixture, declaringPort())

				if findings := findingsFor(result, policy.RuleNetworkPublicIngress); len(findings) != 0 {
					t.Fatalf("a closed rule set produced %+v", findings)
				}
				if unknowns := unknownsFor(result, policy.CheckNetworkIngressDeterminable); len(unknowns) != 0 {
					t.Fatalf("a closed rule set produced %+v", unknowns)
				}
			})
		}
	})

	t.Run("a deny below the allow produces none", func(t *testing.T) {
		// Only the two clouds that have denies. AWS is not missing a case here:
		// its rules are an allow-only union, and a fixture pretending otherwise
		// would be testing a cloud that does not exist.
		for cloud, fixture := range clouds(denied) {
			t.Run(cloud, func(t *testing.T) {
				result := evaluateNetwork(t, cloud, fixture, declaringPort())

				if findings := findingsFor(result, policy.RuleNetworkPublicIngress); len(findings) != 0 {
					t.Fatalf("a denied rule produced %+v", findings)
				}
			})
		}
	})

	t.Run("an unsettled set is unknown everywhere", func(t *testing.T) {
		for cloud, fixture := range clouds(undetermined) {
			t.Run(cloud, func(t *testing.T) {
				result := evaluateNetwork(t, cloud, fixture, declaringPort())

				unknowns := unknownsFor(result, policy.CheckNetworkIngressDeterminable)
				if len(unknowns) != 1 {
					t.Fatalf("unknowns = %d, want 1: %+v", len(unknowns), unknowns)
				}
				if !unknowns[0].Required {
					t.Error("a declaration is waiting on this and the unknown does not prevent a pass")
				}
				if len(findingsFor(result, policy.RuleNetworkPublicIngress)) != 0 {
					t.Error("an unsettled set produced a finding")
				}
			})
		}
	})

	t.Run("a value the parser could not read is unknown everywhere", func(t *testing.T) {
		// One field per cloud that the plan states and this build cannot read.
		// Each fixture differs from its open twin in that one field, so what the
		// unknown is caused by is not in doubt.
		unreadable := scenario{"sg-unreadable-protocol", "nsg-unreadable-port", "fw-unreadable-port"}
		for cloud, fixture := range clouds(unreadable) {
			t.Run(cloud, func(t *testing.T) {
				result := evaluateNetwork(t, cloud, fixture, declaringPort())

				if unknowns := unknownsFor(result, policy.CheckNetworkIngressDeterminable); len(unknowns) != 1 {
					t.Fatalf("unknowns = %d, want 1: %+v", len(unknowns), unknowns)
				}
				if findings := findingsFor(result, policy.RuleNetworkPublicIngress); len(findings) != 0 {
					t.Fatalf("an unreadable value produced %+v", findings)
				}
			})
		}
	})

	t.Run("the declaration changes the disposition and not the finding", func(t *testing.T) {
		for cloud, fixture := range clouds(open) {
			t.Run(cloud, func(t *testing.T) {
				undeclared := declaringPort()
				undeclared.Resources = nil

				blocked := findingsFor(evaluateNetwork(t, cloud, fixture, declaringPort()),
					policy.RuleNetworkPublicIngress)
				warned := findingsFor(evaluateNetwork(t, cloud, fixture, undeclared),
					policy.RuleNetworkPublicIngress)

				if len(blocked) != 1 || len(warned) != 1 {
					t.Fatalf("findings = %d and %d, want one each", len(blocked), len(warned))
				}
				if blocked[0].Disposition != evidence.DispositionBlock ||
					warned[0].Disposition != evidence.DispositionWarn {
					t.Fatalf("dispositions = %q and %q, want BLOCK and WARN",
						blocked[0].Disposition, warned[0].Disposition)
				}
				if blocked[0].RuleID != warned[0].RuleID || blocked[0].Severity != warned[0].Severity {
					t.Error("the contract changed the finding and not only its disposition")
				}
				if blocked[0].Observed.Value.Display() != warned[0].Observed.Value.Display() {
					t.Error("the contract changed what was observed, which is a fact about the plan")
				}
			})
		}
	})
}

// TestAddingAMapperDoesNotTouchTheRule covers the criterion mechanically rather
// than by inspection: the rule is applied to every network fixture every mapper
// produces, and what it reads is the normalized capability alone.
//
// A fourth cloud would add fixtures here and change nothing else. The test that
// would fail if it did is the import boundary one, and this is the other half:
// the rule reaches a verdict for each cloud without naming any.
func TestAddingAMapperDoesNotTouchTheRule(t *testing.T) {
	// One scenario per row, and the verdict the rule must reach for it whatever
	// cloud states it. The contract declares one port, so an open 22 exceeds it
	// and a port-less protocol is a question it cannot answer.
	//
	// The previous version of this test counted verdicts and compared none. It
	// asserted that something was judged, which is satisfied by a rule that
	// reaches a different answer in every cloud -- the one thing it exists to
	// rule out.
	scenarios := []struct {
		name        string
		fixtures    map[string]string
		disposition evidence.Disposition
		observed    string
	}{{
		name:        "a port open to any address that the contract does not declare",
		fixtures:    map[string]string{"aws": "sg-public-inline", "azure": "nsg-public-inline", "gcp": "fw-public"},
		disposition: evidence.DispositionBlock,
		observed:    "tcp/22",
	}, {
		name:        "a protocol with no ports",
		fixtures:    map[string]string{"aws": "sg-icmp", "azure": "nsg-icmp", "gcp": "fw-icmp"},
		disposition: evidence.DispositionWarn,
		observed:    "icmp",
	}, {
		name:        "every protocol on every port",
		fixtures:    map[string]string{"aws": "sg-every-protocol", "azure": "nsg-every-protocol", "gcp": "fw-every-protocol"},
		disposition: evidence.DispositionBlock,
		observed:    "every/0-65535",
	}}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			for cloud, fixture := range scenario.fixtures {
				result := evaluateNetwork(t, cloud, fixture, declaringPort())

				if len(result.Evaluated) == 0 {
					t.Fatalf("%s/%s: the rule judged nothing, so coverage would report it unjudged",
						cloud, fixture)
				}
				if len(result.Findings) != 1 {
					t.Fatalf("%s/%s: %d findings, want one", cloud, fixture, len(result.Findings))
				}
				finding := result.Findings[0]
				if finding.RuleID != policy.RuleNetworkPublicIngress {
					t.Errorf("%s/%s: rule %q", cloud, fixture, finding.RuleID)
				}
				if finding.Severity != evidence.SeverityHigh {
					t.Errorf("%s/%s: severity %q, want %q", cloud, fixture,
						finding.Severity, evidence.SeverityHigh)
				}
				if finding.Disposition != scenario.disposition {
					t.Errorf("%s/%s: disposition %q, want %q", cloud, fixture,
						finding.Disposition, scenario.disposition)
				}
				if finding.Observed == nil {
					t.Fatalf("%s/%s: the finding observes nothing", cloud, fixture)
				}
				if got := finding.Observed.Value.Display(); got != scenario.observed {
					t.Errorf("%s/%s: observed %q, want %q", cloud, fixture, got, scenario.observed)
				}
				// The evidence is the one thing that must differ: it names this
				// cloud's own attributes, which is how the rule stays ignorant
				// of them.
				//
				// Named, not merely non-empty. The first version checked that
				// the fields were set, and a mapper citing `ingress[0].access`
				// on an Azure network security group -- an attribute that does
				// not exist on that type -- shipped a BLOCK whose evidence led a
				// reader into the plan to find nothing, with the whole suite
				// green.
				if len(finding.Evidence) == 0 {
					t.Errorf("%s/%s: the finding cites nothing", cloud, fixture)
				}
				for _, ref := range finding.Evidence {
					if ref.ResourceAddress == "" || ref.Path == "" {
						t.Errorf("%s/%s: a citation names no attribute: %+v", cloud, fixture, ref)
						continue
					}
					root := strings.FieldsFunc(ref.Path, func(r rune) bool {
						return r == '.' || r == '['
					})
					if len(root) == 0 || !citable[cloud][root[0]] {
						t.Errorf("%s/%s: the evidence cites %q, which is not an attribute this "+
							"cloud's resources have; a reader following it finds nothing",
							cloud, fixture, ref.Path)
					}
				}
			}
		})
	}

	// And the closed case, where no cloud may produce a finding at all.
	for cloud, fixture := range map[string]string{
		"aws": "sg-closed-inline", "azure": "nsg-closed-inline", "gcp": "fw-closed",
	} {
		result := evaluateNetwork(t, cloud, fixture, declaringPort())
		if len(result.Findings) != 0 {
			t.Errorf("%s/%s: a closed set produced %d findings", cloud, fixture, len(result.Findings))
		}
		if len(result.Evaluated) == 0 {
			t.Errorf("%s/%s: a closed set was not judged", cloud, fixture)
		}
	}
}

// citable is the attributes each cloud's mappers may name in evidence, by their
// root. It is written out rather than derived, because deriving it from the
// mappers would make the assertion agree with whatever they do.
//
// A reader follows a citation into the plan, so a path whose root is not an
// attribute of that cloud's resources is a dead end -- and `ingress[0].access`
// on an Azure network security group is exactly that.
var citable = map[string]map[string]bool{
	"aws": {
		"ingress": true, "protocol": true, "from_port": true, "to_port": true,
		"cidr_blocks": true, "ipv6_cidr_blocks": true, "prefix_list_ids": true,
		"ip_protocol": true, "cidr_ipv4": true, "cidr_ipv6": true, "prefix_list_id": true,
		"tags": true,
	},
	"azure": {
		"security_rule": true, "priority": true, "access": true, "direction": true,
		"protocol": true, "source_address_prefix": true, "source_address_prefixes": true,
		"destination_port_range": true, "destination_port_ranges": true,
		"destination_address_prefix": true, "destination_address_prefixes": true,
		"tags": true,
	},
	"gcp": {
		"allow": true, "deny": true, "priority": true, "direction": true, "disabled": true,
		"source_ranges": true, "source_tags": true, "source_service_accounts": true,
		"target_tags": true, "target_service_accounts": true, "network": true,
		"labels": true,
	},
}

// evaluateDatabase runs the database rule over a cloud's fixture, so the three
// are compared against one declared intent.
func evaluateDatabase(t *testing.T, cloud, fixture string, declared intent.Contract) policy.Result {
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
	return policy.DatabaseExposure(declared, providers.Normalize(plan, providers.Default()))
}

// requiringPrivate is the contract the database cases are judged against: one
// that asks for private databases, stated once so every cloud is compared
// against the same intent.
func requiringPrivate() intent.Contract {
	return intent.Contract{
		SchemaVersion:      "1.2",
		ChangeID:           "contract-test",
		Environment:        "test",
		AllowedClouds:      []string{"aws", "azure", "gcp"},
		DestructiveChanges: intent.DestructiveForbidden,
		Resources: []intent.ResourceIntent{
			{Family: intent.FamilyDatabase, Exposure: intent.ExposurePrivate},
		},
	}
}

// TestOneRuleCoversThreeCloudsForDatabases is this milestone's claim, and the
// harder version of the one milestone 08 made.
//
// There the three clouds disagreed about the machinery of a single question --
// an ordered rule set, resolved in the mapper. Here they disagree about *where
// the answer lives*: AWS keeps the allow list in a security group that another
// family judges, Azure keeps it in the server's own control resources, GCP keeps
// it in an attribute. Three shapes, and one rule that names none of them.
//
// The scenarios are equivalent, not identical: each cloud's fixture is the
// idiomatic way to write that scenario in that cloud, which is the only
// comparison worth making.
func TestOneRuleCoversThreeCloudsForDatabases(t *testing.T) {
	t.Run("reachable everywhere produces one finding", func(t *testing.T) {
		fixtures := map[string]struct{ fixture, resource string }{
			"aws":   {"real-databases", "aws_db_instance.reachable"},
			"azure": {"sql-reachable", "azurerm_mssql_server.db"},
			"gcp":   {"real-databases", "google_sql_database_instance.reachable"},
		}

		for cloud, where := range fixtures {
			result := evaluateDatabase(t, cloud, where.fixture, requiringPrivate())

			var found *evidence.Finding
			for i := range result.Findings {
				if result.Findings[i].Resource != nil &&
					result.Findings[i].Resource.Address == where.resource {
					found = &result.Findings[i]
				}
			}
			if found == nil {
				t.Fatalf("%s: no finding about %s; the rule did not see a reachable database",
					cloud, where.resource)
			}
			if found.RuleID != policy.RuleDatabasePublicReachable {
				t.Errorf("%s: rule = %q, want %q", cloud, found.RuleID,
					policy.RuleDatabasePublicReachable)
			}
			if found.Severity != evidence.SeverityHigh {
				t.Errorf("%s: severity = %q, want %q; impact does not depend on the cloud",
					cloud, found.Severity, evidence.SeverityHigh)
			}
			if found.Disposition != evidence.DispositionBlock {
				t.Errorf("%s: disposition = %q, want %q", cloud, found.Disposition,
					evidence.DispositionBlock)
			}
			if found.Observed == nil || found.Observed.Value.Display() != "true" {
				t.Errorf("%s: observed = %v, want the same fact in every cloud", cloud, found.Observed)
			}
			// The evidence is the one thing that must differ: it names this
			// cloud's own attributes, which is how the rule stays ignorant of
			// them.
			if len(found.Evidence) == 0 {
				t.Errorf("%s: the finding cites nothing", cloud)
			}
			for _, ref := range found.Evidence {
				if ref.ResourceAddress == "" || ref.Path == "" {
					t.Errorf("%s: a citation names no attribute: %+v", cloud, ref)
				}
			}
		}
	})

	t.Run("private everywhere produces none", func(t *testing.T) {
		fixtures := map[string]struct{ fixture, resource string }{
			"aws":   {"real-databases", "aws_db_instance.private"},
			"azure": {"sql-no-endpoint", "azurerm_mssql_server.db"},
			"gcp":   {"real-databases", "google_sql_database_instance.no_endpoint"},
		}

		for cloud, where := range fixtures {
			result := evaluateDatabase(t, cloud, where.fixture, requiringPrivate())
			for _, finding := range result.Findings {
				if finding.Resource != nil && finding.Resource.Address == where.resource {
					t.Errorf("%s: a database with no public endpoint produced %q",
						cloud, finding.Claim)
				}
			}
		}
	})

	t.Run("an endpoint nobody is admitted to produces none", func(t *testing.T) {
		// Each cloud's own way of writing "a public endpoint that nothing
		// reaches": a closed security group, a one-office range, an empty
		// authorized-network list.
		fixtures := map[string]struct{ fixture, resource string }{
			"aws":   {"real-databases", "aws_db_instance.endpoint_closed_group"},
			"azure": {"sql-one-office", "azurerm_mssql_server.db"},
			"gcp":   {"real-databases", "google_sql_database_instance.endpoint_only"},
		}

		for cloud, where := range fixtures {
			result := evaluateDatabase(t, cloud, where.fixture, requiringPrivate())
			for _, finding := range result.Findings {
				if finding.Resource != nil && finding.Resource.Address == where.resource {
					t.Errorf("%s: an endpoint nobody is admitted to produced %q",
						cloud, finding.Claim)
				}
			}
			// Whether it is *settled* rather than merely unreported differs by
			// cloud, and the difference is real rather than an inconsistency.
			// GCP keeps its allow list in an attribute, so a readable instance
			// has the whole list and closure is provable. Azure's rules are
			// always separate resources -- there is no inline form -- so the
			// plan never holds the whole set and closure is never provable.
			// AWS is in between: the groups are correlated by reference, and a
			// group named by identifier leaves no trace, so a proven closure is
			// bounded rather than absolute.
			var undetermined bool
			for _, unknown := range result.Unknowns {
				if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable &&
					unknown.ResourceAddress != nil && *unknown.ResourceAddress == where.resource {
					undetermined = true
				}
			}
			if settles := cloud != "azure"; settles == undetermined {
				t.Errorf("%s: settled = %v, want %v; the clouds differ in whether this is "+
					"provable and the test has to say which", cloud, !undetermined, settles)
			}
		}
	})

	t.Run("the declared exposure changes the disposition and not the finding", func(t *testing.T) {
		public := requiringPrivate()
		public.Resources[0].Exposure = intent.ExposurePublic

		for cloud, fixture := range map[string]string{
			"aws": "real-databases", "azure": "sql-reachable", "gcp": "real-databases",
		} {
			blocked := evaluateDatabase(t, cloud, fixture, requiringPrivate())
			allowed := evaluateDatabase(t, cloud, fixture, public)

			if len(blocked.Findings) == 0 {
				t.Fatalf("%s: the private contract produced no finding", cloud)
			}
			// Reported, at a disposition that affects no decision. This
			// asserted zero findings, which is the milestone's criterion 9 read
			// backwards: the declaration changes the disposition and not whether
			// the change is reported. A declaration covers every database in the
			// plan and cannot be scoped, so an entry written for one
			// intentionally public database silenced the rest.
			if len(allowed.Findings) != len(blocked.Findings) {
				t.Errorf("%s: declaring the exposure public changed the findings "+
					"from %d to %d, and it may change only their disposition",
					cloud, len(blocked.Findings), len(allowed.Findings))
			}
			for _, finding := range allowed.Findings {
				if finding.Disposition != evidence.DispositionInfo {
					t.Errorf("%s: disposition = %q under a public declaration, want INFO",
						cloud, finding.Disposition)
				}
			}
			for _, finding := range blocked.Findings {
				if finding.Severity != evidence.SeverityHigh {
					t.Errorf("%s: severity depends on the contract", cloud)
				}
			}
		}
	})
}

// TestAddingADatabaseMapperDoesNotTouchTheRule is criterion 3 of this milestone,
// and the thing the import boundary cannot prove on its own: the rule reaches a
// verdict in every cloud without naming one.
func TestAddingADatabaseMapperDoesNotTouchTheRule(t *testing.T) {
	judged := map[string]int{}
	for cloud, fixtures := range map[string][]string{
		"aws":   {"real-databases", "real-aurora-defaults"},
		"azure": {"sql-reachable", "sql-no-rules", "pg-reachable"},
		"gcp":   {"real-databases", "real-databases-unreadable"},
	} {
		for _, fixture := range fixtures {
			result := evaluateDatabase(t, cloud, fixture, requiringPrivate())
			if len(result.Evaluated) == 0 {
				t.Errorf("%s/%s: the rule judged nothing, so coverage would report it unjudged",
					cloud, fixture)
			}
			judged[cloud] += len(result.Evaluated)
		}
	}
	for _, cloud := range []string{"aws", "azure", "gcp"} {
		if judged[cloud] == 0 {
			t.Errorf("the rule reached no verdict in %s", cloud)
		}
	}
}
