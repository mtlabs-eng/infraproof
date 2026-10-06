package providers_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// TestEveryMissingControlAUnsettledSetReportsIsAsserted covers what an
// independent review found deletable: six of the nine identifiers this family
// introduced could be removed with a green suite, because no test read
// NetworkCapabilities.Unresolved for them.
//
// A missing control is the whole explanation a reader gets for an unknown, and
// the bound on what a finding means when there is one. An identifier nothing
// asserts is an identifier that can fall silent, which is how the milestone came
// to claim "the attachment is reported as a non-required unknown on every
// finding" while GCP reported nothing of the sort.
//
// Each case names the fixture, the cloud and the identifiers that fixture must
// produce. It lives here rather than in a mapper package because the claim is
// about all three clouds agreeing to bound their answers.
func TestEveryMissingControlAnUnsettledSetReportsIsAsserted(t *testing.T) {
	cases := []struct {
		cloud    string
		fixture  string
		resource string
		want     []string
	}{
		// What governs the rule set is never in the plan, in all three clouds.
		{"aws", "sg-public-inline", "aws_security_group.web",
			[]string{"AWS_SECURITY_GROUP_ATTACHMENT_UNKNOWN"}},
		{"azure", "nsg-public-inline", "azurerm_network_security_group.web",
			[]string{"AZURE_NSG_ASSOCIATION_UNKNOWN"}},
		{"gcp", "fw-public", "google_compute_firewall.web",
			[]string{"GCP_FIREWALL_SCOPE_UNKNOWN", "GCP_FIREWALL_DENY_MAY_EXIST_ELSEWHERE"}},

		// A set the plan holds only part of, which is the common case for the
		// two clouds whose rules can be separate resources.
		{"aws", "sg-no-rules", "aws_security_group.web",
			[]string{"AWS_SECURITY_GROUP_RULES_INCOMPLETE"}},
		{"aws", "real-groups", "aws_security_group.norules",
			[]string{"AWS_SECURITY_GROUP_RULES_INCOMPLETE"}},
		{"azure", "nsg-separate-closed", "azurerm_network_security_group.web",
			[]string{"AZURE_NSG_RULES_INCOMPLETE"}},
		{"azure", "nsg-separate-open", "azurerm_network_security_group.web",
			[]string{"AZURE_NSG_RULES_INCOMPLETE"}},

		// Closure proven from an inline set, bounded by the rule resource the
		// provider does not refuse elsewhere.
		{"aws", "sg-closed-inline", "aws_security_group.web",
			[]string{"AWS_SECURITY_GROUP_RULES_MAY_EXIST_ELSEWHERE"}},

		// A source this build cannot resolve.
		{"aws", "sg-prefix-list-inline", "aws_security_group.web",
			[]string{"AWS_SECURITY_GROUP_PREFIX_LIST_UNREAD"}},

		// The approximations, each with its own identifier so that two different
		// reasons cannot hide behind one.
		{"azure", "nsg-deny-partial-protocol", "azurerm_network_security_group.web",
			[]string{"AZURE_NSG_DENY_NARROWER_THAN_ALLOW"}},
		{"azure", "nsg-deny-one-host", "azurerm_network_security_group.web",
			[]string{"AZURE_NSG_DENY_NARROWER_BY_DESTINATION"}},
		{"gcp", "fw-deny-narrow-targets", "google_compute_firewall.web",
			[]string{"GCP_FIREWALL_DENY_NARROWER_BY_TARGET"}},
		{"gcp", "fw-deny-partial-protocol", "google_compute_firewall.web",
			[]string{"GCP_FIREWALL_DENY_NARROWER_BY_PROTOCOL"}},

		// A network the plan has not determined, where nothing can be ordered
		// against anything.
		{"gcp", "fw-unknown-network", "google_compute_firewall.web",
			[]string{"GCP_FIREWALL_NETWORK_UNDETERMINED"}},
	}

	for _, c := range cases {
		t.Run(c.cloud+"/"+c.fixture+"/"+c.resource, func(t *testing.T) {
			found, ok := normalizeFrom(t, c.cloud, c.fixture).At(c.resource)
			if !ok {
				t.Fatalf("fixture %s has no resource at %s", c.fixture, c.resource)
			}
			if found.Network == nil {
				t.Fatal("the resource carries no network capabilities")
			}

			reported := make([]string, 0, len(found.Network.Unresolved))
			for _, control := range found.Network.Unresolved {
				if control.CheckID == "" || control.Reason == "" {
					t.Fatalf("a missing control says nothing: %+v", control)
				}
				if strings.Contains(control.Reason, c.resource) {
					t.Errorf("the reason interpolates a plan value: %q", control.Reason)
				}
				reported = append(reported, control.CheckID)
			}
			for _, want := range c.want {
				if !slices.Contains(reported, want) {
					t.Errorf("%s is not reported; got %v", want, reported)
				}
			}
		})
	}
}

// TestEveryNetworkCheckIdentifierIsAssertedSomewhere is the backstop for the
// table above: adding a tenth identifier without a case for it fails here rather
// than shipping an explanation nothing proves is ever produced.
func TestEveryNetworkCheckIdentifierIsAssertedSomewhere(t *testing.T) {
	declared := map[string]bool{}
	for _, cloud := range []string{"aws", "azure", "gcp"} {
		raw, err := os.ReadFile(filepath.Join("..", "providers", cloud, "network.go"))
		if err != nil {
			t.Fatalf("reading the %s mapper: %v", cloud, err)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			_, after, found := strings.Cut(line, `= "`)
			if !found || !strings.Contains(line, "check") {
				continue
			}
			identifier, _, found := strings.Cut(after, `"`)
			if found && identifier == strings.ToUpper(identifier) && identifier != "" {
				declared[identifier] = true
			}
		}
	}
	if len(declared) == 0 {
		t.Fatal("no check identifiers found, so this test asserts nothing")
	}

	raw, err := os.ReadFile("controls_test.go")
	if err != nil {
		t.Fatalf("reading this test: %v", err)
	}
	for identifier := range declared {
		if !strings.Contains(string(raw), identifier) {
			t.Errorf("%s is declared by a mapper and asserted by no case in the table above", identifier)
		}
	}
}

// normalizeFrom builds the graph of a fixture belonging to one cloud's package.
func normalizeFrom(t *testing.T, cloud, fixture string) model.Graph {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "providers", cloud, "testdata", fixture+".json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return providers.Normalize(plan, providers.Default())
}

// TestEveryInterpretedTypeHasAFamily covers the question FamilyOf exists to
// answer, which no test asked it directly.
//
// The normalizer calls it to place a control resource, and a mapper returning the
// wrong family for a type it interprets files that resource under rules written
// for something else. Mutating one mapper's firewall case to object storage
// survived every test in the suite: a firewall is also a subject, so Map sets the
// family for it and the branch is dead for the one type that was mutated.
//
// So the expected family is named rather than merely required to exist. Asking
// every mapper about every type it admits is what makes the contract hold for the
// next mapper rather than for the three that exist.
func TestEveryInterpretedTypeHasAFamily(t *testing.T) {
	families := map[string]map[string]model.Family{
		"aws": {
			"aws_s3_bucket":                       model.FamilyObjectStorage,
			"aws_s3_bucket_acl":                   model.FamilyObjectStorage,
			"aws_s3_bucket_policy":                model.FamilyObjectStorage,
			"aws_s3_bucket_public_access_block":   model.FamilyObjectStorage,
			"aws_security_group":                  model.FamilyNetwork,
			"aws_vpc_security_group_ingress_rule": model.FamilyNetwork,
		},
		"azure": {
			"azurerm_storage_account":        model.FamilyObjectStorage,
			"azurerm_storage_container":      model.FamilyObjectStorage,
			"azurerm_network_security_group": model.FamilyNetwork,
			"azurerm_network_security_rule":  model.FamilyNetwork,
		},
		"gcp": {
			"google_storage_bucket":             model.FamilyObjectStorage,
			"google_storage_bucket_iam_member":  model.FamilyObjectStorage,
			"google_storage_bucket_iam_binding": model.FamilyObjectStorage,
			"google_storage_bucket_iam_policy":  model.FamilyObjectStorage,
			"google_compute_firewall":           model.FamilyNetwork,
		},
	}

	for _, mapper := range providers.Default() {
		cloud := string(mapper.Cloud())
		expected, known := families[cloud]
		if !known {
			t.Fatalf("the %s mapper is not in this table, so its families are unasserted", cloud)
		}
		for resourceType, want := range expected {
			if !mapper.Interprets(resourceType) {
				t.Errorf("%s: the mapper no longer interprets %s, so this table is stale",
					cloud, resourceType)
				continue
			}
			if got := mapper.FamilyOf(resourceType); got != want {
				t.Errorf("%s: %s is filed under %q, want %q; a control resource of that type would "+
					"be judged by another family's rules", cloud, resourceType, got, want)
			}
		}
	}
}

// TestATypeNoMapperInterpretsHasNoFamily is the other direction: FamilyUnknown
// has to stay the answer for everything else, or a resource nothing understands
// gets filed under a family and judged by its rules.
func TestATypeNoMapperInterpretsHasNoFamily(t *testing.T) {
	for _, mapper := range providers.Default() {
		for _, resourceType := range []string{
			"aws_instance", "azurerm_virtual_machine", "google_compute_instance",
			"aws_s3_bucket_ownership_controls", "", "random_pet",
		} {
			if mapper.Interprets(resourceType) {
				continue
			}
			if family := mapper.FamilyOf(resourceType); family != model.FamilyUnknown {
				t.Errorf("%s: %q is not interpreted and was filed under %q",
					mapper.Cloud(), resourceType, family)
			}
		}
	}
}
