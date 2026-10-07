package providers_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
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

		// The database family. Its allow list is another subject's verdict, so
		// what it leaves unresolved is which subject, or that there is none this
		// plan can name.
		{"aws", "real-databases", "aws_db_instance.no_group",
			[]string{"AWS_DATABASE_SECURITY_GROUPS_UNKNOWN"}},
		{"aws", "real-databases", "aws_db_instance.unnameable_engine",
			[]string{"AWS_DATABASE_ENGINE_UNREADABLE"}},
		{"aws", "rds-cluster-elsewhere", "aws_rds_cluster_instance.aurora",
			[]string{"AWS_DATABASE_CLUSTER_NOT_IN_PLAN"}},
		{"azure", "sql-no-rules", "azurerm_mssql_server.db",
			[]string{"AZURE_DATABASE_FIREWALL_RULES_INCOMPLETE"}},
		{"azure", "sql-unreadable-range", "azurerm_mssql_server.db",
			[]string{"AZURE_DATABASE_FIREWALL_RANGE_UNREADABLE"}},
		{"azure", "sql-switch-absent", "azurerm_mssql_server.db",
			[]string{"AZURE_DATABASE_PUBLIC_ACCESS_UNDETERMINED"}},
		{"gcp", "real-databases-unreadable", "google_sql_database_instance.version_unreadable",
			[]string{"GCP_SQL_DATABASE_VERSION_UNREADABLE"}},
		{"gcp", "real-databases-unreadable", "google_sql_database_instance.network_unreadable",
			[]string{"GCP_SQL_AUTHORIZED_NETWORK_UNREADABLE"}},
		{"gcp", "sql-cloned", "google_sql_database_instance.cloned",
			[]string{"GCP_SQL_IP_CONFIGURATION_UNREADABLE"}},
	}

	for _, c := range cases {
		t.Run(c.cloud+"/"+c.fixture+"/"+c.resource, func(t *testing.T) {
			found, ok := normalizeFrom(t, c.cloud, c.fixture).At(c.resource)
			if !ok {
				t.Fatalf("fixture %s has no resource at %s", c.fixture, c.resource)
			}
			unresolved := unresolvedOf(found)
			if unresolved == nil {
				t.Fatalf("the resource carries no capabilities of any family")
			}

			reported := make([]string, 0, len(unresolved))
			for _, control := range unresolved {
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
// table above: adding an identifier without a case for it fails here rather than
// shipping an explanation nothing proves is ever produced.
//
// Three things it got wrong at first, each found by a review writing an
// identifier the obvious way. It only considered lines containing the lowercase
// word "check", so an identifier written inline at the use site -- `CheckID:
// "GCP_..."` -- was invisible. It only read network.go, so moving one to another
// file in the same package hid it. And it searched this file as one blob, so a
// mention in a comment satisfied the assertion.
func TestEveryNetworkCheckIdentifierIsAssertedSomewhere(t *testing.T) {
	declared := map[string]string{}
	for _, cloud := range []string{"aws", "azure", "gcp"} {
		paths, err := filepath.Glob(filepath.Join("..", "providers", cloud, "*.go"))
		if err != nil {
			t.Fatalf("listing the %s mapper: %v", cloud, err)
		}
		var read int
		for _, path := range paths {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			read++
			for _, identifier := range checkIdentifiers(string(raw)) {
				declared[identifier] = filepath.Base(path)
			}
		}
		if read == 0 {
			t.Fatalf("no %s mapper source was read, so nothing is asserted", cloud)
		}
	}
	if len(declared) < 10 {
		t.Fatalf("found %d check identifiers, which is too few to be the set: %v",
			len(declared), declared)
	}

	asserted := assertedIdentifiers(t)
	for identifier, file := range declared {
		if !asserted[identifier] {
			t.Errorf("%s declares %s and no test anywhere names it, so the explanation a reader "+
				"gets for an unknown can be deleted with a green suite", file, identifier)
		}
	}
}

// checkIdentifiers finds the check identifiers a mapper declares, by their shape
// rather than by the name of the constant holding them.
//
// A check identifier is an upper-case, underscore-separated string literal
// naming a cloud. Matching on the surrounding code is what let one written at
// the use site go unseen.
func checkIdentifiers(source string) []string {
	var found []string
	for _, match := range identifierPattern.FindAllStringSubmatch(source, -1) {
		found = append(found, match[1])
	}
	return found
}

var identifierPattern = regexp.MustCompile(`"((?:AWS|AZURE|GCP)_[A-Z0-9_]+)"`)

// assertedIdentifiers reads every check identifier any test in this repository
// names, from the parsed source rather than from the text.
//
// Parsed, because a mention in a comment is not an assertion and a review
// silenced an earlier version of this backstop with one comment line. Every test
// rather than this file, because the question is whether anything defends the
// identifier -- the storage family's are asserted where the storage family is
// tested, and a network one moved into another test must keep counting.
func assertedIdentifiers(t *testing.T) map[string]bool {
	t.Helper()

	asserted := map[string]bool{}
	root := filepath.Join("..", "..", "internal")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			// A test that does not parse is the build's problem, not this
			// walk's, and go test would have said so first.
			return nil
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			text, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			if identifierPattern.MatchString(`"` + text + `"`) {
				asserted[text] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tests: %v", err)
	}
	if len(asserted) == 0 {
		t.Fatal("no check identifier is named by any test, so this backstop asserts nothing")
	}
	return asserted
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

// unresolvedOf returns the missing controls a resource reports, whichever family
// it belongs to.
//
// The table above read Network directly, which was right while only the network
// family reported controls and became a reason to skip a third family's
// identifiers the moment one existed. Exactly one capability is set on a subject
// this build understands, so there is nothing to choose between.
func unresolvedOf(found model.NormalizedResource) []model.MissingControl {
	switch {
	case found.Network != nil:
		return found.Network.Unresolved
	case found.ObjectStorage != nil:
		return found.ObjectStorage.Unresolved
	case found.Database != nil:
		return found.Database.Unresolved
	default:
		return nil
	}
}

// TestASubjectCarryingItsOwnVerdictIsNotReadAsDeferring covers a guard whose own
// comment says "every family is asked" and that asked two.
//
// A subject with no capability has deferred to something, and coverage then goes
// looking for what. A database subject carries its own, so leaving it out of the
// test made every database look like a resource that deferred -- inert while no
// binding joins a database to another subject, and a trap for the next one.
func TestASubjectCarryingItsOwnVerdictIsNotReadAsDeferring(t *testing.T) {
	cases := map[string]struct{ cloud, fixture, resource string }{
		"a bucket":         {"aws", "public-acl", "aws_s3_bucket.assets"},
		"a security group": {"aws", "sg-public-inline", "aws_security_group.web"},
		"a database":       {"aws", "real-databases", "aws_db_instance.reachable"},
		"a Cloud SQL instance": {"gcp", "real-databases",
			"google_sql_database_instance.reachable"},
		"an Azure server": {"azure", "sql-reachable", "azurerm_mssql_server.db"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			found, ok := normalizeFrom(t, c.cloud, c.fixture).At(c.resource)
			if !ok {
				t.Fatalf("fixture %s has no resource at %s", c.fixture, c.resource)
			}
			if unresolvedOf(found) == nil && found.ObjectStorage == nil &&
				found.Network == nil && found.Database == nil {
				t.Fatal("the subject carries no capability of any family")
			}
			if len(found.DefersTo) != 0 {
				t.Errorf("a subject carrying its own verdict defers to %v", found.DefersTo)
			}
		})
	}
}
