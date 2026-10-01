package policy_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers"
)

// TestRulesDependOnNoProvider turns an acceptance criterion into something the
// build enforces. "The universal rule imports no provider-specific package" is
// a claim a reviewer would otherwise have to re-check by hand every time a rule
// is edited, and it is the claim the whole provider-neutral design rests on.
//
// The check is transitive, because importing a package that imports a provider
// would breach the boundary just as thoroughly.
func TestRulesDependOnNoProvider(t *testing.T) {
	const forbidden = "github.com/mtlabs-eng/infraproof/internal/providers"

	for _, pkg := range []string{
		"github.com/mtlabs-eng/infraproof/internal/policy",
		"github.com/mtlabs-eng/infraproof/internal/model",
		"github.com/mtlabs-eng/infraproof/internal/evidence",
		"github.com/mtlabs-eng/infraproof/internal/render",
	} {
		t.Run(pkg, func(t *testing.T) {
			out, err := exec.Command("go", "list", "-deps", pkg).Output()
			if err != nil {
				t.Fatalf("go list -deps %s: %v", pkg, err)
			}
			for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if strings.HasPrefix(dependency, forbidden) {
					t.Fatalf("%s depends on %s", pkg, dependency)
				}
			}
		})
	}
}

// TestNoRuleDecidesFromACloud closes the route the other two tests cannot see.
//
// Both of those are anchored to the internal/providers prefix: one forbids
// policy from importing anything under it, the other checks what the registry
// reaches within it. Neither notices cloud-specific judgement written one
// directory up — a package internal/awsrules deciding whether a control applies
// to AWS, imported by the policy engine, satisfies both and breaches the design
// completely.
//
// The boundary is about content, not location, and the content that matters is
// narrower than the word. Naming a cloud is not the breach: the Evidence
// Bundle's cloud enumeration is part of its contract, and the intent contract's
// allowed set is data a user writes. Branching on one is the breach — that is a
// rule knowing something only a mapper is allowed to know.
//
// So this looks for comparisons against a particular cloud in executable code,
// in everything the policy engine reaches, and it parses rather than greps, so
// a doc comment mentioning AWS costs nothing.
func TestNoRuleDecidesFromACloud(t *testing.T) {
	clouds := map[string]bool{}
	for _, mapper := range providers.Default() {
		clouds[string(mapper.Cloud())] = true
	}

	for _, pkg := range reachedByPolicy(t) {
		directory := packageDirectory(t, pkg)
		if isMapperOrRegistry(directory, clouds) {
			continue
		}

		set := token.NewFileSet()
		packages, err := parser.ParseDir(set, directory, func(f fs.FileInfo) bool {
			return !strings.HasSuffix(f.Name(), "_test.go")
		}, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", directory, err)
		}

		for _, parsed := range packages {
			ast.Inspect(parsed, func(node ast.Node) bool {
				for _, site := range comparisonSites(node) {
					named := cloudsNamedBy(site, clouds)
					switch {
					case len(named) == 0:
						continue
					case len(named) == len(clouds):
						// Every cloud at one site is a membership test against
						// the closed set, which is what an enumeration is for.
						// Singling one out is the judgement this forbids.
						continue
					}
					t.Errorf("%s decides from %s; that judgement belongs in a mapper",
						set.Position(site[0].Pos()), strings.Join(named, ", "))
				}
				return true
			})
		}
	}
}

// comparisonSites returns each place a value is compared, as the group of
// expressions compared together. Grouping matters: one case clause listing
// every cloud is an enumeration, and the same clause listing one is a decision,
// and only the group tells them apart.
func comparisonSites(node ast.Node) [][]ast.Expr {
	switch typed := node.(type) {
	case *ast.BinaryExpr:
		if typed.Op != token.EQL && typed.Op != token.NEQ {
			return nil
		}
		return [][]ast.Expr{{typed.X, typed.Y}}
	case *ast.SwitchStmt:
		if typed.Tag == nil {
			return nil
		}
		var sites [][]ast.Expr
		for _, statement := range typed.Body.List {
			if clause, ok := statement.(*ast.CaseClause); ok && len(clause.List) > 0 {
				sites = append(sites, clause.List)
			}
		}
		return sites
	default:
		return nil
	}
}

// cloudsNamedBy returns the distinct clouds a comparison site identifies, in
// sorted order so a failure reads the same way twice.
func cloudsNamedBy(site []ast.Expr, clouds map[string]bool) []string {
	found := map[string]bool{}
	for _, expression := range site {
		if cloud, named := namesACloud(expression, clouds); named {
			found[cloud] = true
		}
	}

	names := make([]string, 0, len(found))
	for cloud := range found {
		names = append(names, cloud)
	}
	slices.Sort(names)
	return names
}

// namesACloud reports whether an expression identifies a particular cloud,
// either as a string literal or as a constant named for one. CloudUnknown is
// not a cloud: it is the absence of one, and a rule is required to notice that.
func namesACloud(expression ast.Expr, clouds map[string]bool) (string, bool) {
	switch typed := expression.(type) {
	case *ast.BasicLit:
		if typed.Kind != token.STRING {
			return "", false
		}
		text := strings.ToLower(strings.Trim(typed.Value, `"`))
		return text, clouds[text]
	case *ast.SelectorExpr:
		name := typed.Sel.Name
		for cloud := range clouds {
			if strings.EqualFold(name, "Cloud"+cloud) {
				return cloud, true
			}
		}
	case *ast.Ident:
		for cloud := range clouds {
			if strings.EqualFold(typed.Name, "Cloud"+cloud) {
				return cloud, true
			}
		}
	case *ast.CallExpr:
		// A conversion such as model.Cloud("aws").
		for _, argument := range typed.Args {
			if cloud, named := namesACloud(argument, clouds); named {
				return cloud, true
			}
		}
	}
	return "", false
}

// reachedByPolicy returns this project's packages that the policy engine
// transitively depends on, plus the engine itself.
func reachedByPolicy(t *testing.T) []string {
	t.Helper()

	out, err := exec.Command("go", "list", "-deps",
		"github.com/mtlabs-eng/infraproof/internal/policy").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	var ours []string
	for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(dependency, "github.com/mtlabs-eng/infraproof/") {
			ours = append(ours, dependency)
		}
	}
	if len(ours) < 2 {
		t.Fatalf("expected the policy engine to reach several of our packages, got %v", ours)
	}
	return ours
}

func packageDirectory(t *testing.T, pkg string) string {
	t.Helper()

	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", pkg).Output()
	if err != nil {
		t.Fatalf("go list %s: %v", pkg, err)
	}
	return strings.TrimSpace(string(out))
}

// isMapperOrRegistry reports the directories permitted to decide from a cloud:
// a cloud's own package, and the registry that assembles them.
func isMapperOrRegistry(directory string, clouds map[string]bool) bool {
	for cloud := range clouds {
		if strings.HasSuffix(directory, filepath.Join("providers", cloud)) {
			return true
		}
	}
	return strings.HasSuffix(directory, filepath.Join("internal", "providers"))
}

// TestTheModelDependsOnNothingOfOurs keeps the normalized layer at the bottom.
// If it learned about plans, rules or output, every cloud added later would
// inherit that coupling.
func TestTheModelDependsOnNothingOfOurs(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/mtlabs-eng/infraproof/internal/model").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(dependency, "github.com/mtlabs-eng/infraproof/") &&
			dependency != "github.com/mtlabs-eng/infraproof/internal/model" {
			t.Fatalf("the model depends on %s", dependency)
		}
	}
}

// TestAMapperIsReachableOnlyThroughTheRegistry records where the one place that
// names a cloud is. Adding a fourth cloud must be an entry in the registry and
// a new subpackage, nothing else.
//
// Counting subpackages is not enough on its own: a shared helper under
// internal/providers is legitimate, and a cloud smuggled in as one would be a
// back door through which policy could reach provider knowledge without any
// registry entry. So both halves are checked — every cloud in the registry has
// its own package, and every other reachable subpackage names no cloud at all.
func TestAMapperIsReachableOnlyThroughTheRegistry(t *testing.T) {
	const root = "github.com/mtlabs-eng/infraproof/internal/providers/"

	reachable := subpackagesOf(t, "github.com/mtlabs-eng/infraproof/internal/providers")

	// Derived from the registry rather than hard-coded, so adding a cloud does
	// not require editing the test that proves the boundary holds.
	clouds := map[string]bool{}
	for _, mapper := range providers.Default() {
		clouds[string(mapper.Cloud())] = true

		pkg := root + string(mapper.Cloud())
		if !reachable[pkg] {
			t.Errorf("the registry declares %s but does not reach %s", mapper.Cloud(), pkg)
		}
	}

	for pkg := range reachable {
		if clouds[strings.TrimPrefix(pkg, root)] {
			continue
		}
		// A shared helper. It may be reached, but it must not itself reach a
		// cloud, or it becomes a second route to provider knowledge.
		for dependency := range subpackagesOf(t, pkg) {
			if clouds[strings.TrimPrefix(dependency, root)] {
				t.Errorf("%s is not a cloud package but depends on %s", pkg, dependency)
			}
		}
	}
}

// subpackagesOf returns the packages under internal/providers that a package
// transitively depends on.
func subpackagesOf(t *testing.T, pkg string) map[string]bool {
	t.Helper()

	out, err := exec.Command("go", "list", "-f", "{{join .Deps \"\\n\"}}", pkg).Output()
	if err != nil {
		t.Fatalf("go list %s: %v", pkg, err)
	}

	found := map[string]bool{}
	for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(dependency, "github.com/mtlabs-eng/infraproof/internal/providers/") {
			found[dependency] = true
		}
	}
	return found
}

// TestNoRuleReachesTheFilesystem keeps the layer that decides away from the
// layer that reads configuration.
//
// internal/tfconfig reads .tf files to say where a declaration is written. A
// rule that could reach it would be a rule whose verdict could depend on what a
// file says now, and the milestone that added locations turns on them never being
// load-bearing: a verdict that changed when a file moved would not be a verdict
// about the plan. The check is transitive, for the reason the provider one is.
func TestNoRuleReachesTheFilesystem(t *testing.T) {
	const forbidden = "github.com/mtlabs-eng/infraproof/internal/tfconfig"

	for _, pkg := range []string{
		"github.com/mtlabs-eng/infraproof/internal/policy",
		"github.com/mtlabs-eng/infraproof/internal/model",
		"github.com/mtlabs-eng/infraproof/internal/evidence",
		"github.com/mtlabs-eng/infraproof/internal/render",
		"github.com/mtlabs-eng/infraproof/internal/providers",
	} {
		t.Run(pkg, func(t *testing.T) {
			out, err := exec.Command("go", "list", "-deps", pkg).Output()
			if err != nil {
				t.Fatalf("go list -deps %s: %v", pkg, err)
			}
			for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if strings.HasPrefix(dependency, forbidden) {
					t.Fatalf("%s depends on %s", pkg, dependency)
				}
			}
		})
	}
}

// TestLocatingDependsOnNoProvider holds the new package to the same rule as the
// rest of the core. Where a declaration is written is a question about Terraform
// and about a filesystem; no cloud comes into it.
func TestLocatingDependsOnNoProvider(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/mtlabs-eng/infraproof/internal/tfconfig").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(dependency, "github.com/mtlabs-eng/infraproof/internal/providers") ||
			strings.HasPrefix(dependency, "github.com/mtlabs-eng/infraproof/internal/policy") {
			t.Fatalf("internal/tfconfig depends on %s", dependency)
		}
	}
}
