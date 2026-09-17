package policy_test

import (
	"os/exec"
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
