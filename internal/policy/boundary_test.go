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
func TestAMapperIsReachableOnlyThroughTheRegistry(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .Deps \"\\n\"}}",
		"github.com/mtlabs-eng/infraproof/internal/providers").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}

	var clouds int
	for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if strings.HasPrefix(dependency, "github.com/mtlabs-eng/infraproof/internal/providers/") {
			clouds++
		}
	}
	// Derived from the registry rather than hard-coded, so adding a cloud does
	// not require editing the test that proves the boundary holds.
	if want := len(providers.Default()); clouds != want {
		t.Fatalf("the registry reaches %d provider packages, want %d", clouds, want)
	}
}
