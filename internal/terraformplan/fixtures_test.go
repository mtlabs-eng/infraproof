package terraformplan

import (
	"os"
	"path/filepath"
	"testing"
)

// fixtureBytes reads a plan fixture. Tests name fixtures; production code never
// does.
func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name+".json"))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	return raw
}

// parseFixture parses a fixture that is expected to be valid.
func parseFixture(t *testing.T, name string) Plan {
	t.Helper()
	plan, err := Parse(fixtureBytes(t, name))
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return plan
}

// onlyChange returns the single resource change of a one-resource fixture.
func onlyChange(t *testing.T, name string) ResourceChange {
	t.Helper()
	plan := parseFixture(t, name)
	if len(plan.ResourceChanges) != 1 {
		t.Fatalf("fixture %s has %d resource changes, want 1", name, len(plan.ResourceChanges))
	}
	return plan.ResourceChanges[0]
}
