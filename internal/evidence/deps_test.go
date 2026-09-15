package evidence

import (
	"os"
	"strings"
	"testing"
)

// TestNoExternalModuleDependencies is the machine-checkable form of the
// milestone criterion that no package imports Terraform, cloud, MCP, GitHub, or
// LLM dependencies: the module declares no requirements at all.
func TestNoExternalModuleDependencies(t *testing.T) {
	raw, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "require") {
			t.Fatalf("go.mod declares a dependency: %q", strings.TrimSpace(line))
		}
	}
}
