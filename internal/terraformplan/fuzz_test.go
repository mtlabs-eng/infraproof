package terraformplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzParse guards the untrusted-input boundary. docs/ARCHITECTURE.md sequences
// full fuzzing after the parser stabilizes; the seed corpus alone runs as an
// ordinary unit test at no cost, and a panic here would turn a malformed plan
// into a denial of verification.
func FuzzParse(f *testing.F) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("reading testdata: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("testdata", entry.Name()))
		if err != nil {
			f.Fatalf("reading %s: %v", entry.Name(), err)
		}
		f.Add(raw)
	}
	f.Add([]byte(""))
	f.Add([]byte("{}"))

	f.Fuzz(func(t *testing.T, raw []byte) {
		plan, err := Parse(raw)
		if err != nil {
			return
		}
		// A successful parse must produce a usable plan, not a half-built one.
		if !strings.HasPrefix(plan.Digest, "sha256:") {
			t.Fatalf("digest %q is malformed", plan.Digest)
		}
		for _, change := range plan.ResourceChanges {
			if len(change.Actions) == 0 {
				t.Fatalf("change %q parsed with no actions", change.Address)
			}
			_ = change.After.Keys()
			_ = change.Before.Keys()
		}
	})
}
