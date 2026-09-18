package intent_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/intent"
)

// FuzzParse holds the new untrusted boundary. The contract is a file a human
// edits, so the likeliest malformed one is a typo rather than an attack — but
// both must be an input error, never a crash, and never a Contract that
// validation accepted and a rule then misreads.
//
// docs/ARCHITECTURE.md asks for this at every parsing boundary;
// internal/terraformplan has had one since milestone 02.
func FuzzParse(f *testing.F) {
	f.Add(valid)
	f.Add("")
	f.Add("{}")
	f.Add("null")
	f.Add("[]")
	f.Add("---\nschema_version: \"1.0\"\n")
	f.Add(`{"schema_version": "1.0", "schema_version": "2.0"}`)
	f.Add(`{"resources": [{"family": "object_storage", "exposure": "private"}]}`)
	f.Add("\xef\xbb\xbf" + valid)

	f.Fuzz(func(t *testing.T, raw string) {
		contract, err := intent.Parse([]byte(raw), "contract.json")
		if err != nil {
			// A rejected contract must carry nothing a caller could act on.
			if contract.SchemaVersion != "" || len(contract.Resources) != 0 ||
				len(contract.AllowedClouds) != 0 || contract.Digest != "" {
				t.Fatalf("a rejected contract carried data: %+v", contract)
			}
			return
		}

		// Everything a rule reads must be established, or the rule concludes
		// from a value validation never approved.
		if contract.Digest == "" {
			t.Fatal("an accepted contract carries no digest")
		}
		if contract.Environment == "" {
			t.Fatal("an accepted contract carries no environment")
		}
		if len(contract.AllowedClouds) == 0 {
			t.Fatal("an accepted contract allows no cloud")
		}
		if len(contract.Resources) == 0 {
			t.Fatal("an accepted contract declares no resource")
		}
		if !contract.DestructiveChanges.Valid() {
			t.Fatalf("an accepted contract has destructive policy %q", contract.DestructiveChanges)
		}
		for i, resource := range contract.Resources {
			if !resource.Exposure.Valid() {
				t.Fatalf("resources[%d] has exposure %q", i, resource.Exposure)
			}
			if resource.Family == "" {
				t.Fatalf("resources[%d] has no family", i)
			}
		}
	})
}
