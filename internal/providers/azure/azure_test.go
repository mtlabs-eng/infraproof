package azure_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

func container(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture+".json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	found, ok := providers.Normalize(plan, providers.Default()).At("azurerm_storage_container.assets")
	if !ok || found.ObjectStorage == nil {
		t.Fatalf("fixture %s produced no normalized container", fixture)
	}
	return found
}

// TestPublicAccessDetermination covers the conjunction. Neither resource
// settles the question alone, and the account is often somewhere else entirely.
func TestPublicAccessDetermination(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		grants bool
	}{
		"public-blob":                   {model.FactKnown, true},
		"public-container":              {model.FactKnown, true},
		"private-account-forbids":       {model.FactKnown, false},
		"private-container":             {model.FactKnown, false},
		"unknown-account-absent":        {model.FactUnknown, false},
		"unknown-account-not-yet-known": {model.FactUnknown, false},
		"absent-container-access-type":  {model.FactUnknown, false},
		"redacted-account-flag":         {model.FactRedacted, false},
	}

	for fixture, want := range cases {
		t.Run(fixture, func(t *testing.T) {
			fact := container(t, fixture).ObjectStorage.PublicAccess
			if fact.State != want.state {
				t.Fatalf("state = %q, want %q", fact.State, want.state)
			}
			if fact.Get() != want.grants {
				t.Fatalf("grants public = %v, want %v", fact.Get(), want.grants)
			}
		})
	}
}

// TestAnAbsentAccessTypeIsNotPrivate is the rule docs/ARCHITECTURE.md:73 states
// outright. The provider's default happens to be private, but reading absence
// as a value is the mistake the whole model exists to prevent.
func TestAnAbsentAccessTypeIsNotPrivate(t *testing.T) {
	fact := container(t, "absent-container-access-type").ObjectStorage.PublicAccess

	if fact.State == model.FactKnown {
		t.Fatalf("an absent access type was read as a value: %v", fact.Get())
	}
}

// TestAMissingAccountIsReported names the gap rather than assuming the account
// forbids public access.
func TestAMissingAccountIsReported(t *testing.T) {
	missing := container(t, "unknown-account-absent").ObjectStorage
	if len(missing.Unresolved) != 1 || missing.Unresolved[0].CheckID != "AZURE_STORAGE_ACCOUNT_NOT_IN_PLAN" {
		t.Fatalf("unresolved = %v", missing.Unresolved)
	}

	present := container(t, "public-blob").ObjectStorage
	if len(present.Unresolved) != 0 {
		t.Fatalf("unresolved = %v, want none when the account is in the plan", present.Unresolved)
	}
}

func TestEveryFactNamesItsProvenance(t *testing.T) {
	for _, fixture := range []string{"public-blob", "private-container", "private-account-forbids"} {
		t.Run(fixture, func(t *testing.T) {
			fact := container(t, fixture).ObjectStorage.PublicAccess
			if len(fact.Sources) == 0 {
				t.Fatal("the fact names no source")
			}
			for _, source := range fact.Sources {
				if source.Cloud != model.CloudAzure || source.ResourceAddress == "" || source.AttributePath == "" {
					t.Fatalf("incomplete provenance: %+v", source)
				}
			}
		})
	}
}
