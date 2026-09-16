package azure_test

import (
	"fmt"
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

// TestAnAccountWithNoContainerIsStillReported keeps the three clouds
// symmetrical. An AWS bucket with no controls in its plan produces a required
// unknown; an Azure account that permits anonymous access with no container in
// the plan produced nothing at all, which is a quieter answer than the evidence
// supports.
func TestAnAccountWithNoContainerIsStillReported(t *testing.T) {
	account := func(allow bool) model.NormalizedResource {
		t.Helper()
		raw := []byte(fmt.Sprintf(`{
		  "format_version": "1.2",
		  "resource_changes": [{
		    "address": "azurerm_storage_account.example", "mode": "managed",
		    "type": "azurerm_storage_account", "name": "example", "provider_name": "p",
		    "change": {"actions": ["create"], "before": null,
		               "after": {"name": "s", "allow_nested_items_to_be_public": %v}}
		  }]
		}`, allow))

		plan, err := terraformplan.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		resource, ok := providers.Normalize(plan, providers.Default()).At("azurerm_storage_account.example")
		if !ok {
			t.Fatal("the account is missing from the graph")
		}
		return resource
	}

	permitting := account(true)
	if permitting.ObjectStorage == nil {
		t.Fatal("an account permitting anonymous access with no container in the plan must not be silent")
	}
	if permitting.ObjectStorage.PublicAccess.IsKnown() {
		t.Fatalf("state = %q; no container means no conclusion", permitting.ObjectStorage.PublicAccess.State)
	}
	if len(permitting.ObjectStorage.Unresolved) != 1 ||
		permitting.ObjectStorage.Unresolved[0].CheckID != "AZURE_CONTAINER_NOT_IN_PLAN" {
		t.Fatalf("unresolved = %v", permitting.ObjectStorage.Unresolved)
	}

	forbidding := account(false)
	if forbidding.ObjectStorage == nil || !forbidding.ObjectStorage.PublicAccess.IsKnown() ||
		forbidding.ObjectStorage.PublicAccess.Get() {
		t.Fatal("an account that forbids anonymous access proves nothing in it is public")
	}
}

// TestAnAccountDefersToItsContainers keeps the account from reporting alongside
// the containers it gates, which would say the same thing twice.
func TestAnAccountDefersToItsContainers(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "public-blob.json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	resource, ok := providers.Normalize(plan, providers.Default()).At("azurerm_storage_account.example")
	if !ok {
		t.Fatal("the account is missing from the graph")
	}
	if !resource.Interpreted {
		t.Fatal("the account was understood and must say so")
	}
	if resource.ObjectStorage != nil {
		t.Fatal("with its container in the plan, the account must not report separately")
	}
}

// TestTwoAccountsGatingOneContainerCannotBeResolved covers a contradictory
// plan. Choosing between two storage accounts would state a determination the
// plan does not support, and an unreadable gate already degrades to UNKNOWN.
func TestTwoAccountsGatingOneContainerCannotBeResolved(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.aaa", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "aaa", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "a", "allow_nested_items_to_be_public": false}}},
	    {"address": "azurerm_storage_account.zzz", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "zzz", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "z", "allow_nested_items_to_be_public": true}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.aaa", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "aaa", "expressions": {}},
	    {"address": "azurerm_storage_account.zzz", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "zzz", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "azurerm_storage_account.aaa.id", "azurerm_storage_account.aaa",
	       "azurerm_storage_account.zzz.id", "azurerm_storage_account.zzz"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At("azurerm_storage_container.assets")
	if !ok || resource.ObjectStorage == nil {
		t.Fatal("no normalized container")
	}

	fact := resource.ObjectStorage.PublicAccess
	if fact.IsKnown() {
		t.Fatalf("two contradictory accounts cannot yield a determination, got state=%q grants=%v",
			fact.State, fact.Get())
	}
	if len(resource.ObjectStorage.Unresolved) == 0 {
		t.Fatal("an unresolvable gate must be reported")
	}
}
