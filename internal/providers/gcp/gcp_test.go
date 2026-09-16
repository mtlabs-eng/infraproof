package gcp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

func bucket(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture+".json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	found, ok := providers.Normalize(plan, providers.Default()).At("google_storage_bucket.assets")
	if !ok || found.ObjectStorage == nil {
		t.Fatalf("fixture %s produced no normalized bucket", fixture)
	}
	return found
}

func TestPublicAccessDetermination(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		grants bool
	}{
		"public-iam-member":                   {model.FactKnown, true},
		"public-iam-binding":                  {model.FactKnown, true},
		"private-enforced":                    {model.FactKnown, false},
		"private-enforced-with-public-member": {model.FactKnown, false},
		"private-named-members":               {model.FactKnown, false},
		"unknown-inherited-no-grant":          {model.FactUnknown, false},
		"unknown-iam-policy-data":             {model.FactUnknown, false},
		"absent-public-access-prevention":     {model.FactUnknown, false},
		"redacted-iam-policy-data":            {model.FactRedacted, false},
	}

	for fixture, want := range cases {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if fact.State != want.state {
				t.Fatalf("state = %q, want %q", fact.State, want.state)
			}
			if fact.Get() != want.grants {
				t.Fatalf("grants public = %v, want %v", fact.Get(), want.grants)
			}
		})
	}
}

// TestInheritedPreventionProvesNothing is the GCP counterpart of the AWS
// account-level block, and the reason a bucket with no public binding is still
// UNKNOWN: "inherited" defers to an organization policy no plan contains.
func TestInheritedPreventionProvesNothing(t *testing.T) {
	inherited := bucket(t, "unknown-inherited-no-grant").ObjectStorage
	if inherited.PublicAccess.State == model.FactKnown {
		t.Fatal("inherited prevention was read as proof of anything")
	}
	if len(inherited.Unresolved) != 1 || inherited.Unresolved[0].CheckID != "GCP_ORGANIZATION_PUBLIC_ACCESS_POLICY" {
		t.Fatalf("unresolved = %v", inherited.Unresolved)
	}

	enforced := bucket(t, "private-enforced").ObjectStorage
	if len(enforced.Unresolved) != 0 {
		t.Fatalf("unresolved = %v, want none when prevention is enforced", enforced.Unresolved)
	}
}

// TestEnforcedPreventionOverridesAPublicBinding covers the case a pattern
// matcher gets wrong: a plan can name allUsers and still not be public.
func TestEnforcedPreventionOverridesAPublicBinding(t *testing.T) {
	fact := bucket(t, "private-enforced-with-public-member").ObjectStorage.PublicAccess

	if fact.State != model.FactKnown || fact.Get() {
		t.Fatalf("state = %q grants = %v, want a known false", fact.State, fact.Get())
	}
}

// TestAllAuthenticatedUsersCountsAsEveryone keeps the second spelling of public
// in scope. It means any Google account at all, not any account in the project.
func TestAllAuthenticatedUsersCountsAsEveryone(t *testing.T) {
	fact := bucket(t, "public-iam-binding").ObjectStorage.PublicAccess

	if fact.State != model.FactKnown || !fact.Get() {
		t.Fatalf("state = %q grants = %v, want a known true", fact.State, fact.Get())
	}
}

func TestEveryFactNamesItsProvenance(t *testing.T) {
	for _, fixture := range []string{"public-iam-member", "private-enforced", "public-iam-binding"} {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if len(fact.Sources) == 0 {
				t.Fatal("the fact names no source")
			}
			for _, source := range fact.Sources {
				if source.Cloud != model.CloudGCP || source.ResourceAddress == "" || source.AttributePath == "" {
					t.Fatalf("incomplete provenance: %+v", source)
				}
			}
		})
	}
}
