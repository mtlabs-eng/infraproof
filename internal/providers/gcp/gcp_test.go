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

// TestADefiniteGrantOutranksAnUnreadableOne keeps the worst answer from
// winning. An IAM resource nobody can read leaves the question open, but a
// definite allUsers grant elsewhere closes it — reporting UNKNOWN there would
// withhold a finding the plan proves.
func TestADefiniteGrantOutranksAnUnreadableOne(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "google_storage_bucket.assets", "mode": "managed", "type": "google_storage_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "a", "public_access_prevention": "inherited"}}},
	    {"address": "google_storage_bucket_iam_member.aaa_unreadable", "mode": "managed",
	     "type": "google_storage_bucket_iam_member", "name": "aaa_unreadable", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {},
	                "after_unknown": {"member": true}}},
	    {"address": "google_storage_bucket_iam_member.zzz_public", "mode": "managed",
	     "type": "google_storage_bucket_iam_member", "name": "zzz_public", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"role": "roles/storage.objectViewer", "member": "allUsers"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "google_storage_bucket.assets", "mode": "managed", "type": "google_storage_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "google_storage_bucket_iam_member.aaa_unreadable", "mode": "managed",
	     "type": "google_storage_bucket_iam_member", "name": "aaa_unreadable",
	     "expressions": {"bucket": {"references": ["google_storage_bucket.assets.name", "google_storage_bucket.assets"]}}},
	    {"address": "google_storage_bucket_iam_member.zzz_public", "mode": "managed",
	     "type": "google_storage_bucket_iam_member", "name": "zzz_public",
	     "expressions": {"bucket": {"references": ["google_storage_bucket.assets.name", "google_storage_bucket.assets"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At("google_storage_bucket.assets")
	if !ok || resource.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}

	fact := resource.ObjectStorage.PublicAccess
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("state=%q grants=%v, want a known true", fact.State, fact.Get())
	}
}

// TestAnIAMBindingBindsOnlyThroughItsBucketArgument is the AWS defect in GCP.
//
// An IAM member, binding or policy carries the bucket it applies to in
// "bucket". An ordering dependency on some other bucket, or a condition
// interpolating one, names a bucket without granting anything on it — and
// reading either as the application let a public grant on one bucket be
// attributed to another.
func TestAnIAMBindingBindsOnlyThroughItsBucketArgument(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "google_storage_bucket.private", "mode": "managed",
	     "type": "google_storage_bucket", "name": "private", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "p", "public_access_prevention": "enforced"}}},
	    {"address": "google_storage_bucket_iam_member.elsewhere", "mode": "managed",
	     "type": "google_storage_bucket_iam_member", "name": "elsewhere", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a-bucket-managed-elsewhere",
	                          "role": "roles/storage.objectViewer", "member": "allUsers"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "google_storage_bucket.private", "mode": "managed",
	     "type": "google_storage_bucket", "name": "private", "expressions": {}},
	    {"address": "google_storage_bucket_iam_member.elsewhere", "mode": "managed",
	     "type": "google_storage_bucket_iam_member", "name": "elsewhere",
	     "expressions": {
	       "bucket": {"constant_value": "a-bucket-managed-elsewhere"},
	       "condition": {"references": [
	         "google_storage_bucket.private.name", "google_storage_bucket.private"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	bucket, ok := graph.At("google_storage_bucket.private")
	if !ok || bucket.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	for _, source := range bucket.ObjectStorage.PublicAccess.Sources {
		if source.ResourceAddress == "google_storage_bucket_iam_member.elsewhere" {
			t.Fatalf("a grant on another bucket was attributed to this one: %s", source.ResourceAddress)
		}
	}

	// And the grant defers to nobody: it governs a bucket that is not here.
	member, ok := graph.At("google_storage_bucket_iam_member.elsewhere")
	if !ok {
		t.Fatal("no normalized IAM member")
	}
	if len(member.DefersTo) != 0 {
		t.Fatalf("a grant on a bucket managed elsewhere defers to %v", member.DefersTo)
	}
}
