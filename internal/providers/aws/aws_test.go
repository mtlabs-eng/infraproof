package aws_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

func normalize(t *testing.T, fixture string) model.Graph {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture+".json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return providers.Normalize(plan, providers.Default())
}

func bucket(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At("aws_s3_bucket.assets")
	if !ok {
		t.Fatalf("fixture %s has no bucket at aws_s3_bucket.assets", fixture)
	}
	if found.ObjectStorage == nil {
		t.Fatalf("fixture %s produced no object-storage capabilities", fixture)
	}
	return found
}

// TestPublicAccessDetermination is the mapper's whole job. "Known(true)" means
// the change grants public access; "Known(false)" means the plan itself proves
// it is prevented; anything else means a control the answer depends on is not
// in the plan.
func TestPublicAccessDetermination(t *testing.T) {
	cases := map[string]model.FactState{
		"public-acl":                   model.FactKnown,
		"public-policy":                model.FactKnown,
		"private":                      model.FactKnown,
		"private-with-account-block":   model.FactKnown,
		"private-acl-blocked":          model.FactKnown,
		"blocked-public-acl":           model.FactKnown,
		"blocked-public-policy":        model.FactKnown,
		"public-acl-write":             model.FactKnown,
		"unknown-no-controls":          model.FactUnknown,
		"unknown-policy-not-yet-known": model.FactUnknown,
		"unknown-conditional-policy":   model.FactUnknown,
		"redacted-policy":              model.FactRedacted,
	}
	grants := map[string]bool{"public-acl": true, "public-policy": true, "public-acl-write": true}

	for fixture, wantState := range cases {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if fact.State != wantState {
				t.Fatalf("state = %q, want %q", fact.State, wantState)
			}
			if fact.Get() != grants[fixture] {
				t.Fatalf("grants public = %v, want %v", fact.Get(), grants[fixture])
			}
		})
	}
}

// TestAGrantTheSamePlanBlocksIsNotAGrant covers both routes. A policy or ACL
// naming everyone, alongside a block that shuts that route, does not expose the
// bucket — and on AWS the apply would be rejected outright.
func TestAGrantTheSamePlanBlocksIsNotAGrant(t *testing.T) {
	for _, fixture := range []string{"blocked-public-acl", "blocked-public-policy"} {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if fact.State != model.FactKnown || fact.Get() {
				t.Fatalf("state = %q grants = %v, want a known false", fact.State, fact.Get())
			}
		})
	}
}

// TestPublicReadWriteIsPublicToo keeps the second canned ACL in scope. It
// grants more than public-read, so missing it would be the worse direction of
// error.
func TestPublicReadWriteIsPublicToo(t *testing.T) {
	fact := bucket(t, "public-acl-write").ObjectStorage.PublicAccess

	if fact.State != model.FactKnown || !fact.Get() {
		t.Fatalf("state = %q grants = %v, want a known true", fact.State, fact.Get())
	}
}

// TestAConditionalPolicyIsNotProofOfPublicAccess is the judgement that
// separates this from a pattern matcher. A statement with Principal "*" and a
// condition restricting it to a VPC endpoint is not public, and a tool that
// cannot tell the difference produces findings nobody trusts.
func TestAConditionalPolicyIsNotProofOfPublicAccess(t *testing.T) {
	fact := bucket(t, "unknown-conditional-policy").ObjectStorage.PublicAccess

	if fact.State == model.FactKnown {
		t.Fatalf("a conditional policy was read as a definite answer: %v", fact.Get())
	}
}

// TestARedactedPolicyCannotBeRead keeps milestone 02's discard visible here: a
// policy the plan marked sensitive is not readable, so no conclusion follows
// from it.
func TestARedactedPolicyCannotBeRead(t *testing.T) {
	if got := bucket(t, "redacted-policy").ObjectStorage.PublicAccess.State; got != model.FactRedacted {
		t.Fatalf("state = %q, want %q", got, model.FactRedacted)
	}
}

// TestTheAccountLevelBlockIsReportedWhenAbsent covers the control that decides
// the real answer on AWS and is almost never in a plan.
func TestTheAccountLevelBlockIsReportedWhenAbsent(t *testing.T) {
	withoutIt := bucket(t, "private").ObjectStorage
	if len(withoutIt.Unresolved) != 1 {
		t.Fatalf("unresolved = %v, want the account-level block", withoutIt.Unresolved)
	}
	if withoutIt.Unresolved[0].CheckID != "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK" {
		t.Fatalf("check id = %q", withoutIt.Unresolved[0].CheckID)
	}

	withIt := bucket(t, "private-with-account-block").ObjectStorage
	if len(withIt.Unresolved) != 0 {
		t.Fatalf("unresolved = %v, want none when the account block is in the plan", withIt.Unresolved)
	}
}

// TestEveryFactNamesItsProvenance is an acceptance criterion: a finding has to
// be traceable to the provider attribute it came from.
func TestEveryFactNamesItsProvenance(t *testing.T) {
	for _, fixture := range []string{"public-acl", "public-policy", "private"} {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if len(fact.Sources) == 0 {
				t.Fatal("the fact names no source")
			}
			for _, source := range fact.Sources {
				if source.ResourceAddress == "" || source.AttributePath == "" {
					t.Fatalf("incomplete provenance: %+v", source)
				}
				if source.Cloud != model.CloudAWS {
					t.Fatalf("provenance cloud = %q, want %q", source.Cloud, model.CloudAWS)
				}
			}
		})
	}
}

func TestPublicAclProvenanceNamesTheAcl(t *testing.T) {
	fact := bucket(t, "public-acl").ObjectStorage.PublicAccess

	var found bool
	for _, source := range fact.Sources {
		if source.ResourceAddress == "aws_s3_bucket_acl.assets" && source.AttributePath == "acl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the finding does not point at the ACL that grants access: %v", fact.Sources)
	}
}

// TestSatelliteResourcesStayInTheGraph keeps every change visible. A control
// resource is folded into its bucket's capabilities, but dropping it would hide
// a change from a reader.
func TestSatelliteResourcesStayInTheGraph(t *testing.T) {
	graph := normalize(t, "public-acl")

	if len(graph.Resources) != 3 {
		t.Fatalf("graph has %d resources, want all three from the plan", len(graph.Resources))
	}
	block, ok := graph.At("aws_s3_bucket_public_access_block.assets")
	if !ok {
		t.Fatal("the public access block is missing from the graph")
	}
	if !block.Interpreted {
		t.Fatal("a resource a mapper understood must not read as unsupported")
	}
	if block.ObjectStorage != nil {
		t.Fatal("a control resource has no capabilities of its own")
	}
}

// TestAResourceNoMapperClaimsStaysOpaque is the criterion carried from
// milestone 02 into this layer. An unrecognized resource is retained, is
// labelled as belonging to no cloud and no family, and does not report itself
// as understood — because "we did not look at this" and "we looked and it is
// fine" are different claims.
func TestAResourceNoMapperClaimsStaysOpaque(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "acme_widget.unrecognized", "mode": "managed", "type": "acme_widget",
	    "name": "unrecognized", "provider_name": "registry.terraform.io/acme/acme",
	    "change": {"actions": ["delete"], "before": {"shape": "hexagon"}, "after": null}
	  }]
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	resource, ok := graph.At("acme_widget.unrecognized")
	if !ok {
		t.Fatal("an unrecognized resource was dropped from the graph")
	}
	if resource.Cloud != model.CloudUnknown {
		t.Fatalf("cloud = %q, want %q", resource.Cloud, model.CloudUnknown)
	}
	if resource.Family != model.FamilyUnknown {
		t.Fatalf("family = %q, want %q", resource.Family, model.FamilyUnknown)
	}
	if resource.Interpreted {
		t.Fatal("a resource no mapper claimed must not report itself understood")
	}
	if resource.ObjectStorage != nil {
		t.Fatal("an opaque resource has no capabilities")
	}
	if !resource.Destructive {
		t.Fatal("a delete is destructive whether or not any mapper understood it")
	}
}
