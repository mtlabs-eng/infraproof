package model

import "testing"

// TestUnmappedResourceStaysOpaque is the milestone criterion that an
// unsupported resource is retained rather than dropped. An opaque resource
// carries no capabilities and must never be mistaken for one that was examined
// and found safe.
func TestUnmappedResourceStaysOpaque(t *testing.T) {
	resource := NormalizedResource{
		Address:  "acme_widget.unrecognized",
		Provider: "registry.terraform.io/acme/acme",
		Cloud:    CloudUnknown,
		Family:   FamilyUnknown,
	}

	if resource.ObjectStorage != nil {
		t.Fatal("an opaque resource has no normalized capabilities")
	}
	if resource.Family != FamilyUnknown {
		t.Fatalf("family = %q, want %q", resource.Family, FamilyUnknown)
	}
}

// TestMissingControlIsFirstClass keeps the reason a conclusion could not be
// reached in the model rather than in a message. The account-level block on AWS
// and the organization policy behind GCP's "inherited" are both real, both
// usually outside the plan, and both have to reach the Evidence Bundle.
func TestMissingControlIsFirstClass(t *testing.T) {
	capabilities := ObjectStorageCapabilities{
		PublicAccess: Unknown[bool](aws("aws_s3_bucket.assets", "bucket")),
		Unresolved: []MissingControl{{
			CheckID: "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK",
			Reason:  "The account-level public access block is not part of this plan.",
			Cloud:   CloudAWS,
		}},
	}

	if len(capabilities.Unresolved) != 1 {
		t.Fatalf("unresolved = %v", capabilities.Unresolved)
	}
	if capabilities.Unresolved[0].CheckID == "" || capabilities.Unresolved[0].Reason == "" {
		t.Fatal("a missing control must name a stable check and explain itself")
	}
}

func TestGraphLooksResourcesUpByAddress(t *testing.T) {
	graph := Graph{Resources: []NormalizedResource{
		{Address: "aws_s3_bucket.assets", Cloud: CloudAWS, Family: FamilyObjectStorage},
		{Address: "acme_widget.thing", Cloud: CloudUnknown, Family: FamilyUnknown},
	}}

	found, ok := graph.At("aws_s3_bucket.assets")
	if !ok || found.Family != FamilyObjectStorage {
		t.Fatalf("lookup returned %+v ok=%v", found, ok)
	}
	if _, ok := graph.At("aws_s3_bucket.missing"); ok {
		t.Fatal("a lookup for an address not in the graph must report not found")
	}
	if got := graph.OfFamily(FamilyObjectStorage); len(got) != 1 {
		t.Fatalf("object storage resources = %v, want one", got)
	}
}
