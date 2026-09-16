package providers_test

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

func publicAccess(t *testing.T, graph model.Graph, address string) model.Fact[bool] {
	t.Helper()
	resource, ok := graph.At(address)
	if !ok {
		t.Fatalf("no resource at %s", address)
	}
	if resource.ObjectStorage == nil {
		t.Fatalf("%s has no normalized capabilities", address)
	}
	return resource.ObjectStorage.PublicAccess
}

// TestInstancesDoNotShareControls is the defect that matters most in this
// package. Every instance of a repeated resource shares one configuration
// address, so correlating by that address alone hands one bucket's public
// access block to its sibling — and reports a bucket with a public-read ACL and
// no blocks as provably private, citing the other instance as evidence.
//
// The fixture is a plan Terraform 1.14.0 produced from two for_each instances,
// one locked down and one wide open.
func TestInstancesDoNotShareControls(t *testing.T) {
	graph := normalize(t, "real-aws-for-each-terraform-1.14")

	open := publicAccess(t, graph, `aws_s3_bucket.b["z-public"]`)
	if !open.IsKnown() || !open.Get() {
		t.Fatalf(`b["z-public"] has a public-read ACL and no blocks: state=%q grants=%v`, open.State, open.Get())
	}
	for _, source := range open.Sources {
		if contains(source.ResourceAddress, "a-private") {
			t.Fatalf("the conclusion cites another instance's control: %s", source.ResourceAddress)
		}
	}

	locked := publicAccess(t, graph, `aws_s3_bucket.b["a-private"]`)
	if !locked.IsKnown() || locked.Get() {
		t.Fatalf(`b["a-private"] is blocked on every route: state=%q grants=%v`, locked.State, locked.Get())
	}
	for _, source := range locked.Sources {
		if contains(source.ResourceAddress, "z-public") {
			t.Fatalf("the conclusion cites another instance's control: %s", source.ResourceAddress)
		}
	}
}

// TestASingletonCorrelatesWithRepeatedControls covers the compatible direction:
// one bucket and many controls is a real shape, and the keys do not have to
// match for the relationship to hold.
func TestASingletonCorrelatesWithRepeatedControls(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.a[0]", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "a", "index": 0, "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_acl.a", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "a",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, "aws_s3_bucket.assets")
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("an unrepeated bucket must still see its repeated controls: state=%q grants=%v", fact.State, fact.Get())
	}
}

// TestNestedBlocksDoNotBreakNormalization covers the real plan whose canonical
// S3 stack used to be rejected outright.
func TestNestedBlocksDoNotBreakNormalization(t *testing.T) {
	graph := normalize(t, "real-aws-nested-blocks-terraform-1.14")

	if len(graph.Resources) == 0 {
		t.Fatal("the plan normalized to nothing")
	}
	var buckets int
	for _, resource := range graph.Resources {
		if resource.ObjectStorage != nil {
			buckets++
		}
	}
	if buckets == 0 {
		t.Fatal("no bucket was normalized")
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
