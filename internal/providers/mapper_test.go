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

// TestAnUnkeyedControlBindsOnlyToTheInstanceItNames is the second door into the
// same defect. A control with no repetition of its own names one instance
// explicitly — aws_s3_bucket.b["a"] — and treating "has no keys" as "matches
// every instance" hands its protection to the sibling it was never about.
func TestAnUnkeyedControlBindsOnlyToTheInstanceItNames(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"a\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "example-a"}}},
	    {"address": "aws_s3_bucket.b[\"z\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "example-z"}}},
	    {"address": "aws_s3_bucket_public_access_block.locked", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "locked", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.locked", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "locked",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[\"a\"].id", "aws_s3_bucket.b[\"a\"]", "aws_s3_bucket.b"]}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[\"z\"].id", "aws_s3_bucket.b[\"z\"]", "aws_s3_bucket.b"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	open := publicAccess(t, graph, `aws_s3_bucket.b["z"]`)
	if !open.IsKnown() || !open.Get() {
		t.Fatalf(`b["z"] has a public ACL and no block of its own: state=%q grants=%v`, open.State, open.Get())
	}
	for _, source := range open.Sources {
		if contains(source.ResourceAddress, "locked") {
			t.Fatalf("the conclusion cites a block that belongs to the sibling: %s", source.ResourceAddress)
		}
	}

	locked := publicAccess(t, graph, `aws_s3_bucket.b["a"]`)
	if !locked.IsKnown() || locked.Get() {
		t.Fatalf(`b["a"] is blocked on every route: state=%q grants=%v`, locked.State, locked.Get())
	}
	for _, source := range locked.Sources {
		if contains(source.ResourceAddress, "open") {
			t.Fatalf("the conclusion cites an ACL that belongs to the sibling: %s", source.ResourceAddress)
		}
	}
}

// TestNestedModuleKeysAreComparedInFull covers keys at two levels. Comparing
// only the first or only the last would let a resource in module.m["eu"] pick
// up a control from module.m["us"].
func TestNestedModuleKeysAreComparedInFull(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.outer[\"eu\"].module.inner[\"one\"].aws_s3_bucket.b",
	     "module_address": "module.outer[\"eu\"].module.inner[\"one\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "eu-one"}}},
	    {"address": "module.outer[\"eu\"].module.inner[\"two\"].aws_s3_bucket.b",
	     "module_address": "module.outer[\"eu\"].module.inner[\"two\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "eu-two"}}},
	    {"address": "module.outer[\"eu\"].module.inner[\"one\"].aws_s3_bucket_public_access_block.b",
	     "module_address": "module.outer[\"eu\"].module.inner[\"one\"]",
	     "mode": "managed", "type": "aws_s3_bucket_public_access_block", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "module.outer[\"eu\"].module.inner[\"two\"].aws_s3_bucket_acl.b",
	     "module_address": "module.outer[\"eu\"].module.inner[\"two\"]",
	     "mode": "managed", "type": "aws_s3_bucket_acl", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"outer": {"source": "./outer", "module": {
	    "module_calls": {"inner": {"source": "./inner", "module": {"resources": [
	      {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	       "expressions": {}},
	      {"address": "aws_s3_bucket_public_access_block.b", "mode": "managed",
	       "type": "aws_s3_bucket_public_access_block", "name": "b",
	       "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}},
	      {"address": "aws_s3_bucket_acl.b", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "b",
	       "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}}
	    ]}}}
	  }}}}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	open := publicAccess(t, graph, `module.outer["eu"].module.inner["two"].aws_s3_bucket.b`)
	if !open.IsKnown() || !open.Get() {
		t.Fatalf("inner two has a public ACL and no block: state=%q grants=%v", open.State, open.Get())
	}
	locked := publicAccess(t, graph, `module.outer["eu"].module.inner["one"].aws_s3_bucket.b`)
	if !locked.IsKnown() || locked.Get() {
		t.Fatalf("inner one is blocked on every route: state=%q grants=%v", locked.State, locked.Get())
	}
}

// TestRealKeyedReferencePlan is the reproduction from the third review round,
// as Terraform 1.14.0 wrote it. One bucket of a for_each pair is named by an
// unrepeated public access block, the other by an unrepeated public ACL, and
// reading either control as applying to both reported the open bucket as
// provably private.
func TestRealKeyedReferencePlan(t *testing.T) {
	graph := normalize(t, "real-aws-keyed-reference-terraform-1.14")

	open := publicAccess(t, graph, `aws_s3_bucket.b["z"]`)
	if !open.IsKnown() || !open.Get() {
		t.Fatalf(`b["z"] is public: state=%q grants=%v`, open.State, open.Get())
	}
	for _, source := range open.Sources {
		if contains(source.ResourceAddress, "locked") {
			t.Fatalf("cited the sibling's block: %s", source.ResourceAddress)
		}
	}

	locked := publicAccess(t, graph, `aws_s3_bucket.b["a"]`)
	if !locked.IsKnown() || locked.Get() {
		t.Fatalf(`b["a"] is private: state=%q grants=%v`, locked.State, locked.Get())
	}
	for _, source := range locked.Sources {
		if contains(source.ResourceAddress, "open") {
			t.Fatalf("cited the sibling's ACL: %s", source.ResourceAddress)
		}
	}
}

// TestAModuleKeyIsNotAResourceKey covers depths that differ. A bucket declared
// once inside module.m["eu"] carries one key; a control repeated inside the
// same module carries two. Comparing only the last key would read "eu" against
// "x" and refuse a relationship that plainly holds.
func TestAModuleKeyIsNotAResourceKey(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"eu\"].aws_s3_bucket.b", "module_address": "module.m[\"eu\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "eu"}}},
	    {"address": "module.m[\"eu\"].aws_s3_bucket_acl.b[\"x\"]", "module_address": "module.m[\"eu\"]",
	     "mode": "managed", "type": "aws_s3_bucket_acl", "name": "b", "index": "x", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.b", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "b",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}}
	  ]}}}}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, `module.m["eu"].aws_s3_bucket.b`)
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("the bucket's own ACL grants public access: state=%q grants=%v", fact.State, fact.Get())
	}
}

// TestAKeyedReferenceMatchesTheResourceKeyNotTheModuleKey covers the other half
// of the same distinction. A reference written inside a module names the
// instance at the end of the address, so matching its key against the module's
// would compare "a" with "eu" and pick the wrong instance — or none.
func TestAKeyedReferenceMatchesTheResourceKeyNotTheModuleKey(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"eu\"].aws_s3_bucket.b[\"a\"]", "module_address": "module.m[\"eu\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "eu-a"}}},
	    {"address": "module.m[\"eu\"].aws_s3_bucket.b[\"z\"]", "module_address": "module.m[\"eu\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "eu-z"}}},
	    {"address": "module.m[\"eu\"].aws_s3_bucket_acl.open", "module_address": "module.m[\"eu\"]",
	     "mode": "managed", "type": "aws_s3_bucket_acl", "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[\"z\"].id", "aws_s3_bucket.b[\"z\"]", "aws_s3_bucket.b"]}}}
	  ]}}}}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	named := publicAccess(t, graph, `module.m["eu"].aws_s3_bucket.b["z"]`)
	if !named.IsKnown() || !named.Get() {
		t.Fatalf("the named instance has the public ACL: state=%q grants=%v", named.State, named.Get())
	}

	other := publicAccess(t, graph, `module.m["eu"].aws_s3_bucket.b["a"]`)
	if other.IsKnown() && other.Get() {
		t.Fatal("the unnamed instance must not inherit its sibling's ACL")
	}
}
