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

// TestABareDependsOnDoesNotReadmitSiblings covers the first door. A keyed
// reference says which instance a control is about; an explicit depends_on on
// the same resource says only that it comes after. Letting the second widen the
// first turns adding one routine line into a silent loss of the distinction.
func TestABareDependsOnDoesNotReadmitSiblings(t *testing.T) {
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
	     "depends_on": ["aws_s3_bucket.b"],
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
			t.Fatalf("a depends_on line re-admitted the sibling's block: %s", source.ResourceAddress)
		}
	}
}

// TestABareReferenceFromAnUnrepeatedControlIsAmbiguous covers the second door,
// and the limit of positional pairing.
//
// "for_each = aws_s3_bucket.b" pairs by position because the control is
// repeated in lockstep with its target. An unrepeated control reaching one
// instance dynamically — lookup(aws_s3_bucket.b, "a").id — carries no key at
// all, and the plan does not record which instance it chose. Pairing it with
// every instance asserts a relationship the plan never states.
func TestABareReferenceFromAnUnrepeatedControlIsAmbiguous(t *testing.T) {
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
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.b"]}}},
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
		t.Fatalf(`b["z"] has a public ACL: state=%q grants=%v`, open.State, open.Get())
	}
	for _, source := range open.Sources {
		if contains(source.ResourceAddress, "locked") {
			t.Fatalf("an ambiguous reference supplied a block: %s", source.ResourceAddress)
		}
	}

	// The other instance is not thereby proved private either: the block might
	// be its, and the plan does not say.
	other := publicAccess(t, graph, `aws_s3_bucket.b["a"]`)
	if other.IsKnown() && !other.Get() {
		t.Fatal(`b["a"] cannot be proved private by a block that names no instance`)
	}
}

// TestOneReferenceMayNameTwoInstances keeps two distinct links from collapsing
// into one. An argument interpolating two buckets names both.
func TestOneReferenceMayNameTwoInstances(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"a\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket.b[\"z\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}},
	    {"address": "aws_s3_bucket_acl.both", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "both", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.both", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "both",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[\"a\"].arn", "aws_s3_bucket.b[\"a\"]",
	       "aws_s3_bucket.b[\"z\"].arn", "aws_s3_bucket.b[\"z\"]"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	refs := changeAtAddress(t, plan, "aws_s3_bucket_acl.both").References
	if len(refs) != 2 {
		t.Fatalf("references = %v, want one per named instance", refs)
	}

	graph := providers.Normalize(plan, providers.Default())
	for _, address := range []string{`aws_s3_bucket.b["a"]`, `aws_s3_bucket.b["z"]`} {
		fact := publicAccess(t, graph, address)
		if !fact.IsKnown() || !fact.Get() {
			t.Fatalf("%s is named by the public ACL: state=%q grants=%v", address, fact.State, fact.Get())
		}
	}
}

func changeAtAddress(t *testing.T, plan terraformplan.Plan, address string) terraformplan.ResourceChange {
	t.Helper()
	for _, change := range plan.ResourceChanges {
		if change.Address == address {
			return change
		}
	}
	t.Fatalf("no change at %s", address)
	return terraformplan.ResourceChange{}
}

// TestAReferenceToAnAddressWithFewerKeysDoesNotPanic covers a plan whose
// configuration and resource_changes disagree: the reference names an instance
// of something the changes record without one. CLAUDE.md requires data to be
// validated at boundaries, and a verifier that panics on a malformed plan has
// denied the verification.
func TestAReferenceToAnAddressWithFewerKeysDoesNotPanic(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[\"a\"].id", "aws_s3_bucket.b[\"a\"]"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("normalizing a self-inconsistent plan panicked: %v", r)
		}
	}()
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, "aws_s3_bucket.b")
	if fact.IsKnown() && fact.Get() {
		t.Fatal("a reference naming an instance the plan does not contain should not bind")
	}
}

// TestBothRealAmbiguityPlans is the pair of reproductions from the fourth
// review round, as Terraform wrote them: one where an explicit depends_on
// widened a keyed reference, and one where an unrepeated control reached a
// repeated bucket dynamically.
func TestBothRealAmbiguityPlans(t *testing.T) {
	for _, fixture := range []string{
		"real-aws-bare-depends-on-terraform-1.14",
		"real-aws-ambiguous-reference-terraform-1.14",
	} {
		t.Run(fixture, func(t *testing.T) {
			graph := normalize(t, fixture)

			open := publicAccess(t, graph, `aws_s3_bucket.b["z"]`)
			if !open.IsKnown() || !open.Get() {
				t.Fatalf(`b["z"] has a public ACL: state=%q grants=%v`, open.State, open.Get())
			}
			for _, source := range open.Sources {
				if contains(source.ResourceAddress, "locked") {
					t.Fatalf("cited the block that names the sibling: %s", source.ResourceAddress)
				}
			}
		})
	}

	// Where the control names its instance the other bucket is provably
	// private; where it does not, nothing about it is proved either way.
	named := publicAccess(t, normalize(t, "real-aws-bare-depends-on-terraform-1.14"), `aws_s3_bucket.b["a"]`)
	if !named.IsKnown() || named.Get() {
		t.Fatalf("a keyed block still proves its own bucket private: state=%q", named.State)
	}
	dynamic := publicAccess(t, normalize(t, "real-aws-ambiguous-reference-terraform-1.14"), `aws_s3_bucket.b["a"]`)
	if dynamic.IsKnown() {
		t.Fatalf("an ambiguous block proves nothing: state=%q grants=%v", dynamic.State, dynamic.Get())
	}
}

// TestASingleInstanceLeavesNothingToChooseBetween is the limit of the
// ambiguity rule. A bare reference from an unrepeated control is refused
// because the plan does not record which instance it reached — but where the
// target has exactly one instance there is nothing to record, and refusing
// would discard a relationship the plan states plainly.
func TestASingleInstanceLeavesNothingToChooseBetween(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"only\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "b", "index": "only", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "only"}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.b"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, `aws_s3_bucket.b["only"]`)
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("the one instance there is carries the public ACL: state=%q grants=%v",
			fact.State, fact.Get())
	}
}
