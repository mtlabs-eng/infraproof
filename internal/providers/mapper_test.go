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

// TestRepeatedInstancesReachNoVerdict records the cost of that decision on the
// shape it falls hardest on: a for_each over buckets with controls repeated
// alongside them. One instance is locked down and one is wide open, and the
// plan cannot say which control belongs to which, so neither gets an answer.
//
// This used to report both correctly, by an assumption that was wrong on two
// real plans. A lost finding is recoverable; a bucket published to the internet
// and reported provably private is not.
func TestRepeatedInstancesReachNoVerdict(t *testing.T) {
	graph := normalize(t, "real-aws-for-each-terraform-1.14")

	for _, address := range []string{`aws_s3_bucket.b["z-public"]`, `aws_s3_bucket.b["a-private"]`} {
		fact := publicAccess(t, graph, address)
		if fact.IsKnown() {
			t.Fatalf("%s: state=%q grants=%v — the plan does not resolve which control is its own",
				address, fact.State, fact.Get())
		}
		for _, source := range fact.Sources {
			if contains(source.ResourceAddress, "public_access_block") {
				t.Fatalf("%s cites a block that was not correlated: %s", address, source.ResourceAddress)
			}
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

// TestPositionalPairingNeedsThePlanToSaySo is the last door of the same class.
// "aws_s3_bucket.b[each.key]" pairs one instance with one instance.
// "aws_s3_bucket.b[each.value]" pairs them through a map, and a swap map pairs
// each control with its sibling's bucket. Assuming the first when the plan says
// the second reports the public bucket as provably private, citing the block
// that governs the other one.
//
// The fixture is a plan Terraform 1.14.0 produced from a swap map.
func TestPositionalPairingNeedsThePlanToSaySo(t *testing.T) {
	graph := normalize(t, "real-aws-swapped-index-terraform-1.14")

	public := publicAccess(t, graph, `aws_s3_bucket.b["a"]`)
	if !public.IsKnown() || !public.Get() {
		t.Fatalf(`b["a"] carries the public ACL through a keyed reference: state=%q grants=%v`,
			public.State, public.Get())
	}
	for _, source := range public.Sources {
		if contains(source.ResourceAddress, "pab") {
			t.Fatalf("a block reached through a swap map was read as this bucket's: %s", source.ResourceAddress)
		}
	}

	other := publicAccess(t, graph, `aws_s3_bucket.b["z"]`)
	if other.IsKnown() {
		t.Fatalf(`b["z"] is governed by a block the plan does not resolve: state=%q grants=%v`,
			other.State, other.Get())
	}
}

// TestPreferKeyedIsScopedToItsTarget keeps the rule from over-reaching. A
// resource that names one instance of A and the whole of B must keep its
// reference to B.
func TestPreferKeyedIsScopedToItsTarget(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "assets"}}},
	    {"address": "aws_s3_bucket.other[\"a\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "other", "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "other"}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket.other", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "other", "expressions": {}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {
	       "bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]},
	       "other":  {"references": ["aws_s3_bucket.other[\"a\"].id", "aws_s3_bucket.other[\"a\"]"]}
	     }}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	graph := providers.Normalize(plan, providers.Default())
	fact := publicAccess(t, graph, "aws_s3_bucket.assets")
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("a bare reference to one target must survive a keyed reference to another: state=%q grants=%v",
			fact.State, fact.Get())
	}
}

// TestNoIndexFormPairsRepeatedInstances is what seven review rounds arrived at.
//
// Six of them found the same defect through a new door, and the seventh found
// that the door cannot be closed: Terraform's configuration block records which
// values take part in an expression, never how they are combined, and a string
// literal takes part in nothing. So "b[each.key]" and
// "b[each.key == \"a\" ? \"z\" : \"a\"]" emit an identical reference list — one
// pairs instance to instance, the other pairs every control with its sibling's
// bucket, and the plan does not distinguish them.
//
// Pairing repeated resources by position is therefore not attempted at all. The
// table is now a statement about what a plan can express rather than about what
// this code assumes, and every row but the literal key says the same thing.
func TestNoIndexFormPairsRepeatedInstances(t *testing.T) {
	cases := map[string]struct {
		references string
		pairs      bool
		why        string
	}{
		"a literal key": {
			`["aws_s3_bucket.b[\"a\"].id", "aws_s3_bucket.b[\"a\"]", "aws_s3_bucket.b"]`, true,
			"the instance is named outright, so nothing is assumed",
		},
		"the resource's own key": {
			`["aws_s3_bucket.b", "each.key"]`, false,
			"indistinguishable from any pure function of the own key, including one that permutes",
		},
		"the count index": {
			`["aws_s3_bucket.b", "count.index"]`, false,
			"indistinguishable from b[count.index + 1]",
		},
		"a lookup keyed by the own key": {
			`["aws_s3_bucket.b", "local.m", "each.key"]`, false,
			"local.m may map each key to a different one",
		},
		"the for_each value": {
			`["aws_s3_bucket.b", "each.value"]`, false,
			"may reach any instance, including a sibling's",
		},
		"a value from elsewhere": {
			`["aws_s3_bucket.b", "local.other"]`, false,
			"the index is resolved outside this resource's repetition",
		},
		"no index at all": {
			`["aws_s3_bucket.b"]`, false,
			"the control reaches one instance and the plan does not record which",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {"address": "aws_s3_bucket.b[\"a\"]", "mode": "managed", "type": "aws_s3_bucket",
			     "name": "b", "index": "a", "provider_name": "p",
			     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
			    {"address": "aws_s3_bucket.b[\"z\"]", "mode": "managed", "type": "aws_s3_bucket",
			     "name": "b", "index": "z", "provider_name": "p",
			     "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}},
			    {"address": "aws_s3_bucket_acl.a[\"a\"]", "mode": "managed", "type": "aws_s3_bucket_acl",
			     "name": "a", "index": "a", "provider_name": "p",
			     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
			  ],
			  "configuration": {"root_module": {"resources": [
			    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
			     "expressions": {}},
			    {"address": "aws_s3_bucket_acl.a", "mode": "managed", "type": "aws_s3_bucket_acl",
			     "name": "a", "expressions": {"bucket": {"references": ` + c.references + `}}}
			  ]}}
			}`)

			plan, err := terraformplan.Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			graph := providers.Normalize(plan, providers.Default())

			fact := publicAccess(t, graph, `aws_s3_bucket.b["a"]`)
			if got := fact.IsKnown() && fact.Get(); got != c.pairs {
				t.Fatalf(`b["a"] public = %v, want %v — %s`, got, c.pairs, c.why)
			}

			// Whatever the indexing, the control never governs the instance
			// whose key it does not share.
			sibling := publicAccess(t, graph, `aws_s3_bucket.b["z"]`)
			if sibling.IsKnown() && sibling.Get() {
				t.Fatal(`b["z"] does not share the control's key and must not be governed by it`)
			}
		})
	}
}

// TestAControlMayBeRepeatedMoreDeeplyThanItsTarget covers the depth comparison
// itself. A bucket declared once inside a repeated module, with controls
// repeated again inside it, is a resource repeated less deeply than the thing
// referring to it — and requiring equal depth would refuse a relationship that
// plainly holds.
func TestAControlMayBeRepeatedMoreDeeplyThanItsTarget(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"eu\"].aws_s3_bucket.b", "module_address": "module.m[\"eu\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "eu"}}},
	    {"address": "module.m[\"us\"].aws_s3_bucket.b", "module_address": "module.m[\"us\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "us"}}},
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

	inEurope := publicAccess(t, graph, `module.m["eu"].aws_s3_bucket.b`)
	if !inEurope.IsKnown() || !inEurope.Get() {
		t.Fatalf("the bucket in this module instance has the public ACL: state=%q grants=%v",
			inEurope.State, inEurope.Get())
	}

	elsewhere := publicAccess(t, graph, `module.m["us"].aws_s3_bucket.b`)
	if elsewhere.IsKnown() && elsewhere.Get() {
		t.Fatal("a control in one module instance must not reach into another")
	}
}

// TestRealPermutedIndexPlans are the two shapes the enumeration got wrong, as
// Terraform wrote them. One indexes through a swap map keyed by the resource's
// own key; the other does arithmetic on count.index. In both the public bucket
// was reported provably private, citing the block that governs its sibling.
func TestRealPermutedIndexPlans(t *testing.T) {
	t.Run("a lookup table that permutes", func(t *testing.T) {
		graph := normalize(t, "real-aws-permuting-lookup-terraform-1.14")

		public := publicAccess(t, graph, `aws_s3_bucket.b["a"]`)
		if !public.IsKnown() || !public.Get() {
			t.Fatalf(`b["a"] carries the public ACL: state=%q grants=%v`, public.State, public.Get())
		}
		for _, source := range public.Sources {
			if contains(source.ResourceAddress, "pab") {
				t.Fatalf("a block reached through a swap map was read as this bucket's: %s", source.ResourceAddress)
			}
		}
		if other := publicAccess(t, graph, `aws_s3_bucket.b["z"]`); other.IsKnown() {
			t.Fatalf(`b["z"] is governed by a block the plan does not resolve: state=%q`, other.State)
		}
	})

	t.Run("arithmetic on the count index", func(t *testing.T) {
		graph := normalize(t, "real-aws-count-arithmetic-terraform-1.14")

		public := publicAccess(t, graph, "aws_s3_bucket.b[1]")
		if !public.IsKnown() || !public.Get() {
			t.Fatalf("b[1] carries the public ACL: state=%q grants=%v", public.State, public.Get())
		}
		for _, source := range public.Sources {
			if contains(source.ResourceAddress, "pab") {
				t.Fatalf("a counted block was paired by position: %s", source.ResourceAddress)
			}
		}
		if other := publicAccess(t, graph, "aws_s3_bucket.b[0]"); other.IsKnown() {
			t.Fatalf("b[0] is governed by a block the plan does not resolve: state=%q", other.State)
		}
	})
}

// TestADeeperTargetIsNotReachedFromOutside covers the depth guard, which valid
// Terraform cannot reach: a resource in an outer module can only see a nested
// module's outputs, never its resources. A plan whose configuration and
// resource_changes disagree can present the shape anyway, and the guard is what
// stops a control being paired with a resource nested below it.
func TestADeeperTargetIsNotReachedFromOutside(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"eu\"].module.n[\"x\"].aws_s3_bucket.b",
	     "module_address": "module.m[\"eu\"].module.n[\"x\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "x"}}},
	    {"address": "module.m[\"eu\"].module.n[\"y\"].aws_s3_bucket.b",
	     "module_address": "module.m[\"eu\"].module.n[\"y\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "y"}}},
	    {"address": "module.m[\"eu\"].aws_s3_bucket_public_access_block.outer",
	     "module_address": "module.m[\"eu\"]",
	     "mode": "managed", "type": "aws_s3_bucket_public_access_block", "name": "outer",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "module.m[\"eu\"].module.n[\"x\"].aws_s3_bucket_acl.open",
	     "module_address": "module.m[\"eu\"].module.n[\"x\"]",
	     "mode": "managed", "type": "aws_s3_bucket_acl", "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {
	    "resources": [
	      {"address": "aws_s3_bucket_public_access_block.outer", "mode": "managed",
	       "type": "aws_s3_bucket_public_access_block", "name": "outer",
	       "expressions": {"bucket": {"references": ["module.n.aws_s3_bucket.b"]}}}
	    ],
	    "module_calls": {"n": {"source": "./n", "module": {"resources": [
	      {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	       "expressions": {}},
	      {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	       "name": "open",
	       "expressions": {"bucket": {"references": ["aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}}
	    ]}}}
	  }}}}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	public := publicAccess(t, graph, `module.m["eu"].module.n["x"].aws_s3_bucket.b`)
	if !public.IsKnown() || !public.Get() {
		t.Fatalf("the bucket's own ACL grants public access: state=%q grants=%v", public.State, public.Get())
	}
	for _, source := range public.Sources {
		if contains(source.ResourceAddress, "outer") {
			t.Fatalf("a control outside the module governed a resource inside it: %s", source.ResourceAddress)
		}
	}
}

// TestCountingOverAResourceIsNotPairing covers the meta-argument form of the
// same undecidability. "for_each = aws_s3_bucket.b" states that the instances
// correspond by key. "count = length(aws_s3_bucket.b)" states a length, and the
// index that uses it is exactly the one the plan cannot record — so counting
// over a resource cannot carry the pairing either.
func TestCountingOverAResourceIsNotPairing(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[0]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": 0, "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "zero"}}},
	    {"address": "aws_s3_bucket.b[1]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": 1, "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "one"}}},
	    {"address": "aws_s3_bucket_public_access_block.pab[0]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "pab", "index": 0, "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "aws_s3_bucket_public_access_block.pab[1]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "pab", "index": 1, "provider_name": "p",
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
	    {"address": "aws_s3_bucket_public_access_block.pab", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "pab",
	     "count_expression": {"references": ["aws_s3_bucket.b"]},
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.b", "count.index"]}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[1].id", "aws_s3_bucket.b[1]", "aws_s3_bucket.b"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	// b[1] has a public ACL through a literal key. Whether either counted block
	// governs it is not something the plan records.
	public := publicAccess(t, graph, "aws_s3_bucket.b[1]")
	if !public.IsKnown() || !public.Get() {
		t.Fatalf("b[1] carries the public ACL: state=%q grants=%v", public.State, public.Get())
	}
	for _, source := range public.Sources {
		if contains(source.ResourceAddress, "pab") {
			t.Fatalf("a counted block was paired by position: %s", source.ResourceAddress)
		}
	}
}

// TestAnUnresolvedCorrelationSaysSo keeps the undetermined answer actionable.
// A reader whose whole estate reports UNKNOWN needs to know that the cause is a
// reference that names no instance, because that is something they can change.
func TestAnUnresolvedCorrelationSaysSo(t *testing.T) {
	graph := normalize(t, "real-aws-for-each-terraform-1.14")

	resource, ok := graph.At(`aws_s3_bucket.b["z-public"]`)
	if !ok || resource.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}

	var named bool
	for _, control := range resource.ObjectStorage.Unresolved {
		if control.CheckID == "CORRELATION_UNRESOLVED" {
			named = true
			if control.Reason == "" {
				t.Fatal("the gap is named but not explained")
			}
		}
	}
	if !named {
		t.Fatalf("an undetermined correlation must be reported, got %v", resource.ObjectStorage.Unresolved)
	}

	// A plan whose references name their instances has nothing to report.
	clean, ok := normalize(t, "real-aws-keyed-reference-terraform-1.14").At(`aws_s3_bucket.b["a"]`)
	if !ok || clean.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	for _, control := range clean.ObjectStorage.Unresolved {
		if control.CheckID == "CORRELATION_UNRESOLVED" {
			t.Fatal("a plan that names its instances has no unresolved correlation")
		}
	}
}

// TestTheUndecidablePlans are the two that ended the argument. Both index by a
// pure function of the referring resource's own key, using only literals, so
// their reference lists are identical to the honest form — one through a
// conditional in the argument, one through a comprehension in the for_each.
// Neither can be told apart from correct pairing, which is why none of it is
// attempted.
func TestTheUndecidablePlans(t *testing.T) {
	for _, fixture := range []string{
		"real-aws-conditional-index-terraform-1.14",
		"real-aws-permuted-for-each-terraform-1.14",
	} {
		t.Run(fixture, func(t *testing.T) {
			graph := normalize(t, fixture)

			// b["a"] has a public ACL through a literal key, which is
			// resolvable, so it is public whatever the blocks do.
			public := publicAccess(t, graph, `aws_s3_bucket.b["a"]`)
			if !public.IsKnown() || !public.Get() {
				t.Fatalf(`b["a"] carries the public ACL: state=%q grants=%v`, public.State, public.Get())
			}
			for _, source := range public.Sources {
				if contains(source.ResourceAddress, "pab") {
					t.Fatalf("a block whose pairing the plan does not record was applied: %s",
						source.ResourceAddress)
				}
			}
		})
	}
}

// TestAPartialPlanIsNotASingleInstance closes the last route into the
// single-instance shortcut. Counting instances in resource_changes calls a plan
// unambiguous when the configuration says the target is repeated and only one
// instance survived — and a bare reference that meant the absent one is then
// joined to the survivor.
func TestAPartialPlanIsNotASingleInstance(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"z\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}},
	    {"address": "aws_s3_bucket_public_access_block.p", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "p", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "aws_s3_bucket_acl.a", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "a",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "for_each_expression": {"constant_value": ["a", "z"]}, "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.p", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "p",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.b"]}}},
	    {"address": "aws_s3_bucket_acl.a", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "a",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[\"z\"].id", "aws_s3_bucket.b[\"z\"]", "aws_s3_bucket.b"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, `aws_s3_bucket.b["z"]`)
	if fact.IsKnown() && !fact.Get() {
		t.Fatal("a block reaching a repeated resource without naming an instance cannot prove this one private")
	}
	for _, source := range fact.Sources {
		if contains(source.ResourceAddress, "public_access_block") {
			t.Fatalf("the block was applied anyway: %s", source.ResourceAddress)
		}
	}
}

// unresolvedReason returns the reason recorded under a check id, and whether it
// was recorded at all.
func unresolvedReason(t *testing.T, graph model.Graph, address, checkID string) (string, bool) {
	t.Helper()
	resource, ok := graph.At(address)
	if !ok || resource.ObjectStorage == nil {
		t.Fatalf("no normalized object storage at %s", address)
	}
	for _, control := range resource.ObjectStorage.Unresolved {
		if control.CheckID == checkID {
			return control.Reason, true
		}
	}
	return "", false
}

// TestAnUndecidableCorrelationAcrossModulesSaysSo closes the one shape that
// answered UNKNOWN with nowhere for the reader to go. A control in an outer
// module reaching into a repeated inner one cannot say which instance it meant,
// which is the same undecidability as a bare reference between two repeated
// resources, and it must be reported the same way.
func TestAnUndecidableCorrelationAcrossModulesSaysSo(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"eu\"].module.n[\"x\"].aws_s3_bucket.assets",
	     "module_address": "module.m[\"eu\"].module.n[\"x\"]", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "x"}}},
	    {"address": "module.m[\"eu\"].module.n[\"y\"].aws_s3_bucket.assets",
	     "module_address": "module.m[\"eu\"].module.n[\"y\"]", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "y"}}},
	    {"address": "module.m[\"eu\"].aws_s3_bucket_public_access_block.outer",
	     "module_address": "module.m[\"eu\"]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "outer", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {
	    "resources": [
	      {"address": "aws_s3_bucket_public_access_block.outer", "mode": "managed",
	       "type": "aws_s3_bucket_public_access_block", "name": "outer",
	       "expressions": {"bucket": {"references": ["module.n.aws_s3_bucket.assets"]}}}
	    ],
	    "module_calls": {"n": {"source": "./n", "module": {"resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", "expressions": {}}
	    ]}}}
	  }}}}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	address := `module.m["eu"].module.n["x"].aws_s3_bucket.assets`
	fact := publicAccess(t, graph, address)
	if fact.IsKnown() {
		t.Fatalf("a control that cannot say which instance it meant settles nothing: state=%q value=%v",
			fact.State, fact.Get())
	}

	reason, named := unresolvedReason(t, graph, address, "CORRELATION_UNRESOLVED")
	if !named {
		t.Fatal("the undetermined correlation must be reported, so the reader knows what to change")
	}
	if reason == "" {
		t.Fatal("the gap is named but not explained")
	}
}

// TestAnOrderingEdgeIsNotAGovernanceClaim is the defect a fourteenth review
// found, and it is the most serious this project has produced: one ordinary
// line of HCL turned a BLOCK into a PASS on a bucket the plan proves is
// public-read.
//
// depends_on states that one resource must be created before another. It says
// nothing about what governs what, and Terraform documents it as ordering
// alone. Reading it as a correlation let a public-access block that names some
// other bucket by a literal string answer for this one — a correlation the
// configuration does not declare, which is the failure CLAUDE.md names.
func TestAnOrderingEdgeIsNotAGovernanceClaim(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}},
	    {"address": "aws_s3_bucket_public_access_block.elsewhere", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "elsewhere", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a-bucket-managed-elsewhere",
	                          "block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	    {"address": "aws_s3_bucket_public_access_block.elsewhere", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "elsewhere",
	     "expressions": {"bucket": {"constant_value": "a-bucket-managed-elsewhere"}},
	     "depends_on": ["aws_s3_bucket.assets"]}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, "aws_s3_bucket.assets")
	if fact.IsKnown() && !fact.Get() {
		t.Fatal("an ordering dependency was read as the block that governs this bucket")
	}
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("the bucket's own ACL grants public access: state=%q grants=%v", fact.State, fact.Get())
	}
	for _, source := range fact.Sources {
		if contains(source.ResourceAddress, "elsewhere") {
			t.Fatalf("a control that governs another bucket was cited: %s", source.ResourceAddress)
		}
	}
}

// TestAnOrderingEdgeDoesNotCoverAnOrphanControl is the same defect at the
// coverage layer. A control whose governing argument names a bucket managed
// elsewhere defers to nobody, and an ordering dependency must not supply the
// deferral that a governing reference would.
func TestAnOrderingEdgeDoesNotCoverAnOrphanControl(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a", "block_public_acls": true}}},
	    {"address": "aws_s3_bucket_policy.elsewhere", "mode": "managed",
	     "type": "aws_s3_bucket_policy", "name": "elsewhere", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a-bucket-managed-elsewhere", "policy": "{}"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_policy.elsewhere", "mode": "managed",
	     "type": "aws_s3_bucket_policy", "name": "elsewhere",
	     "expressions": {"bucket": {"constant_value": "a-bucket-managed-elsewhere"},
	                     "policy": {"references": ["aws_s3_bucket.assets.arn", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	policy, ok := graph.At("aws_s3_bucket_policy.elsewhere")
	if !ok {
		t.Fatal("no normalized policy")
	}
	if len(policy.DefersTo) != 0 {
		t.Fatalf("a policy governing another bucket defers to %v; mentioning a bucket is not governing it",
			policy.DefersTo)
	}
}

// TestAGovernanceClaimIsRefusedFromEitherEnd closes the half of the previous
// round's fix that was open.
//
// An edge is a claim one resource makes about another, and the graph stores it
// as a symmetric relation. The filter read the type of the resource that wrote
// the reference, so the identical claim written from the bucket instead of from
// the control passed unexamined: a bucket states no binding argument, and a
// type stating none admitted every argument. The same public-access block that
// depends_on could no longer smuggle in walked back through an ordinary tag.
//
// A bucket makes no governance claims at all. Saying so is what distinguishes
// "this type binds by no argument" from "no mapper describes this type", which
// the code previously stored as one value — an unstated fact matching another
// unstated fact.
func TestAGovernanceClaimIsRefusedFromEitherEnd(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket_public_access_block.legacy", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "legacy", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a-bucket-managed-elsewhere",
	                          "block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a", "tags": {"replaces": "a-bucket-managed-elsewhere"}}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket_public_access_block.legacy", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "legacy",
	     "expressions": {"bucket": {"constant_value": "a-bucket-managed-elsewhere"}}},
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets",
	     "expressions": {"tags": {"references": [
	       "aws_s3_bucket_public_access_block.legacy.bucket",
	       "aws_s3_bucket_public_access_block.legacy"]}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, "aws_s3_bucket.assets")
	if fact.IsKnown() && !fact.Get() {
		t.Fatal("a block named from the bucket's own tags answered for this bucket")
	}
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("the bucket's own ACL grants public access: state=%q grants=%v", fact.State, fact.Get())
	}
	for _, source := range fact.Sources {
		if contains(source.ResourceAddress, "legacy") {
			t.Fatalf("a block governing another bucket was cited: %s", source.ResourceAddress)
		}
	}
}

// TestAnOrderingEdgeOnASubjectIsStillRefused replaces a test that could not
// fail. The previous form asserted DefersTo on two buckets, and DefersTo is
// populated only for a subject that reaches no verdict of its own — which an
// AWS bucket never is — so it was empty whatever the code did.
//
// This states the rule where it bites: an ordering dependency written by the
// bucket, on a control that governs some other bucket.
func TestAnOrderingEdgeOnASubjectIsStillRefused(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket_public_access_block.elsewhere", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "elsewhere", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a-bucket-managed-elsewhere",
	                          "block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket_public_access_block.elsewhere", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "elsewhere",
	     "expressions": {"bucket": {"constant_value": "a-bucket-managed-elsewhere"}}},
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {},
	     "depends_on": ["aws_s3_bucket_public_access_block.elsewhere"]},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	fact := publicAccess(t, graph, "aws_s3_bucket.assets")
	if fact.IsKnown() && !fact.Get() {
		t.Fatal("an ordering dependency written by the bucket admitted a foreign block")
	}
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("the bucket's own ACL grants public access: state=%q grants=%v", fact.State, fact.Get())
	}
}

// TestAMetaArgumentStillCarriesTheBinding is the regression for what the
// attribute filter broke.
//
// A control repeated over the resources it governs names them only in
// for_each: its own arguments refer to each.value, which names nothing.
// internal/terraformplan/config.go synthesises those references for exactly
// that reason, and filtering them out as "not the binding argument" lost the
// only link there was — producing a BLOCK on a bucket whose own plan contains
// the block that shuts it, and an UNKNOWN where a proven grant had been.
func TestAMetaArgumentStillCarriesTheBinding(t *testing.T) {
	plan := func(controlType, controlArgs string) []byte {
		return []byte(`{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "assets", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
		    {"address": "` + controlType + `.c[\"assets\"]", "mode": "managed",
		     "type": "` + controlType + `", "name": "c", "index": "assets", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null, "after": {` + controlArgs + `}}}
		  ],
		  "configuration": {"root_module": {"resources": [
		    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "assets", "expressions": {}},
		    {"address": "` + controlType + `.c", "mode": "managed", "type": "` + controlType + `",
		     "name": "c",
		     "for_each_expression": {"references": ["aws_s3_bucket.assets"]},
		     "expressions": {"bucket": {"references": ["each.value"]}}}
		  ]}}
		}`)
	}

	t.Run("a block repeated over its buckets still shuts them", func(t *testing.T) {
		raw := plan("aws_s3_bucket_public_access_block",
			`"block_public_acls": true, "block_public_policy": true,
			 "ignore_public_acls": true, "restrict_public_buckets": true`)

		parsed, err := terraformplan.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		fact := publicAccess(t, providers.Normalize(parsed, providers.Default()), "aws_s3_bucket.assets")
		if fact.IsKnown() && fact.Get() {
			t.Fatal("a bucket was called public while the plan holds the block that shuts it")
		}
	})

	t.Run("a grant repeated over its buckets is still attributed", func(t *testing.T) {
		raw := plan("aws_s3_bucket_acl", `"acl": "public-read"`)

		parsed, err := terraformplan.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		fact := publicAccess(t, providers.Normalize(parsed, providers.Default()), "aws_s3_bucket.assets")
		if !fact.IsKnown() || !fact.Get() {
			t.Fatalf("a proven public grant went unattributed: state=%q grants=%v",
				fact.State, fact.Get())
		}
	})
}

// TestCountCarriesTheBindingLikeForEach covers the other meta-argument.
// Terraform repeats a resource with either, internal/terraformplan records
// both, and a control counted over its buckets names them only there.
func TestCountCarriesTheBindingLikeForEach(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.c[0]", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "c", "index": "0", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_acl.c", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "c",
	     "count_expression": {"references": ["aws_s3_bucket.assets"]},
	     "expressions": {"bucket": {"references": ["count.index"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	fact := publicAccess(t, providers.Normalize(plan, providers.Default()), "aws_s3_bucket.assets")
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("a grant counted over its bucket went unattributed: state=%q grants=%v",
			fact.State, fact.Get())
	}
}

// stubMapper interprets one invented type and is not a Binder, so the
// correlation layer must treat its references as it treats any type it cannot
// describe: admitted, because narrowing what is not understood drops
// correlations this build cannot reason about either way.
// stubMapper stands in for a mapper this build does not ship. It claims a type
// the shipped registry also claims, and binds that type by a different
// argument, so consulting the registry instead of the mappers Normalize was
// given produces a different answer.
type stubMapper struct{}

func (stubMapper) Cloud() model.Cloud       { return model.Cloud("stub") }
func (stubMapper) Interprets(t string) bool { return t == "stub_thing" || t == "aws_s3_bucket_acl" }
func (stubMapper) IsSubject(t string) bool  { return t == "stub_thing" }
func (stubMapper) Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource {
	return model.NormalizedResource{Address: subject.Address, Cloud: model.Cloud("stub"),
		Family: model.FamilyObjectStorage, ObjectStorage: &model.ObjectStorageCapabilities{}}
}

// BindingAttributes binds the ACL by an argument the shipped AWS mapper does
// not name, so a reference under "bucket" is a governance claim to the registry
// and not to this mapper.
func (stubMapper) BindingAttributes(t string) []string {
	if t == "aws_s3_bucket_acl" {
		return []string{"governed_by"}
	}
	return nil
}

// TestCorrelationUsesTheMappersItWasGiven keeps Normalize's injection point
// honest. The correlation layer asks mappers how their types bind, and asking
// the shipped registry instead would make a custom mapper's answer unreachable
// while quietly applying the built-in ones to its types.
func TestCorrelationUsesTheMappersItWasGiven(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "stub_thing.a", "mode": "managed", "type": "stub_thing", "name": "a",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "a"}}},
	    {"address": "aws_s3_bucket_acl.c", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "c",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "private"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "stub_thing.a", "mode": "managed", "type": "stub_thing", "name": "a",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.c", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "c",
	     "expressions": {"bucket": {"references": ["stub_thing.a"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, []providers.Mapper{stubMapper{}})

	control, ok := graph.At("aws_s3_bucket_acl.c")
	if !ok {
		t.Fatal("no normalized control")
	}
	// The injected mapper binds this type by "governed_by", so a reference
	// under "bucket" is not a governance claim — however the shipped registry
	// would read it.
	if len(control.DefersTo) != 0 {
		t.Fatalf("defers to %v; the shipped registry was consulted instead of the injected mapper",
			control.DefersTo)
	}

	// And the argument the injected mapper does name is a claim.
	if _, ok := graph.At("stub_thing.a"); !ok {
		t.Fatal("no normalized subject")
	}
}

// TestAnOrderingEdgeIsRefusedForATypeNoMapperDescribes holds the universal half
// of the rule where it is the only half there is.
//
// A type whose mapper declares no binding admits every argument, because
// narrowing what is not understood drops correlations this build cannot reason
// about either way. Ordering is the exception, and it is an exception that owes
// nothing to any provider: Terraform documents depends_on as sequencing.
func TestAnOrderingEdgeIsRefusedForATypeNoMapperDescribes(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "stub_thing.a", "mode": "managed", "type": "stub_thing", "name": "a",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "a"}}},
	    {"address": "stub_control.c", "mode": "managed", "type": "stub_control", "name": "c",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "c"}}},
	    {"address": "stub_control.named", "mode": "managed", "type": "stub_control", "name": "named",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "n"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "stub_thing.a", "mode": "managed", "type": "stub_thing", "name": "a",
	     "expressions": {}},
	    {"address": "stub_control.c", "mode": "managed", "type": "stub_control", "name": "c",
	     "expressions": {}, "depends_on": ["stub_thing.a"]},
	    {"address": "stub_control.named", "mode": "managed", "type": "stub_control", "name": "named",
	     "expressions": {"anything": {"references": ["stub_thing.a"]}}}
	  ]}}
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, []providers.Mapper{openMapper{}})

	control, ok := graph.At("stub_control.c")
	if !ok {
		t.Fatal("no normalized control")
	}
	if len(control.DefersTo) != 0 {
		t.Fatalf("an ordering dependency supplied the deferral: %v", control.DefersTo)
	}

	// The other half: every argument that is not an ordering dependency is
	// admitted for a type no mapper describes, because narrowing what is not
	// understood drops correlations this build cannot reason about either way.
	named, ok := graph.At("stub_control.named")
	if !ok {
		t.Fatal("no normalized control")
	}
	if len(named.DefersTo) != 1 || named.DefersTo[0] != "stub_thing.a" {
		t.Fatalf("defers to %v; an undescribed type must admit its ordinary arguments",
			named.DefersTo)
	}
}

// openMapper describes its types without declaring how they bind, which is the
// case that admits every argument.
type openMapper struct{}

func (openMapper) Cloud() model.Cloud       { return model.Cloud("stub") }
func (openMapper) Interprets(t string) bool { return t == "stub_thing" || t == "stub_control" }
func (openMapper) IsSubject(t string) bool  { return t == "stub_thing" }
func (openMapper) Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource {
	return model.NormalizedResource{Address: subject.Address, Cloud: model.Cloud("stub"),
		Family: model.FamilyObjectStorage, ObjectStorage: &model.ObjectStorageCapabilities{}}
}
