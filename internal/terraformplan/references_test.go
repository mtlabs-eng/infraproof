package terraformplan

import (
	"reflect"
	"strings"
	"testing"
)

// Correlating a bucket with the resources that control its access cannot be
// done by matching attribute values: in a plan, a public-access-block's bucket
// field is the bucket's id, which is unknown until apply. The configuration
// block records the reference by address instead, and that is the only link
// that survives planning.
func TestConfigurationReferencesAreCaptured(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	      "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    },
	    {
	      "address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	      "type": "aws_s3_bucket_public_access_block", "name": "assets",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    }
	  ],
	  "configuration": {
	    "root_module": {
	      "resources": [
	        {
	          "address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	          "name": "assets", "provider_config_key": "aws",
	          "expressions": {"bucket": {"constant_value": "example-assets"}}
	        },
	        {
	          "address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	          "type": "aws_s3_bucket_public_access_block", "name": "assets",
	          "provider_config_key": "aws",
	          "expressions": {
	            "bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]},
	            "block_public_policy": {"constant_value": true}
	          }
	        }
	      ]
	    }
	  }
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	block := changeAt(t, plan, "aws_s3_bucket_public_access_block.assets")
	want := []ExpressionReference{{Attribute: "bucket", Target: "aws_s3_bucket.assets"}}
	if !reflect.DeepEqual(block.References, want) {
		t.Fatalf("references = %v, want %v", block.References, want)
	}

	bucket := changeAt(t, plan, "aws_s3_bucket.assets")
	if len(bucket.References) != 0 {
		t.Fatalf("a resource with only constant expressions has no references, got %v", bucket.References)
	}
}

// TestAttributeReferencesCollapseToTheResource keeps one link per referenced
// resource. Terraform emits both the attribute form and the bare resource form
// of the same reference; only the second is an address.
func TestAttributeReferencesCollapseToTheResource(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	holder := changeAt(t, plan, "terraform_data.sensitive_holder")
	want := []ExpressionReference{{Attribute: "input", Target: "random_password.secret"}}
	if !reflect.DeepEqual(holder.References, want) {
		t.Fatalf("references = %v, want %v", holder.References, want)
	}
}

// TestNonResourceReferencesAreDropped keeps count.index, each.key and variables
// out of the graph. They are references, but not to resources, and a
// correlation edge to "var.name" would be meaningless.
func TestNonResourceReferencesAreDropped(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	for _, address := range []string{"null_resource.counted[0]", `null_resource.keyed["eu"]`, "terraform_data.known_secret"} {
		t.Run(address, func(t *testing.T) {
			if got := changeAt(t, plan, address).References; len(got) != 0 {
				t.Fatalf("references = %v, want none — count.index, each.key and var are not resources", got)
			}
		})
	}
}

// TestReferencesResolveThroughModules mirrors the provider-alias walk: a
// configuration reference inside a module is module-relative and has to be
// qualified before it names anything.
func TestReferencesResolveThroughModules(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "module.storage.aws_s3_bucket.assets", "module_address": "module.storage",
	      "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    },
	    {
	      "address": "module.storage.aws_s3_bucket_public_access_block.assets[0]",
	      "module_address": "module.storage", "index": 0,
	      "mode": "managed", "type": "aws_s3_bucket_public_access_block", "name": "assets",
	      "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    }
	  ],
	  "configuration": {
	    "root_module": {
	      "module_calls": {
	        "storage": {
	          "source": "./modules/storage",
	          "module": {
	            "resources": [
	              {
	                "address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	                "name": "assets", "expressions": {}
	              },
	              {
	                "address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	                "type": "aws_s3_bucket_public_access_block", "name": "assets",
	                "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}
	              }
	            ]
	          }
	        }
	      }
	    }
	  }
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	block := changeAt(t, plan, "module.storage.aws_s3_bucket_public_access_block.assets[0]")
	want := []ExpressionReference{{Attribute: "bucket", Target: "module.storage.aws_s3_bucket.assets"}}
	if !reflect.DeepEqual(block.References, want) {
		t.Fatalf("references = %v, want %v", block.References, want)
	}
}

// TestReferencesAreSortedAndDeduplicated keeps the graph deterministic, for the
// same reason the Evidence Bundle orders its collections.
func TestReferencesAreSortedAndDeduplicated(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "a.one", "mode": "managed", "type": "a", "name": "one", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "a.two", "mode": "managed", "type": "a", "name": "two", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "b.link", "mode": "managed", "type": "b", "name": "link", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}}
	  ],
	  "configuration": {
	    "root_module": {
	      "resources": [
	        {"address": "a.one", "mode": "managed", "type": "a", "name": "one", "expressions": {}},
	        {"address": "a.two", "mode": "managed", "type": "a", "name": "two", "expressions": {}},
	        {"address": "b.link", "mode": "managed", "type": "b", "name": "link",
	         "expressions": {
	           "zebra": {"references": ["a.two.id", "a.two"]},
	           "apple": {"references": ["a.one.id", "a.one", "a.one.arn", "a.one"]}
	         }}
	      ]
	    }
	  }
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := []ExpressionReference{
		{Attribute: "apple", Target: "a.one"},
		{Attribute: "zebra", Target: "a.two"},
	}
	if got := changeAt(t, plan, "b.link").References; !reflect.DeepEqual(got, want) {
		t.Fatalf("references = %v, want %v", got, want)
	}
}

func TestReferencesAreAbsentWithoutAConfigurationBlock(t *testing.T) {
	if got := onlyChange(t, "create").References; len(got) != 0 {
		t.Fatalf("references = %v, want none", got)
	}
}

// TestMalformedExpressionsAreReported keeps the new walk inside the same
// error-reporting contract as the rest of the package.
func TestMalformedExpressionsAreReported(t *testing.T) {
	cases := map[string]string{
		"expressions is not an object":   `"expressions": 7`,
		"an expression is not an object": `"expressions": {"bucket": 7}`,
		"references is not an array":     `"expressions": {"bucket": {"references": "a.b"}}`,
		"a reference is not a string":    `"expressions": {"bucket": {"references": [7]}}`,
	}

	for name, fragment := range cases {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{
			  "format_version": "1.2",
			  "resource_changes": [],
			  "configuration": {"root_module": {"resources": [
			    {"address": "a.b", "mode": "managed", "type": "a", "name": "b", ` + fragment + `}
			  ]}}
			}`)

			_, err := Parse(raw)
			if err == nil {
				t.Fatal("malformed expressions should be reported")
			}
			if !contains(err.Error(), "expressions") {
				t.Fatalf("error %q does not locate the expressions block", err.Error())
			}
		})
	}
}

// TestConfigAddressMatchesReferenceTargets is what makes correlation possible:
// a reference names a resource the way the configuration block spells it, with
// no count or for_each key, so a subject has to be spelled the same way before
// the two can be compared.
func TestConfigAddressMatchesReferenceTargets(t *testing.T) {
	cases := map[string]string{
		"aws_s3_bucket.assets":                         "aws_s3_bucket.assets",
		"aws_s3_bucket.assets[0]":                      "aws_s3_bucket.assets",
		`aws_s3_bucket.assets["eu"]`:                   "aws_s3_bucket.assets",
		`module.storage["eu"].aws_s3_bucket.assets[1]`: "module.storage.aws_s3_bucket.assets",
	}

	for address, want := range cases {
		t.Run(address, func(t *testing.T) {
			change := ResourceChange{Address: address}
			if got := change.ConfigAddress(); got != want {
				t.Fatalf("ConfigAddress() = %q, want %q", got, want)
			}
		})
	}
}

// TestEveryInstanceSharesOneConfigAddress is the property correlation relies
// on: count and for_each instances of one configuration block all correlate to
// the same referenced resource.
func TestEveryInstanceSharesOneConfigAddress(t *testing.T) {
	first := ResourceChange{Address: "aws_s3_bucket.assets[0]"}
	second := ResourceChange{Address: "aws_s3_bucket.assets[1]"}

	if first.ConfigAddress() != second.ConfigAddress() {
		t.Fatalf("%q and %q should share a configuration address", first.ConfigAddress(), second.ConfigAddress())
	}
}

// TestNestedBlockExpressionsParse covers the shape that broke the canonical S3
// stack. In the configuration representation an attribute is an object but a
// nested block is an array of objects, and rejecting the array turns a
// best-practice plan into invalid input.
func TestNestedBlockExpressionsParse(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
	     "type": "aws_s3_bucket_ownership_controls", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {"bucket": {"constant_value": "example"}}},
	    {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
	     "type": "aws_s3_bucket_ownership_controls", "name": "assets",
	     "expressions": {
	       "bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]},
	       "rule": [{"object_ownership": {"constant_value": "BucketOwnerPreferred"}}]
	     }}
	  ]}}
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("a nested block should not make a plan unreadable: %v", err)
	}
	controls := changeAt(t, plan, "aws_s3_bucket_ownership_controls.assets")
	if len(controls.References) != 1 || controls.References[0].Target != "aws_s3_bucket.assets" {
		t.Fatalf("references = %v", controls.References)
	}
}

// TestReferencesInsideNestedBlocksAreFound keeps the recursion honest: a
// reference buried in a block is still a reference.
func TestReferencesInsideNestedBlocksAreFound(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "a.target", "mode": "managed", "type": "a", "name": "target", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "b.holder", "mode": "managed", "type": "b", "name": "holder", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "a.target", "mode": "managed", "type": "a", "name": "target", "expressions": {}},
	    {"address": "b.holder", "mode": "managed", "type": "b", "name": "holder",
	     "expressions": {"outer": [{"inner": [{"deep": {"references": ["a.target.id", "a.target"]}}]}]}}
	  ]}}
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	refs := changeAt(t, plan, "b.holder").References
	if len(refs) != 1 || refs[0].Target != "a.target" {
		t.Fatalf("references = %v", refs)
	}
	if refs[0].Attribute != "outer.inner.deep" {
		t.Fatalf("attribute = %q, want the nested path", refs[0].Attribute)
	}
}

// TestMetaArgumentReferencesAreCaptured covers the idiomatic
// "for_each = aws_s3_bucket.b" pattern, where the only link between a control
// and the resource it controls is the meta-argument: its bucket attribute
// refers to each.value, which names nothing.
func TestMetaArgumentReferencesAreCaptured(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"one\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "b", "index": "one", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "aws_s3_bucket_public_access_block.b[\"one\"]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "b", "index": "one", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "a.dependent", "mode": "managed", "type": "a", "name": "dependent", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {"bucket": {"references": ["each.key"]}}},
	    {"address": "aws_s3_bucket_public_access_block.b", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "b",
	     "for_each_expression": {"references": ["aws_s3_bucket.b"]},
	     "expressions": {"bucket": {"references": ["each.value.id", "each.value"]}}},
	    {"address": "a.dependent", "mode": "managed", "type": "a", "name": "dependent",
	     "depends_on": ["aws_s3_bucket.b"],
	     "expressions": {}}
	  ]}}
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	block := changeAt(t, plan, `aws_s3_bucket_public_access_block.b["one"]`)
	if len(block.References) != 1 || block.References[0].Target != "aws_s3_bucket.b" {
		t.Fatalf("for_each references = %v", block.References)
	}
	if block.References[0].Attribute != "for_each" {
		t.Fatalf("attribute = %q, want for_each", block.References[0].Attribute)
	}

	dependent := changeAt(t, plan, "a.dependent")
	if len(dependent.References) != 1 || dependent.References[0].Attribute != "depends_on" {
		t.Fatalf("depends_on references = %v", dependent.References)
	}
}

// TestInstanceKeysSeparateSiblings is what stops one instance's controls being
// read as another's. Every instance of a configuration block shares one
// configuration address, so the address alone cannot tell them apart.
func TestInstanceKeysSeparateSiblings(t *testing.T) {
	cases := map[string][]string{
		"aws_s3_bucket.b":                         nil,
		`aws_s3_bucket.b["one"]`:                  {"one"},
		"aws_s3_bucket.b[0]":                      {"0"},
		`module.m["eu"].aws_s3_bucket.b`:          {"eu"},
		`module.m["eu"].aws_s3_bucket.b["one"]`:   {"eu", "one"},
		`module.m[0].module.n[1].aws_s3_bucket.b`: {"0", "1"},
		`aws_s3_bucket.b["a]b"]`:                  {"a]b"},
	}

	for address, want := range cases {
		t.Run(address, func(t *testing.T) {
			got := ResourceChange{Address: address}.InstanceKeys()
			if len(got) != len(want) {
				t.Fatalf("keys = %v, want %v", got, want)
			}
			for i := range want {
				if got[i] != want[i] {
					t.Fatalf("keys = %v, want %v", got, want)
				}
			}
		})
	}
}

// TestAKeyedReferenceKeepsItsKey is the information the correlation layer was
// missing. Terraform writes the instance a reference names — aws_s3_bucket.b["a"]
// — alongside the bare resource form, and discarding the key leaves nothing to
// tell one instance's controls from another's.
func TestAKeyedReferenceKeepsItsKey(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"a\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b[\"a\"].id", "aws_s3_bucket.b[\"a\"]", "aws_s3_bucket.b"]}}}
	  ]}}
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	refs := changeAt(t, plan, "aws_s3_bucket_acl.open").References
	if len(refs) != 1 {
		t.Fatalf("references = %v, want one", refs)
	}
	if refs[0].Target != "aws_s3_bucket.b" {
		t.Fatalf("target = %q", refs[0].Target)
	}
	if len(refs[0].TargetKeys) != 1 || refs[0].TargetKeys[0] != "a" {
		t.Fatalf("target keys = %v, want [a] — the bare sibling must not erase the keyed form", refs[0].TargetKeys)
	}
}

// TestABareReferenceCarriesNoKeys keeps the other form working. A meta-argument
// such as "for_each = aws_s3_bucket.b" names the whole resource on purpose, and
// inventing a key for it would break the pairing it exists to express.
func TestABareReferenceCarriesNoKeys(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"a\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "aws_s3_bucket_acl.b[\"a\"]", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "b", "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.b", "mode": "managed", "type": "aws_s3_bucket_acl", "name": "b",
	     "for_each_expression": {"references": ["aws_s3_bucket.b"]},
	     "expressions": {"bucket": {"references": ["each.value.id", "each.value"]}}}
	  ]}}
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	refs := changeAt(t, plan, `aws_s3_bucket_acl.b["a"]`).References
	if len(refs) != 1 || refs[0].Target != "aws_s3_bucket.b" {
		t.Fatalf("references = %v", refs)
	}
	if len(refs[0].TargetKeys) != 0 {
		t.Fatalf("target keys = %v, want none", refs[0].TargetKeys)
	}
}

// TestKeyedAndBareReferencesToDifferentInstancesBothSurvive keeps two distinct
// links distinct.
func TestKeyedAndBareReferencesToDifferentInstancesBothSurvive(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "a.one", "mode": "managed", "type": "a", "name": "one", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "b.target", "mode": "managed", "type": "b", "name": "target", "expressions": {}},
	    {"address": "a.one", "mode": "managed", "type": "a", "name": "one",
	     "expressions": {
	       "first":  {"references": ["b.target[\"x\"].id", "b.target[\"x\"]", "b.target"]},
	       "second": {"references": ["b.target[\"y\"].id", "b.target[\"y\"]", "b.target"]}
	     }}
	  ]}}
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	refs := changeAt(t, plan, "a.one").References
	if len(refs) != 2 {
		t.Fatalf("references = %v, want two", refs)
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		if len(ref.TargetKeys) != 1 {
			t.Fatalf("reference %v lost its key", ref)
		}
		seen[ref.TargetKeys[0]] = true
	}
	if !seen["x"] || !seen["y"] {
		t.Fatalf("keys seen = %v, want x and y", seen)
	}
}

// TestModuleKeysAreStructural separates the two kinds of repetition. A module
// key is shared by everything inside that module instance, so pairing on it
// asserts nothing; a resource key is chosen independently by each resource, so
// pairing on it is an assumption.
func TestModuleKeysAreStructural(t *testing.T) {
	cases := map[string]struct {
		address, module   string
		module_, resource int
	}{
		"no repetition":        {"aws_s3_bucket.b", "", 0, 0},
		"resource repeated":    {`aws_s3_bucket.b["a"]`, "", 0, 1},
		"module repeated":      {`module.m["eu"].aws_s3_bucket.b`, `module.m["eu"]`, 1, 0},
		"both repeated":        {`module.m["eu"].aws_s3_bucket.b["a"]`, `module.m["eu"]`, 1, 1},
		"two modules repeated": {`module.m["eu"].module.n["x"].aws_s3_bucket.b`, `module.m["eu"].module.n["x"]`, 2, 0},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := ResourceChange{Address: c.address, ModuleAddress: c.module}
			if got := len(change.ModuleKeys()); got != c.module_ {
				t.Fatalf("module keys = %d, want %d", got, c.module_)
			}
			if got := len(change.InstanceKeys()) - len(change.ModuleKeys()); got != c.resource {
				t.Fatalf("resource keys = %d, want %d", got, c.resource)
			}
		})
	}
}

// TestARepeatedDeclarationIsRecorded separates what the configuration declares
// from what survives into the changes. A resource declared with for_each is
// repeated whether or not every instance is present, and correlation needs the
// declaration: counting surviving instances would call a partial plan
// unambiguous.
func TestARepeatedDeclarationIsRecorded(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b[\"z\"]", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}},
	    {"address": "aws_s3_bucket.single", "mode": "managed", "type": "aws_s3_bucket", "name": "single",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "s"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "for_each_expression": {"constant_value": ["a", "z"]}, "expressions": {}},
	    {"address": "aws_s3_bucket.single", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "single", "expressions": {}}
	  ]}}
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !changeAt(t, plan, `aws_s3_bucket.b["z"]`).DeclaredRepeated {
		t.Fatal("a resource declared with for_each is repeated even when one instance is in the plan")
	}
	if changeAt(t, plan, "aws_s3_bucket.single").DeclaredRepeated {
		t.Fatal("a resource declared without repetition is not repeated")
	}
}

// TestTwoConfigurationEntriesAtOneAddressAreRefused holds one rule in the two
// places a plan states an identity.
//
// resource_changes refuses two entries at one address, because an address
// identifies one change and a verdict about one would answer for the other.
// The configuration walk accepted them and kept the last, so a second entry
// erased the first one's references — and a reference is the only dependable
// link between a resource and the controls over it. A plan naming the bucket an
// ACL applies to, then repeating the ACL with no arguments, reported the grant
// as undetermined rather than as the grant it states.
//
// Nothing about that is visible to a reader: the plan parses, the verdict moves,
// and no diagnostic says why.
func TestTwoConfigurationEntriesAtOneAddressAreRefused(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}},
	    {"address": "aws_s3_bucket_acl.a", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.a", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "a", "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.b.id", "aws_s3_bucket.b"]}}},
	    {"address": "aws_s3_bucket_acl.a", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "a", "expressions": {}}
	  ]}}
	}`)

	_, err := Parse(raw)
	if err == nil {
		t.Fatal("a configuration declaring one address twice was accepted, and one of the two was discarded")
	}
	if !strings.Contains(err.Error(), "configuration.root_module.resources[2].address") {
		t.Errorf("the error does not locate the second entry: %v", err)
	}
	if strings.Contains(err.Error(), "aws_s3_bucket_acl.a") {
		t.Errorf("a plan value reached a diagnostic: %v", err)
	}
}

// TestOneAddressPerModuleIsNotOneAddressPerPlan keeps the rule where it
// belongs. Two modules declaring the same relative address are two resources,
// and the qualified address is what distinguishes them.
func TestOneAddressPerModuleIsNotOneAddressPerPlan(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.one.aws_s3_bucket.b", "module_address": "module.one", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}},
	    {"address": "module.two.aws_s3_bucket.b", "module_address": "module.two", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {
	    "one": {"module": {"resources": [
	      {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	       "expressions": {}}]}},
	    "two": {"module": {"resources": [
	      {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	       "expressions": {}}]}}
	  }}}
	}`)

	if _, err := Parse(raw); err != nil {
		t.Fatalf("two modules declaring the same relative address were refused: %v", err)
	}
}
