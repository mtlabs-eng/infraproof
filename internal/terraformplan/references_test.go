package terraformplan

import (
	"reflect"
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
