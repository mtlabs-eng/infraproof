package terraformplan

import "testing"

// TestStripIndexKeys pins the address normalisation the configuration walk
// depends on. A for_each key is an arbitrary string, so it can contain the very
// brackets that delimit it — which is why the scan tracks quoting.
func TestStripIndexKeys(t *testing.T) {
	cases := map[string]string{
		"aws_s3_bucket.assets":                      "aws_s3_bucket.assets",
		"aws_s3_bucket.assets[0]":                   "aws_s3_bucket.assets",
		"aws_s3_bucket.assets[12]":                  "aws_s3_bucket.assets",
		`aws_s3_bucket.assets["eu"]`:                "aws_s3_bucket.assets",
		`module.storage["eu"].aws_s3_bucket.assets`: "module.storage.aws_s3_bucket.assets",
		`module.storage[0].aws_s3_bucket.assets[1]`: "module.storage.aws_s3_bucket.assets",
		"module.storage.module.inner.aws_s3.bucket": "module.storage.module.inner.aws_s3.bucket",
		`aws_s3_bucket.assets["a.b"]`:               "aws_s3_bucket.assets",
		`aws_s3_bucket.assets["a]b"]`:               "aws_s3_bucket.assets",
		`aws_s3_bucket.assets["a[b"]`:               "aws_s3_bucket.assets",
		`aws_s3_bucket.assets["a\"b"]`:              "aws_s3_bucket.assets",
		`aws_s3_bucket.assets["a\\"]`:               "aws_s3_bucket.assets",
		`module.odd["a]b"].random_pet.inner`:        "module.odd.random_pet.inner",
		`module.odd["a]b"].random_pet.inner["c]d"]`: "module.odd.random_pet.inner",
		"": "",
	}

	for address, want := range cases {
		t.Run(address, func(t *testing.T) {
			if got := stripIndexKeys(address); got != want {
				t.Fatalf("stripIndexKeys(%q) = %q, want %q", address, got, want)
			}
		})
	}
}

// TestAliasResolvesThroughABracketedForEachKey is the same guarantee end to
// end. Terraform accepts a for_each key containing "]", and a normaliser that
// stopped at the first bracket would silently fail to match the configuration
// and drop the provider instance.
func TestAliasResolvesThroughABracketedForEachKey(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "module.odd[\"a]b\"].random_pet.inner",
	      "module_address": "module.odd[\"a]b\"]",
	      "mode": "managed",
	      "type": "random_pet",
	      "name": "inner",
	      "provider_name": "registry.terraform.io/hashicorp/random",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    }
	  ],
	  "configuration": {
	    "provider_config": {
	      "random.west": {
	        "name": "random",
	        "alias": "west",
	        "full_name": "registry.terraform.io/hashicorp/random"
	      }
	    },
	    "root_module": {
	      "module_calls": {
	        "odd": {
	          "source": "./modules/odd",
	          "module": {
	            "resources": [
	              {
	                "address": "random_pet.inner",
	                "mode": "managed",
	                "type": "random_pet",
	                "name": "inner",
	                "provider_config_key": "random.west"
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
	change := plan.ResourceChanges[0]
	if change.ProviderConfigKey != "random.west" {
		t.Fatalf("provider config key = %q, want random.west", change.ProviderConfigKey)
	}
	if change.ProviderAlias != "west" {
		t.Fatalf("provider alias = %q, want west", change.ProviderAlias)
	}
}

// TestEmptyForEachKeyIsNotAnAbsentIndex pins the reason HasIndex exists
// separately from Index. for_each = { "" = ... } is legal.
func TestEmptyForEachKeyIsNotAnAbsentIndex(t *testing.T) {
	withEmptyKey := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets[\"\"]",
	      "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "index": "",
	      "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    }
	  ]
	}`)
	withoutIndex := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets",
	      "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	      "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    }
	  ]
	}`)

	keyed, err := Parse(withEmptyKey)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	plain, err := Parse(withoutIndex)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !keyed.ResourceChanges[0].HasIndex {
		t.Fatal("an empty for_each key is an index and must report HasIndex")
	}
	if plain.ResourceChanges[0].HasIndex {
		t.Fatal("a resource without an index must not report HasIndex")
	}
	if keyed.ResourceChanges[0].Index != plain.ResourceChanges[0].Index {
		t.Fatal("this test is only meaningful when both render the same index text")
	}
}

func TestMalformedIndexIsReported(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets",
	      "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "index": {},
	      "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    }
	  ]
	}`)

	_, err := Parse(raw)
	if err == nil {
		t.Fatal("an index that is neither a string nor a number should be rejected")
	}
	if got := err.Error(); !contains(got, "index") {
		t.Fatalf("error %q does not locate the index", got)
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
