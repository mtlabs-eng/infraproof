package terraformplan

import "testing"

func TestNestedModuleAddressesArePreserved(t *testing.T) {
	plan := parseFixture(t, "nested-modules")

	cases := map[string]struct {
		module   string
		name     string
		index    string
		hasIndex bool
	}{
		"module.storage.aws_s3_bucket.assets":            {"module.storage", "assets", "", false},
		"module.storage.aws_s3_bucket.replicas[0]":       {"module.storage", "replicas", "0", true},
		"module.storage.module.inner.aws_s3_bucket.logs": {"module.storage.module.inner", "logs", "", false},
		`module.storage["eu"].aws_s3_bucket.keyed`:       {`module.storage["eu"]`, "keyed", "", false},
	}

	for address, want := range cases {
		t.Run(address, func(t *testing.T) {
			change := changeAt(t, plan, address)
			if change.ModuleAddress != want.module {
				t.Fatalf("module address = %q, want %q", change.ModuleAddress, want.module)
			}
			if change.Name != want.name {
				t.Fatalf("name = %q, want %q", change.Name, want.name)
			}
			if change.HasIndex != want.hasIndex {
				t.Fatalf("HasIndex = %v, want %v", change.HasIndex, want.hasIndex)
			}
			if change.Index != want.index {
				t.Fatalf("index = %q, want %q", change.Index, want.index)
			}
		})
	}
}

func TestStringIndexIsPreserved(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets[\"eu\"]",
	      "mode": "managed",
	      "type": "aws_s3_bucket",
	      "name": "assets",
	      "index": "eu",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {"actions": ["create"], "before": null, "after": {}}
	    }
	  ]
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := plan.ResourceChanges[0]
	if !change.HasIndex || change.Index != "eu" {
		t.Fatalf("HasIndex = %v index = %q, want true and eu", change.HasIndex, change.Index)
	}
}
