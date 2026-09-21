package providers_test

import (
	"fmt"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Each cloud names the same idea differently, and only an explicit declaration
// counts. A module named "staging" or a file called staging.tfplan is a guess
// about a name; docs/INTENT-CONTRACT.md is explicit that guessing is not
// sufficient evidence for blocking.
func TestEnvironmentIsReadFromAnExplicitDeclaration(t *testing.T) {
	cases := map[string]struct {
		resourceType string
		address      string
		attribute    string
	}{
		"AWS tags":   {"aws_s3_bucket", "aws_s3_bucket.b", "tags"},
		"Azure tags": {"azurerm_storage_account", "azurerm_storage_account.b", "tags"},
		"GCP labels": {"google_storage_bucket", "google_storage_bucket.b", "labels"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {"address": "%s", "mode": "managed", "type": "%s", "name": "b", "provider_name": "p",
			     "change": {"actions": ["create"], "before": null,
			                "after": {"name": "b", "%s": {"environment": "staging"}}}}
			  ]
			}`, tc.address, tc.resourceType, tc.attribute)

			resource := normalizedAt(t, raw, tc.address)
			if !resource.Environment.IsKnown() {
				t.Fatalf("environment = %q, want a known declaration", resource.Environment.State)
			}
			if resource.Environment.Get() != "staging" {
				t.Errorf("environment = %q", resource.Environment.Get())
			}
			if len(resource.Environment.Sources) == 0 {
				t.Error("the declaration must locate the attribute it came from")
			}
		})
	}
}

// TestAnEnvironmentKeyIsMatchedWithoutRegardToCase keeps a conventional tag
// readable however it was capitalized. "Environment" and "environment" are one
// declaration, not two.
func TestAnEnvironmentKeyIsMatchedWithoutRegardToCase(t *testing.T) {
	for _, key := range []string{"environment", "Environment", "ENVIRONMENT"} {
		t.Run(key, func(t *testing.T) {
			raw := fmt.Sprintf(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
			     "provider_name": "p",
			     "change": {"actions": ["create"], "before": null,
			                "after": {"bucket": "b", "tags": {"%s": "staging"}}}}
			  ]
			}`, key)

			resource := normalizedAt(t, raw, "aws_s3_bucket.b")
			if !resource.Environment.IsKnown() || resource.Environment.Get() != "staging" {
				t.Fatalf("environment = %v/%q", resource.Environment.State, resource.Environment.Get())
			}
		})
	}
}

// TestNothingUnstatedDeclaresAnEnvironment is the rule the M03 rounds
// converged on, applied to this fact. An absent tag, an unreadable one, and one
// of the wrong kind are all unstated, and an unstated environment agrees with
// nothing — least of all with whatever the contract happens to say.
func TestNothingUnstatedDeclaresAnEnvironment(t *testing.T) {
	cases := map[string]string{
		"no tags at all":            `"bucket": "b"`,
		"tags without the key":      `"bucket": "b", "tags": {"owner": "checkout"}`,
		"an empty value":            `"bucket": "b", "tags": {"environment": ""}`,
		"tags of the wrong kind":    `"bucket": "b", "tags": ["environment"]`,
		"a value of the wrong kind": `"bucket": "b", "tags": {"environment": ["staging"]}`,
	}

	for name, after := range cases {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
			     "provider_name": "p",
			     "change": {"actions": ["create"], "before": null, "after": {%s}}}
			  ]
			}`, after)

			resource := normalizedAt(t, raw, "aws_s3_bucket.b")
			if resource.Environment.IsKnown() {
				t.Fatalf("an unstated environment was read as %q", resource.Environment.Get())
			}
		})
	}
}

// TestAnUnreadableEnvironmentKeepsItsState separates "not declared" from "not
// readable", because the two produce different reports: one says the resource
// said nothing, the other says it said something this run could not see.
func TestAnUnreadableEnvironmentKeepsItsState(t *testing.T) {
	cases := map[string]struct {
		after string
		want  model.FactState
	}{
		"not yet known": {
			`"bucket": "b", "tags": null}, "after_unknown": {"tags": true`,
			model.FactUnknown,
		},
		"sensitive": {
			`"bucket": "b", "tags": {"environment": "staging"}}, "after_sensitive": {"tags": true`,
			model.FactRedacted,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
			     "provider_name": "p",
			     "change": {"actions": ["create"], "before": null, "after": {%s}}}
			  ]
			}`, tc.after)

			resource := normalizedAt(t, raw, "aws_s3_bucket.b")
			if resource.Environment.State != tc.want {
				t.Fatalf("state = %q, want %q", resource.Environment.State, tc.want)
			}
			if resource.Environment.IsKnown() {
				t.Error("an unreadable declaration must not present a value")
			}
		})
	}
}

// TestAnUninterpretedResourceDeclaresNoEnvironment keeps the fact tied to a
// mapper that understood the resource. Reading a tag block from a resource type
// no mapper claimed would be guessing that the provider calls it what AWS does.
func TestAnUninterpretedResourceDeclaresNoEnvironment(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "vendor_thing.b", "mode": "managed", "type": "vendor_thing", "name": "b",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"tags": {"environment": "staging"}}}}
	  ]
	}`

	resource := normalizedAt(t, raw, "vendor_thing.b")
	if resource.Interpreted {
		t.Fatal("no mapper should have claimed this resource")
	}
	if resource.Environment.IsKnown() {
		t.Fatalf("an uninterpreted resource declared %q", resource.Environment.Get())
	}
}

// TestTwoDeclarationsAreAmbiguousNotResolved is round eleven's finding one
// level up. Two controls of one kind over one subject is not a fact stated
// twice, it is a fact not stated: which of them the provider applies is not
// something the plan says.
//
// Keys() is sorted, so "Environment" precedes "environment" and taking the
// first match let a resource tagged with both report whichever sorted first —
// a plan declaring production passing a staging contract, with the bundle
// saying the change was consistent in every supported check.
func TestTwoDeclarationsAreAmbiguousNotResolved(t *testing.T) {
	cases := map[string]string{
		"differing in case":  `{"Environment": "staging", "environment": "production"}`,
		"the other way":      `{"Environment": "production", "environment": "staging"}`,
		"three of them":      `{"ENVIRONMENT": "a", "Environment": "b", "environment": "c"}`,
		"one of them absent": `{"Environment": "staging", "environment": ""}`,
	}

	for name, tags := range cases {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
			     "provider_name": "p",
			     "change": {"actions": ["create"], "before": null,
			                "after": {"bucket": "b", "tags": %s}}}
			  ]
			}`, tags)

			resource := normalizedAt(t, raw, "aws_s3_bucket.b")
			if resource.Environment.IsKnown() {
				t.Fatalf("two declarations resolved to %q", resource.Environment.Get())
			}
		})
	}
}

// TestOneDeclarationRepeatedIsStillOneDeclaration keeps the ambiguity rule from
// costing the ordinary case. Two keys that agree say one thing.
func TestOneDeclarationRepeatedIsStillOneDeclaration(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "b", "tags": {"Environment": "staging", "environment": "staging"}}}}
	  ]
	}`

	resource := normalizedAt(t, raw, "aws_s3_bucket.b")
	if !resource.Environment.IsKnown() || resource.Environment.Get() != "staging" {
		t.Fatalf("two agreeing declarations gave %v/%q",
			resource.Environment.State, resource.Environment.Get())
	}
}

func normalizedAt(t *testing.T, raw, address string) model.NormalizedResource {
	t.Helper()
	plan, err := terraformplan.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, raw)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At(address)
	if !ok {
		t.Fatalf("no normalized resource at %s", address)
	}
	return resource
}

// TestAnUnreadableValueKeepsItsStateWhenTheBlockIsReadable covers the marker on
// the value rather than on the whole attribute.
//
// Removing the per-value check does not leak — the parser reports an unreadable
// value as KindAbsent — but it degrades REDACTED to ABSENT, turning "the
// resource said something this run could not see" into "the resource said
// nothing". Those produce different reports, and after this milestone they
// produce different decisions: one is a required unknown and the other is not.
func TestAnUnreadableValueKeepsItsStateWhenTheBlockIsReadable(t *testing.T) {
	cases := map[string]struct {
		after string
		want  model.FactState
	}{
		"the value is sensitive": {
			`"bucket": "b", "tags": {"owner": "checkout", "environment": "staging"}},
			 "after_sensitive": {"tags": {"environment": true}`,
			model.FactRedacted,
		},
		"the value is not yet known": {
			`"bucket": "b", "tags": {"owner": "checkout", "environment": null}},
			 "after_unknown": {"tags": {"environment": true}`,
			model.FactUnknown,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			raw := fmt.Sprintf(`{
			  "format_version": "1.2",
			  "resource_changes": [
			    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
			     "provider_name": "p",
			     "change": {"actions": ["create"], "before": null, "after": {%s}}}
			  ]
			}`, tc.after)

			resource := normalizedAt(t, raw, "aws_s3_bucket.b")
			if resource.Environment.State != tc.want {
				t.Fatalf("state = %q, want %q", resource.Environment.State, tc.want)
			}
		})
	}
}

// TestAControlDefersOnlyToASubject keeps a deferral from pointing at another
// control.
//
// A control resource's meaning belongs to the subject it governs. Two controls
// correlated with each other — a policy and an ownership-controls block both
// naming the same bucket are related through it — would otherwise vouch for one
// another, and the question of whether anything judged them would be passed
// back and forth and never answered.
func TestAControlDefersOnlyToASubject(t *testing.T) {
	// Two controls and no bucket. They are correlated with each other through
	// the bucket they both name, which is not in this plan.
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket_policy.open", "mode": "managed", "type": "aws_s3_bucket_policy",
	     "name": "open", "provider_name": "registry.terraform.io/hashicorp/aws",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "elsewhere"}}},
	    {"address": "aws_s3_bucket_ownership_controls.own", "mode": "managed",
	     "type": "aws_s3_bucket_ownership_controls", "name": "own",
	     "provider_name": "registry.terraform.io/hashicorp/aws",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "elsewhere"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket_policy.open", "mode": "managed", "type": "aws_s3_bucket_policy",
	     "name": "open",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket_ownership_controls.own"]}}},
	    {"address": "aws_s3_bucket_ownership_controls.own", "mode": "managed",
	     "type": "aws_s3_bucket_ownership_controls", "name": "own",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket_policy.open"]}}}
	  ]}}
	}`

	for _, address := range []string{
		"aws_s3_bucket_policy.open", "aws_s3_bucket_ownership_controls.own",
	} {
		resource := normalizedAt(t, raw, address)
		if !resource.Interpreted {
			t.Fatalf("%s should have been understood", address)
		}
		if len(resource.DefersTo) != 0 {
			t.Errorf("%s defers to %v; a control is not a subject", address, resource.DefersTo)
		}
	}
}

// TestAControlDefersToTheSubjectItGoverns keeps the rule from costing the
// ordinary case, where the bucket is right there.
func TestAControlDefersToTheSubjectItGoverns(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "provider_name": "registry.terraform.io/hashicorp/aws",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "provider_name": "registry.terraform.io/hashicorp/aws",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`

	control := normalizedAt(t, raw, "aws_s3_bucket_public_access_block.assets")
	if len(control.DefersTo) != 1 || control.DefersTo[0] != "aws_s3_bucket.assets" {
		t.Fatalf("defers to %v, want the bucket it governs", control.DefersTo)
	}
}

// TestAResourceThatGovernsWithoutNamingDefersToWhatItGoverns covers the two
// deferrals the configuration does not record as a reference.
//
// An AWS account-wide block is scoped to the provider instance and names no
// bucket. An Azure storage account is named by its containers rather than
// naming them. In both cases the reference-based default finds nothing, and
// without the mapper saying so each would read as a resource nothing examined —
// which is false, since every verdict in the plan consults it.
func TestAResourceThatGovernsWithoutNamingDefersToWhatItGoverns(t *testing.T) {
	t.Run("an AWS account block", func(t *testing.T) {
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "assets", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
		    {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
		     "type": "aws_s3_account_public_access_block", "name": "this", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"block_public_acls": true, "block_public_policy": true,
		                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
		  ],
		  "configuration": {
		    "provider_config": {"aws": {"name": "aws", "full_name": "p"}},
		    "root_module": {"resources": [
		      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		       "name": "assets", "provider_config_key": "aws", "expressions": {}},
		      {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
		       "type": "aws_s3_account_public_access_block", "name": "this",
		       "provider_config_key": "aws", "expressions": {}}
		    ]}
		  }
		}`

		block := normalizedAt(t, raw, "aws_s3_account_public_access_block.this")
		if len(block.DefersTo) != 1 || block.DefersTo[0] != "aws_s3_bucket.assets" {
			t.Fatalf("defers to %v, want the bucket it governs", block.DefersTo)
		}
	})

	t.Run("an Azure account with a container", func(t *testing.T) {
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "azurerm_storage_account.sa", "mode": "managed",
		     "type": "azurerm_storage_account", "name": "sa", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"name": "s", "allow_nested_items_to_be_public": false}}},
		    {"address": "azurerm_storage_container.assets", "mode": "managed",
		     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"name": "assets", "container_access_type": "private"}}}
		  ],
		  "configuration": {"root_module": {"resources": [
		    {"address": "azurerm_storage_account.sa", "mode": "managed",
		     "type": "azurerm_storage_account", "name": "sa", "expressions": {}},
		    {"address": "azurerm_storage_container.assets", "mode": "managed",
		     "type": "azurerm_storage_container", "name": "assets",
		     "expressions": {"storage_account_id": {"references": [
		       "azurerm_storage_account.sa.id", "azurerm_storage_account.sa"]}}}
		  ]}}
		}`

		account := normalizedAt(t, raw, "azurerm_storage_account.sa")
		if account.ObjectStorage != nil {
			t.Fatal("an account with a container in the plan should defer to it")
		}
		if len(account.DefersTo) != 1 || account.DefersTo[0] != "azurerm_storage_container.assets" {
			t.Fatalf("defers to %v, want the container it answers for", account.DefersTo)
		}
	})

	t.Run("an account block in another provider instance", func(t *testing.T) {
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "assets", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
		    {"address": "aws_s3_account_public_access_block.other", "mode": "managed",
		     "type": "aws_s3_account_public_access_block", "name": "other", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"block_public_acls": true, "block_public_policy": true,
		                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
		  ],
		  "configuration": {
		    "provider_config": {
		      "aws": {"name": "aws", "full_name": "p"},
		      "aws.other": {"name": "aws", "alias": "other", "full_name": "p"}
		    },
		    "root_module": {"resources": [
		      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		       "name": "assets", "provider_config_key": "aws", "expressions": {}},
		      {"address": "aws_s3_account_public_access_block.other", "mode": "managed",
		       "type": "aws_s3_account_public_access_block", "name": "other",
		       "provider_config_key": "aws.other", "expressions": {}}
		    ]}
		  }
		}`

		block := normalizedAt(t, raw, "aws_s3_account_public_access_block.other")
		if len(block.DefersTo) != 0 {
			t.Fatalf("defers to %v; a block in another account governs nothing here", block.DefersTo)
		}
	})
}

// TestGovernsClaimsOnlyWhatItGoverns keeps the deferral from becoming a blanket
// excuse.
//
// Governs answers for one resource type per mapper. Dropping that filter would
// let any resource claim to govern every subject in the plan, so a control for
// a bucket managed elsewhere would be covered by an unrelated bucket that
// happens to be in the same plan — which is the orphan-control defect wearing
// the deferral as a disguise.
func TestGovernsClaimsOnlyWhatItGoverns(t *testing.T) {
	// An ACL for a bucket that is not here, beside an unrelated bucket that is.
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.unrelated", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "unrelated", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "u"}}},
	    {"address": "aws_s3_bucket_acl.elsewhere", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "elsewhere", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "managed-elsewhere", "acl": "public-read"}}}
	  ],
	  "configuration": {
	    "provider_config": {"aws": {"name": "aws", "full_name": "p"}},
	    "root_module": {"resources": [
	      {"address": "aws_s3_bucket.unrelated", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "unrelated", "provider_config_key": "aws", "expressions": {}},
	      {"address": "aws_s3_bucket_acl.elsewhere", "mode": "managed", "type": "aws_s3_bucket_acl",
	       "name": "elsewhere", "provider_config_key": "aws", "expressions": {}}
	    ]}
	  }
	}`

	acl := normalizedAt(t, raw, "aws_s3_bucket_acl.elsewhere")
	if len(acl.DefersTo) != 0 {
		t.Fatalf("an ACL for a bucket managed elsewhere defers to %v", acl.DefersTo)
	}

	// The same shape in Azure: a container whose account is not in the plan,
	// beside an unrelated account that is.
	azure := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.unrelated", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "unrelated", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "u", "allow_nested_items_to_be_public": false}}},
	    {"address": "azurerm_storage_container.orphan", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "orphan", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "o", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.unrelated", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "unrelated", "expressions": {}},
	    {"address": "azurerm_storage_container.orphan", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "orphan", "expressions": {}}
	  ]}}
	}`

	// The container is a subject and reaches its own verdict, so the account's
	// deferral to it is legitimate — but the container must not have been
	// judged using an account it never names.
	container := normalizedAt(t, azure, "azurerm_storage_container.orphan")
	if container.ObjectStorage == nil {
		t.Fatal("a container is a subject and must reach a verdict of its own")
	}
	if container.ObjectStorage.PublicAccess.IsKnown() {
		t.Fatalf("a container whose account is absent was decided anyway: %v",
			container.ObjectStorage.PublicAccess.Get())
	}
	for _, source := range container.ObjectStorage.PublicAccess.Sources {
		if source.ResourceAddress == "azurerm_storage_account.unrelated" {
			t.Fatal("an unrelated account was consulted for this container")
		}
	}
}
