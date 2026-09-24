package providers_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

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

	// The Azure account's deferral comes from the container's own reference to
	// it, not from Governs: a container names its account, so the reference
	// loop already supplies the link and a Governs for Azure was dead code.
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

	// The same shape in Azure. There is no Governs here — a container names its
	// account, so the reference loop is the only route — and what must hold is
	// that an account the container never names is not consulted for it.
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

// TestEveryResourceIsAskedWhereItBelongs closes a claim the bundle made about
// resources nothing had read.
//
// Only a subject went through the environment reader. A control resource and an
// opaque one kept the zero fact, which the rule then reported as "the resource
// declares no environment" — a false statement in a document whose only value
// is that its statements are true, and the same defect the CLOUD_DETERMINABLE
// wording was corrected for.
//
// A control carries tags like anything else, and a resource no mapper
// understood carries whatever it carries. Reading the attribute is one call;
// not reading it and then describing the result was the error.
func TestEveryResourceIsAskedWhereItBelongs(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a", "tags": {"environment": "staging"}}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"tags": {"environment": "production"},
	                          "block_public_acls": true}}},
	    {"address": "vendor_thing.x", "mode": "managed", "type": "vendor_thing", "name": "x",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"tags": {"environment": "production"}}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	    {"address": "vendor_thing.x", "mode": "managed", "type": "vendor_thing", "name": "x",
	     "expressions": {}}
	  ]}}
	}`

	control := normalizedAt(t, raw, "aws_s3_bucket_public_access_block.assets")
	if !control.Environment.IsKnown() || control.Environment.Get() != "production" {
		t.Errorf("a control's environment was not read: %v/%q",
			control.Environment.State, control.Environment.Get())
	}

	// A resource no mapper understood has no provider vocabulary to read it
	// by, so it declares nothing — and must say that rather than nothing at
	// all, which is what a zero fact says.
	opaque := normalizedAt(t, raw, "vendor_thing.x")
	if opaque.Interpreted {
		t.Fatal("no mapper should have claimed this resource")
	}
	// The zero state is the answer here, and it is a different answer from
	// Unknown: nobody looked, rather than somebody looked and could not tell.
	// The rule turns the two into different sentences, and only one of them is
	// true of a resource whose tags are plainly readable.
	if opaque.Environment.State != "" {
		t.Errorf("an opaque resource reported %q; nothing read it, which is not a determination",
			opaque.Environment.State)
	}
	if opaque.Environment.IsKnown() {
		t.Errorf("an opaque resource's tags were read by a vocabulary no mapper vouched for: %q",
			opaque.Environment.Get())
	}
}

// TestADataSourceIsNotAChange keeps a read out of a verdict about a change.
//
// Mode was parsed and read by nothing, so a data source of a supported type was
// normalized as a subject and judged: reading an existing production bucket
// produced an environment mismatch, and reading one alone produced a required
// unknown asking a read to prove its exposure. Neither is about the change, and
// docs/PRODUCT.md disclaims saying anything about existing infrastructure.
//
// A data source is kept in the graph, because a plan's contents are not
// filtered, and it carries no capabilities, because it changes nothing.
func TestADataSourceIsNotAChange(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "data.aws_s3_bucket.existing", "mode": "data", "type": "aws_s3_bucket",
	     "name": "existing", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"bucket": "prod", "tags": {"environment": "production"}}}}
	  ]
	}`

	resource := normalizedAt(t, raw, "data.aws_s3_bucket.existing")

	if resource.ObjectStorage != nil {
		t.Error("a data source was given capabilities; it changes nothing to have them about")
	}
	if resource.Environment.IsKnown() {
		t.Errorf("a data source declared an environment for the change: %q", resource.Environment.Get())
	}
	if resource.Destructive {
		t.Error("a read was called destructive")
	}
}

// TestAModeThatContradictsItsActionsIsNotBelieved keeps one unvalidated string
// from erasing a resource from the report.
//
// Terraform's answer to "is this a change?" is the pair (mode, actions), and
// this build restated it as mode == "data". A plan claiming to read while its
// actions say delete was believed on the mode alone: four rules skipped it,
// and the bundle did not mention that the plan contained anything.
//
// Two declarations that disagree are the project's own settled case. Neither
// may be believed, and the disagreement is reported rather than resolved.
func TestAModeThatContradictsItsActionsIsNotBelieved(t *testing.T) {
	read := func(actions string) string {
		return `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "data.aws_s3_bucket.existing", "mode": "data", "type": "aws_s3_bucket",
		     "name": "existing", "provider_name": "p",
		     "change": {"actions": ` + actions + `, "before": {"bucket": "b"}, "after": null}}
		  ]
		}`
	}

	t.Run("a read that says it deletes", func(t *testing.T) {
		resource := normalizedAt(t, read(`["delete"]`), "data.aws_s3_bucket.existing")
		if resource.ReadOnly {
			t.Fatal("a change claiming to read while deleting was believed to be a read")
		}
	})

	t.Run("a read that says it creates", func(t *testing.T) {
		resource := normalizedAt(t, read(`["create"]`), "data.aws_s3_bucket.existing")
		if resource.ReadOnly {
			t.Fatal("a change claiming to read while creating was believed to be a read")
		}
	})

	for name, actions := range map[string]string{
		"a plain read": `["read"]`,
		"a no-op read": `["no-op"]`,
	} {
		t.Run(name, func(t *testing.T) {
			resource := normalizedAt(t, read(actions), "data.aws_s3_bucket.existing")
			if !resource.ReadOnly {
				t.Fatalf("a data source whose actions agree was not read as one: %s", actions)
			}
		})
	}
}

// TestAReadCannotDecideAVerdict draws the admissibility boundary where the
// facts are made, rather than where they are read.
//
// ReadOnly was applied four times in the policy layer and nowhere in the
// normalizer, so every rule could decline to judge a read and none could stop
// a read from having already judged something else. An Azure container set to
// blob access, beside a data source reporting that its account forbids
// anonymous access, came back Known(false) — the plan proves prevention — on a
// plan that manages the container and merely observes the account.
//
// Worse than the wrong verdict: the record naming the gap disappeared with it,
// because the account looked present, and the data source appeared nowhere in
// the bundle because a Known(false) emits nothing.
func TestAReadCannotDecideAVerdict(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "data.azurerm_storage_account.existing", "mode": "data",
	     "type": "azurerm_storage_account", "name": "existing", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"name": "acct", "allow_nested_items_to_be_public": false}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "data.azurerm_storage_account.existing", "mode": "data",
	     "type": "azurerm_storage_account", "name": "existing", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "data.azurerm_storage_account.existing.id",
	       "data.azurerm_storage_account.existing"]}}}
	  ]}}
	}`

	container := normalizedAt(t, raw, "azurerm_storage_container.assets")
	if container.ObjectStorage == nil {
		t.Fatal("no normalized container")
	}

	exposure := container.ObjectStorage.PublicAccess
	if exposure.IsKnown() && !exposure.Get() {
		t.Fatal("a read of existing state was taken as proof that the change prevents exposure")
	}
	for _, source := range exposure.Sources {
		if contains(source.ResourceAddress, "data.") {
			t.Errorf("a read contributed to the verdict: %s", source.ResourceAddress)
		}
	}

	// And the gap it hid is named again: the account gating this container is
	// not part of this plan, whatever the plan reads about it.
	var named bool
	for _, control := range container.ObjectStorage.Unresolved {
		if control.CheckID == "AZURE_STORAGE_ACCOUNT_NOT_IN_PLAN" {
			named = true
		}
	}
	if !named {
		t.Fatalf("the missing account was not reported: %v", container.ObjectStorage.Unresolved)
	}

	// The read is still in the graph. Nothing in a plan is filtered away.
	if _, ok := providers.Normalize(mustParse(t, raw), providers.Default()).
		At("data.azurerm_storage_account.existing"); !ok {
		t.Error("the data source was dropped from the graph rather than declared inadmissible")
	}
}

// TestAReadCannotShutARouteForAManagedResource is the same boundary on the AWS
// side, where a control is a separate resource rather than the subject's own
// gate.
func TestAReadCannotShutARouteForAManagedResource(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}},
	    {"address": "data.aws_s3_bucket_public_access_block.existing", "mode": "data",
	     "type": "aws_s3_bucket_public_access_block", "name": "existing", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	    {"address": "data.aws_s3_bucket_public_access_block.existing", "mode": "data",
	     "type": "aws_s3_bucket_public_access_block", "name": "existing",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`

	bucket := normalizedAt(t, raw, "aws_s3_bucket.assets")
	if bucket.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	exposure := bucket.ObjectStorage.PublicAccess
	if !exposure.IsKnown() || !exposure.Get() {
		t.Fatalf("the bucket's own ACL grants public access: state=%q grants=%v",
			exposure.State, exposure.Get())
	}
}

func mustParse(t *testing.T, raw string) terraformplan.Plan {
	t.Helper()
	plan, err := terraformplan.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return plan
}

// TestWithholdingASourceIsNotTheSameAsItsAbsence is the defect the previous
// round's fix introduced, and the reason it introduced it.
//
// Excluding a read from what a mapper sees stops a read exonerating anything.
// It also makes the read vanish, and an inadmissible fact and an absent fact
// are different things. A container naming two accounts — one managed, one
// read, which is what Terraform writes for a conditional — had its ambiguity
// resolved by deletion: two candidates became one, the survivor became
// authoritative, and a container explicitly set to blob access came back
// proven private.
//
// A fact computed while something was withheld from it is not Known. The
// withheld source is named, so the reader can see what the tool declined to
// use and why the answer is open.
func TestWithholdingASourceIsNotTheSameAsItsAbsence(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.locked", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "locked", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "l", "allow_nested_items_to_be_public": false}}},
	    {"address": "data.azurerm_storage_account.legacy", "mode": "data",
	     "type": "azurerm_storage_account", "name": "legacy", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"name": "g", "allow_nested_items_to_be_public": true}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.locked", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "locked", "expressions": {}},
	    {"address": "data.azurerm_storage_account.legacy", "mode": "data",
	     "type": "azurerm_storage_account", "name": "legacy", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "data.azurerm_storage_account.legacy.id", "data.azurerm_storage_account.legacy",
	       "azurerm_storage_account.locked.id", "azurerm_storage_account.locked"]}}}
	  ]}}
	}`

	container := normalizedAt(t, raw, "azurerm_storage_container.assets")
	if container.ObjectStorage == nil {
		t.Fatal("no normalized container")
	}

	exposure := container.ObjectStorage.PublicAccess
	if exposure.IsKnown() {
		t.Fatalf("a candidate was withheld and the answer was settled anyway: %v", exposure.Get())
	}

	var named bool
	for _, control := range container.ObjectStorage.Unresolved {
		if control.CheckID == "SOURCE_WITHHELD" {
			named = true
			if !contains(control.Reason, "legacy") {
				t.Errorf("the record does not name what was withheld: %q", control.Reason)
			}
		}
	}
	if !named {
		t.Fatalf("nothing recorded that a source was withheld: %v", container.ObjectStorage.Unresolved)
	}
}

// TestAWithheldGrantIsRecordedNotDiscarded is the same rule in the other
// direction. A read cannot incriminate either — what it describes is existing
// state, not what the change does — but discarding it silently left a bundle
// saying the change was consistent in every supported check beside a plan that
// states a public grant.
func TestAWithheldGrantIsRecordedNotDiscarded(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "data.aws_s3_bucket_policy.assets", "mode": "data",
	     "type": "aws_s3_bucket_policy", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"bucket": "a",
	                          "policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\"}]}"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "data.aws_s3_bucket_policy.assets", "mode": "data",
	     "type": "aws_s3_bucket_policy", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`

	bucket := normalizedAt(t, raw, "aws_s3_bucket.assets")
	if bucket.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	if bucket.ObjectStorage.PublicAccess.IsKnown() {
		t.Fatalf("a withheld grant left the answer settled: %v",
			bucket.ObjectStorage.PublicAccess.Get())
	}

	var named bool
	for _, control := range bucket.ObjectStorage.Unresolved {
		if control.CheckID == "SOURCE_WITHHELD" {
			named = true
		}
	}
	if !named {
		t.Fatalf("the withheld policy was not recorded: %v", bucket.ObjectStorage.Unresolved)
	}
}

// TestNothingIsWithheldFromAnOrdinaryPlan keeps the record off every plan that
// has no read in it, so it means something when it appears.
func TestNothingIsWithheldFromAnOrdinaryPlan(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
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

	bucket := normalizedAt(t, raw, "aws_s3_bucket.assets")
	if !bucket.ObjectStorage.PublicAccess.IsKnown() || bucket.ObjectStorage.PublicAccess.Get() {
		t.Fatalf("the block shuts every route: %v/%v",
			bucket.ObjectStorage.PublicAccess.State, bucket.ObjectStorage.PublicAccess.Get())
	}
	for _, control := range bucket.ObjectStorage.Unresolved {
		if control.CheckID == "SOURCE_WITHHELD" {
			t.Errorf("a plan with no read recorded a withheld source: %v", control)
		}
	}
}

// TestWithholdingDependsOnWhetherItWouldHaveMattered replaces a guess with a
// question the mapper answers.
//
// A withheld source was implicated by its type: anything a mapper interprets,
// related to the subject, downgraded the verdict. That is a static stand-in for
// a question about a particular derivation, and it was wrong in both directions
// at once.
//
// It over-corrected where no choice was made: a GCP bucket whose prevention is
// enforced is proven private from its own attribute, before any binding is
// read, and an unrelated IAM policy read alongside it turned a PASS into an
// UNKNOWN. And it under-corrected where a choice was made: a container naming
// two accounts, one managed and one read, had the read deleted from the
// candidate count and the survivor attributed — so the presence of a read made
// the tool more certain than the presence of a managed resource, and produced a
// BLOCK the plan does not determine.
//
// Whether a source would have mattered is answered by adding it back and
// seeing whether the mapper says something else. The second answer is never
// used as a verdict; only the difference between them is.
func TestWithholdingDependsOnWhetherItWouldHaveMattered(t *testing.T) {
	t.Run("a choice the read was a candidate for", func(t *testing.T) {
		// The managed account permits, the read forbids, and which one gates
		// the container is not stated.
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "azurerm_storage_account.open", "mode": "managed",
		     "type": "azurerm_storage_account", "name": "open", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"name": "o", "allow_nested_items_to_be_public": true}}},
		    {"address": "data.azurerm_storage_account.legacy", "mode": "data",
		     "type": "azurerm_storage_account", "name": "legacy", "provider_name": "p",
		     "change": {"actions": ["read"], "before": null,
		                "after": {"name": "g", "allow_nested_items_to_be_public": false}}},
		    {"address": "azurerm_storage_container.assets", "mode": "managed",
		     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"name": "assets", "container_access_type": "blob"}}}
		  ],
		  "configuration": {"root_module": {"resources": [
		    {"address": "azurerm_storage_account.open", "mode": "managed",
		     "type": "azurerm_storage_account", "name": "open", "expressions": {}},
		    {"address": "data.azurerm_storage_account.legacy", "mode": "data",
		     "type": "azurerm_storage_account", "name": "legacy", "expressions": {}},
		    {"address": "azurerm_storage_container.assets", "mode": "managed",
		     "type": "azurerm_storage_container", "name": "assets",
		     "expressions": {"storage_account_id": {"references": [
		       "data.azurerm_storage_account.legacy.id", "data.azurerm_storage_account.legacy",
		       "azurerm_storage_account.open.id", "azurerm_storage_account.open"]}}}
		  ]}}
		}`

		container := normalizedAt(t, raw, "azurerm_storage_container.assets")
		if container.ObjectStorage.PublicAccess.IsKnown() {
			t.Fatalf("the identity of the gate was attributed by deleting a candidate: %v",
				container.ObjectStorage.PublicAccess.Get())
		}
		if !withheldRecorded(container) {
			t.Error("the candidate that was withheld is not named")
		}
	})

	t.Run("a proof the read could not have touched", func(t *testing.T) {
		// Prevention is enforced on the bucket itself, which settles the
		// question before any binding is consulted.
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "google_storage_bucket.b", "mode": "managed",
		     "type": "google_storage_bucket", "name": "b", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"name": "b", "public_access_prevention": "enforced"}}},
		    {"address": "data.google_storage_bucket_iam_policy.current", "mode": "data",
		     "type": "google_storage_bucket_iam_policy", "name": "current", "provider_name": "p",
		     "change": {"actions": ["read"], "before": null,
		                "after": {"bucket": "b", "policy_data": "{}"}}}
		  ],
		  "configuration": {"root_module": {"resources": [
		    {"address": "google_storage_bucket.b", "mode": "managed",
		     "type": "google_storage_bucket", "name": "b", "expressions": {}},
		    {"address": "data.google_storage_bucket_iam_policy.current", "mode": "data",
		     "type": "google_storage_bucket_iam_policy", "name": "current",
		     "expressions": {"bucket": {"references": [
		       "google_storage_bucket.b.name", "google_storage_bucket.b"]}}}
		  ]}}
		}`

		bucket := normalizedAt(t, raw, "google_storage_bucket.b")
		exposure := bucket.ObjectStorage.PublicAccess
		if !exposure.IsKnown() || exposure.Get() {
			t.Fatalf("prevention is enforced on the bucket itself: %v/%v",
				exposure.State, exposure.Get())
		}
		if withheldRecorded(bucket) {
			t.Error("a source the verdict does not depend on was reported as withheld")
		}
	})

	t.Run("a grant the read could not have made", func(t *testing.T) {
		// The bucket's own ACL grants public access. A read cannot unsay it,
		// and nothing here rests on choosing between candidates.
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "assets", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
		    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
		     "name": "open", "provider_name": "p",
		     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}},
		    {"address": "data.aws_s3_bucket_policy.current", "mode": "data",
		     "type": "aws_s3_bucket_policy", "name": "current", "provider_name": "p",
		     "change": {"actions": ["read"], "before": null,
		                "after": {"bucket": "a", "policy": "{}"}}}
		  ],
		  "configuration": {"root_module": {"resources": [
		    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "assets", "expressions": {}},
		    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
		     "name": "open",
		     "expressions": {"bucket": {"references": [
		       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
		    {"address": "data.aws_s3_bucket_policy.current", "mode": "data",
		     "type": "aws_s3_bucket_policy", "name": "current",
		     "expressions": {"bucket": {"references": [
		       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
		  ]}}
		}`

		bucket := normalizedAt(t, raw, "aws_s3_bucket.assets")
		exposure := bucket.ObjectStorage.PublicAccess
		if !exposure.IsKnown() || !exposure.Get() {
			t.Fatalf("the bucket's own ACL grants public access: %v/%v",
				exposure.State, exposure.Get())
		}
	})
}

func withheldRecorded(resource model.NormalizedResource) bool {
	if resource.ObjectStorage == nil {
		return false
	}
	for _, control := range resource.ObjectStorage.Unresolved {
		if control.CheckID == "SOURCE_WITHHELD" {
			return true
		}
	}
	return false
}

// TestAControlOverOnlyReadsSaysSo covers the flag through the normalizer, which
// is where it was never set.
//
// governsOnlyReads was handed the admissible view of the graph, from which
// every read has already been removed — so its read count was always zero and
// the flag was always false. The test that existed set the flag by hand and
// asserted on the sentence, so the whole path passed over the gap.
func TestAControlOverOnlyReadsSaysSo(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "data.aws_s3_bucket.existing", "mode": "data", "type": "aws_s3_bucket",
	     "name": "existing", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_policy.p", "mode": "managed", "type": "aws_s3_bucket_policy",
	     "name": "p", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a", "policy": "{}"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "data.aws_s3_bucket.existing", "mode": "data", "type": "aws_s3_bucket",
	     "name": "existing", "expressions": {}},
	    {"address": "aws_s3_bucket_policy.p", "mode": "managed", "type": "aws_s3_bucket_policy",
	     "name": "p",
	     "expressions": {"bucket": {"references": [
	       "data.aws_s3_bucket.existing.id", "data.aws_s3_bucket.existing"]}}}
	  ]}}
	}`

	control := normalizedAt(t, raw, "aws_s3_bucket_policy.p")
	if !control.GovernsWithheld {
		t.Fatal("a control whose only subject is a read was not marked as governing only reads")
	}

	// And a control over a managed subject is not.
	managed := strings.ReplaceAll(raw, "data.aws_s3_bucket.existing", "aws_s3_bucket.existing")
	managed = strings.ReplaceAll(managed, `"mode": "data"`, `"mode": "managed"`)
	managed = strings.ReplaceAll(managed, `"actions": ["read"]`, `"actions": ["create"]`)
	if ordinary := normalizedAt(t, managed, "aws_s3_bucket_policy.p"); ordinary.GovernsWithheld {
		t.Error("a control over a managed subject was marked as governing only reads")
	}
}

// TestAScopeGovernedControlIsWithheldToo covers the channel a mapper reads
// that the edge map cannot see.
//
// An account-wide block names no bucket: it governs by provider instance, so
// the mapper finds it by walking the scope rather than by following a
// reference. A withheld candidate reached only that way was invisible to the
// bookkeeping, so a read of one was deleted from the candidate count and named
// nowhere — the same shape the reference channel had, in the other of the two
// channels a mapper reads from.
func TestAScopeGovernedControlIsWithheldToo(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "open", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}},
	    {"address": "aws_s3_account_public_access_block.baseline", "mode": "managed",
	     "type": "aws_s3_account_public_access_block", "name": "baseline", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "data.aws_s3_account_public_access_block.current", "mode": "data",
	     "type": "aws_s3_account_public_access_block", "name": "current", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"block_public_acls": false, "block_public_policy": false,
	                          "ignore_public_acls": false, "restrict_public_buckets": false}}}
	  ],
	  "configuration": {
	    "provider_config": {"aws": {"name": "aws", "full_name": "p"}},
	    "root_module": {"resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", "provider_config_key": "aws", "expressions": {}},
	      {"address": "aws_s3_bucket_acl.open", "mode": "managed", "type": "aws_s3_bucket_acl",
	       "name": "open", "provider_config_key": "aws",
	       "expressions": {"bucket": {"references": [
	         "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	      {"address": "aws_s3_account_public_access_block.baseline", "mode": "managed",
	       "type": "aws_s3_account_public_access_block", "name": "baseline",
	       "provider_config_key": "aws", "expressions": {}},
	      {"address": "data.aws_s3_account_public_access_block.current", "mode": "data",
	       "type": "aws_s3_account_public_access_block", "name": "current",
	       "provider_config_key": "aws", "expressions": {}}
	    ]}
	  }
	}`

	bucket := normalizedAt(t, raw, "aws_s3_bucket.assets")
	if bucket.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	if !withheldRecorded(bucket) {
		t.Fatalf("a candidate reached only through the scope was not recorded: %v",
			bucket.ObjectStorage.Unresolved)
	}
}

// TestNormalizingAPlanFullOfReadsStaysCheap keeps the withholding path from
// costing more than the plan is worth.
//
// It has been quadratic twice and cubic once: a loop-invariant rebuilt per
// change, a scan of every read per change, and every read of a subject type
// treated as a candidate for every subject. The last of those took four
// seconds on eight hundred changes.
//
// A ratio between two sizes turned out to measure the machine more than the
// code once the code was fast — at a few milliseconds, scheduler noise and
// garbage collection dominate. A generous absolute bound does not: the work
// here is tens of milliseconds, the bound is two seconds, and every shape this
// has taken before exceeded it by an order of magnitude.
func TestNormalizingAPlanFullOfReadsStaysCheap(t *testing.T) {
	const buckets = 4000

	plan, err := terraformplan.Parse(bucketPlan(t, buckets))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	done := make(chan int, 1)
	go func() { done <- len(providers.Normalize(plan, providers.Default()).Resources) }()

	select {
	case got := <-done:
		if got != 3*buckets {
			t.Fatalf("normalized %d resources, want %d", got, 3*buckets)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("normalizing %d changes did not finish in two seconds", 3*buckets)
	}
}

// bucketPlan builds a plan of n buckets, each with a public access block that
// names it, and a data source beside each.
//
// The reads are the point. Without one in the plan, the whole withholding path
// returns before it does anything, so the test written to protect the cost of
// that path could not see it — and the cost it could not see was cubic.
func bucketPlan(t *testing.T, buckets int) []byte {
	t.Helper()

	var changes, resources []string
	for i := range buckets {
		bucket := fmt.Sprintf("aws_s3_bucket.b%d", i)
		block := fmt.Sprintf("aws_s3_bucket_public_access_block.p%d", i)
		read := fmt.Sprintf("data.aws_s3_bucket.d%d", i)
		changes = append(changes,
			fmt.Sprintf(`{"address": %q, "mode": "data", "type": "aws_s3_bucket", "name": "d%d",
			  "provider_name": "p",
			  "change": {"actions": ["read"], "before": null, "after": {"bucket": "d%d"}}}`,
				read, i, i),
			fmt.Sprintf(`{"address": %q, "mode": "managed", "type": "aws_s3_bucket", "name": "b%d",
			  "provider_name": "p",
			  "change": {"actions": ["create"], "before": null, "after": {"bucket": "b%d"}}}`,
				bucket, i, i),
			fmt.Sprintf(`{"address": %q, "mode": "managed",
			  "type": "aws_s3_bucket_public_access_block", "name": "p%d", "provider_name": "p",
			  "change": {"actions": ["create"], "before": null,
			             "after": {"block_public_acls": true, "block_public_policy": true,
			                       "ignore_public_acls": true, "restrict_public_buckets": true}}}`,
				block, i))
		resources = append(resources,
			fmt.Sprintf(`{"address": %q, "mode": "data", "type": "aws_s3_bucket",
			  "name": "d%d", "expressions": {}}`, read, i),
			fmt.Sprintf(`{"address": %q, "mode": "managed", "type": "aws_s3_bucket",
			  "name": "b%d", "expressions": {}}`, bucket, i),
			fmt.Sprintf(`{"address": %q, "mode": "managed",
			  "type": "aws_s3_bucket_public_access_block", "name": "p%d",
			  "expressions": {"bucket": {"references": [%q, %q]}}}`,
				block, i, bucket+".id", bucket))
	}

	return []byte(`{"format_version": "1.2", "resource_changes": [` + strings.Join(changes, ",") +
		`], "configuration": {"root_module": {"resources": [` + strings.Join(resources, ",") + `]}}}`)
}

// TestOnlyTheUnreadableSourceIsMarkedWithheld covers the mapper side of a flag
// the bundle reports per reference.
//
// The policy test builds provenance by hand, so nothing exercised the mappers
// that produce it: marking every source of a redacted fact and marking none at
// all both passed. A fact is redacted when any one of its sources was, and the
// others were read — that is how the mapper concluded at all.
func TestOnlyTheUnreadableSourceIsMarkedWithheld(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": false, "block_public_policy": false,
	                          "ignore_public_acls": false, "restrict_public_buckets": false}}},
	    {"address": "aws_s3_bucket_policy.assets", "mode": "managed",
	     "type": "aws_s3_bucket_policy", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"policy": "{}"}, "after_sensitive": {"policy": true}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	    {"address": "aws_s3_bucket_policy.assets", "mode": "managed",
	     "type": "aws_s3_bucket_policy", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`

	bucket := normalizedAt(t, raw, "aws_s3_bucket.assets")
	if bucket.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	exposure := bucket.ObjectStorage.PublicAccess
	if exposure.State != model.FactRedacted {
		t.Fatalf("the policy is sensitive, so exposure is %q, want %q",
			exposure.State, model.FactRedacted)
	}

	var withheld, read int
	for _, source := range exposure.Sources {
		if source.Withheld {
			withheld++
			if source.AttributePath != "policy" {
				t.Errorf("a value the mapper read is marked withheld: %s %s",
					source.ResourceAddress, source.AttributePath)
			}
			continue
		}
		read++
	}
	if withheld != 1 {
		t.Errorf("sources marked withheld = %d, want exactly the policy", withheld)
	}
	if read == 0 {
		t.Error("the block flags were read in order to conclude, and none says so")
	}
}

// TestAnUnrelatedReadContestsNothing keeps a read from being a candidate for
// every subject in the plan.
//
// A control that governs by scope names no subject, so it has to be offered to
// all of them. A subject names no subject either — it declares no relation
// from itself — and treating one as scope-governed made every data source of a
// subject type a candidate for every managed resource of that type. Where a
// verdict is read from the subject's own attribute, as GCP's prevention is,
// that is a collision by construction: the verdict cites a bucket and the read
// is a bucket.
//
// Reading some buckets and managing others is an ordinary plan.
func TestAnUnrelatedReadContestsNothing(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "google_storage_bucket.assets", "mode": "managed",
	     "type": "google_storage_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "a", "public_access_prevention": "enforced"}}},
	    {"address": "data.google_storage_bucket.somewhere_else", "mode": "data",
	     "type": "google_storage_bucket", "name": "somewhere_else", "provider_name": "p",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"name": "other", "public_access_prevention": "inherited"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "google_storage_bucket.assets", "mode": "managed",
	     "type": "google_storage_bucket", "name": "assets", "expressions": {}},
	    {"address": "data.google_storage_bucket.somewhere_else", "mode": "data",
	     "type": "google_storage_bucket", "name": "somewhere_else", "expressions": {}}
	  ]}}
	}`

	bucket := normalizedAt(t, raw, "google_storage_bucket.assets")
	if bucket.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}

	exposure := bucket.ObjectStorage.PublicAccess
	if !exposure.IsKnown() || exposure.Get() {
		t.Fatalf("prevention is enforced on this bucket and nothing here contests it: %v/%v",
			exposure.State, exposure.Get())
	}
	if withheldRecorded(bucket) {
		t.Errorf("a read of another bucket was reported as contesting this one: %v",
			bucket.ObjectStorage.Unresolved)
	}
}
