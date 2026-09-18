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
