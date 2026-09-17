package providers_test

import (
	"fmt"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Nine review rounds found the same defect nine times, in four dimensions, and
// the rule they converged on is this:
//
//	The mapper concludes only from facts the plan states. An absent value, a
//	value whose kind it did not check, a correlation the configuration does not
//	declare, and an identity the configuration does not attribute are all
//	unstated — and an unstated fact never matches another unstated fact.
//
// Only one kind of answer can be wrong in the way that matters: Known(false),
// which says a resource is provably not public. This enumerates every input
// each producer of that answer consults, perturbs it once, and requires the
// answer to stop being Known(false).
//
// A new producer, or a new input to an existing one, should fail this table
// rather than reach a reviewer.
func TestNothingUnstatedProvesPrivate(t *testing.T) {
	for _, producer := range provenProducers() {
		t.Run(producer.name, func(t *testing.T) {
			// The unperturbed plan must actually prove the resource private,
			// or the perturbations below prove nothing.
			fact := publicAccessOf(t, producer.plan(unperturbed), producer.subject)
			if !fact.IsKnown() || fact.Get() {
				t.Fatalf("the baseline should be a known false, got state=%q grants=%v", fact.State, fact.Get())
			}

			for name, perturbation := range producer.perturbations {
				t.Run(name, func(t *testing.T) {
					got := publicAccessOf(t, producer.plan(perturbation), producer.subject)
					if got.IsKnown() && !got.Get() {
						t.Fatalf("an unstated input still proved the resource private")
					}
				})
			}
		})
	}
}

// producer is one route to a Known(false) answer.
type producer struct {
	name    string
	subject string
	// plan renders the plan with one input replaced. The unperturbed sentinel
	// renders it untouched, and the empty string renders the input away
	// entirely — which is itself one of the perturbations.
	plan          func(perturbation string) string
	perturbations map[string]string
}

// unperturbed asks for the plan as written. It is distinct from the empty
// string, which is the perturbation that removes the input altogether.
const unperturbed = "\x00"

// absentIllTypedAndUnreadable are the perturbations every value-shaped input
// gets: the plan not mentioning it, mentioning it as the wrong JSON kind, not
// knowing it yet, and marking it sensitive.
func absentIllTypedAndUnreadable(field, illTyped string) map[string]string {
	return map[string]string{
		"absent":    "",
		"ill-typed": fmt.Sprintf(`"%s": %s`, field, illTyped),
		"not yet known": fmt.Sprintf(`"%s": null`, field) +
			fmt.Sprintf(`}, "after_unknown": {"%s": true`, field),
		"sensitive": fmt.Sprintf(`"%s": true`, field) +
			fmt.Sprintf(`}, "after_sensitive": {"%s": true`, field),
	}
}

func provenProducers() []producer {
	return []producer{
		{
			name:    "the AWS bucket block shuts every route",
			subject: "aws_s3_bucket.assets",
			plan: func(p string) string {
				flags := `"block_public_acls": true, "block_public_policy": true,
				          "ignore_public_acls": true, "restrict_public_buckets": true`
				if p != unperturbed {
					flags = `"block_public_policy": true, "ignore_public_acls": true,
					         "restrict_public_buckets": true` + comma(p) + p
				}
				return awsBucketPlan(flags, `"provider_config_key": "aws"`)
			},
			perturbations: absentIllTypedAndUnreadable("block_public_acls", `"true"`),
		},
		{
			name:    "the Azure account forbids anonymous access",
			subject: "azurerm_storage_container.assets",
			plan: func(p string) string {
				gate := `"allow_nested_items_to_be_public": false`
				if p != unperturbed {
					gate = p
				}
				return azureContainerPlan(comma(gate) + gate)
			},
			perturbations: absentIllTypedAndUnreadable("allow_nested_items_to_be_public", `"false"`),
		},
		{
			name:    "the Azure container is private",
			subject: "azurerm_storage_container.assets",
			plan: func(p string) string {
				access := `"container_access_type": "private"`
				if p != unperturbed {
					access = p
				}
				return azureContainerAccessPlan(comma(access) + access)
			},
			perturbations: absentIllTypedAndUnreadable("container_access_type", `["private"]`),
		},
		{
			name:    "GCP prevention is enforced",
			subject: "google_storage_bucket.assets",
			plan: func(p string) string {
				prevention := `"public_access_prevention": "enforced"`
				if p != unperturbed {
					prevention = p
				}
				return gcpBucketPlan(comma(prevention) + prevention)
			},
			perturbations: absentIllTypedAndUnreadable("public_access_prevention", `true`),
		},
	}
}

func comma(p string) string {
	if p == "" {
		return ""
	}
	return ", "
}

func publicAccessOf(t *testing.T, raw, address string) model.Fact[bool] {
	t.Helper()
	plan, err := terraformplan.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, raw)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At(address)
	if !ok || resource.ObjectStorage == nil {
		t.Fatalf("no normalized resource at %s", address)
	}
	return resource.ObjectStorage.PublicAccess
}

func awsBucketPlan(flags, attribution string) string {
	return fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "provider_name": "p", "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {%s}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     %s, "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", %s,
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`, flags, attribution, attribution)
}

func azureContainerPlan(gate string) string {
	return fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.sa", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "sa", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "s"%s}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.sa", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "sa", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "azurerm_storage_account.sa.id", "azurerm_storage_account.sa"]}}}
	  ]}}
	}`, gate)
}

func azureContainerAccessPlan(access string) string {
	return fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.sa", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "sa", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "s", "allow_nested_items_to_be_public": true}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "assets"%s}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.sa", "mode": "managed", "type": "azurerm_storage_account",
	     "name": "sa", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "azurerm_storage_account.sa.id", "azurerm_storage_account.sa"]}}}
	  ]}}
	}`, access)
}

func gcpBucketPlan(prevention string) string {
	return fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "google_storage_bucket.assets", "mode": "managed", "type": "google_storage_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "a"%s}}}
	  ]
	}`, prevention)
}
