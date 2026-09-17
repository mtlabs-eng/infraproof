package aws_test

import (
	"fmt"
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

func bucket(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At("aws_s3_bucket.assets")
	if !ok {
		t.Fatalf("fixture %s has no bucket at aws_s3_bucket.assets", fixture)
	}
	if found.ObjectStorage == nil {
		t.Fatalf("fixture %s produced no object-storage capabilities", fixture)
	}
	return found
}

// TestPublicAccessDetermination is the mapper's whole job. "Known(true)" means
// the change grants public access; "Known(false)" means the plan itself proves
// it is prevented; anything else means a control the answer depends on is not
// in the plan.
func TestPublicAccessDetermination(t *testing.T) {
	cases := map[string]model.FactState{
		"public-acl":                   model.FactKnown,
		"public-policy":                model.FactKnown,
		"private":                      model.FactKnown,
		"private-with-account-block":   model.FactKnown,
		"private-acl-blocked":          model.FactKnown,
		"blocked-public-acl":           model.FactKnown,
		"blocked-public-policy":        model.FactKnown,
		"public-acl-write":             model.FactKnown,
		"unknown-no-controls":          model.FactUnknown,
		"unknown-policy-not-yet-known": model.FactUnknown,
		"unknown-conditional-policy":   model.FactUnknown,
		"redacted-policy":              model.FactRedacted,
	}
	grants := map[string]bool{"public-acl": true, "public-policy": true, "public-acl-write": true}

	for fixture, wantState := range cases {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if fact.State != wantState {
				t.Fatalf("state = %q, want %q", fact.State, wantState)
			}
			if fact.Get() != grants[fixture] {
				t.Fatalf("grants public = %v, want %v", fact.Get(), grants[fixture])
			}
		})
	}
}

// TestAGrantTheSamePlanBlocksIsNotAGrant covers both routes. A policy or ACL
// naming everyone, alongside a block that shuts that route, does not expose the
// bucket — and on AWS the apply would be rejected outright.
func TestAGrantTheSamePlanBlocksIsNotAGrant(t *testing.T) {
	for _, fixture := range []string{"blocked-public-acl", "blocked-public-policy"} {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if fact.State != model.FactKnown || fact.Get() {
				t.Fatalf("state = %q grants = %v, want a known false", fact.State, fact.Get())
			}
		})
	}
}

// TestPublicReadWriteIsPublicToo keeps the second canned ACL in scope. It
// grants more than public-read, so missing it would be the worse direction of
// error.
func TestPublicReadWriteIsPublicToo(t *testing.T) {
	fact := bucket(t, "public-acl-write").ObjectStorage.PublicAccess

	if fact.State != model.FactKnown || !fact.Get() {
		t.Fatalf("state = %q grants = %v, want a known true", fact.State, fact.Get())
	}
}

// TestAConditionalPolicyIsNotProofOfPublicAccess is the judgement that
// separates this from a pattern matcher. A statement with Principal "*" and a
// condition restricting it to a VPC endpoint is not public, and a tool that
// cannot tell the difference produces findings nobody trusts.
func TestAConditionalPolicyIsNotProofOfPublicAccess(t *testing.T) {
	fact := bucket(t, "unknown-conditional-policy").ObjectStorage.PublicAccess

	if fact.State == model.FactKnown {
		t.Fatalf("a conditional policy was read as a definite answer: %v", fact.Get())
	}
}

// TestARedactedPolicyCannotBeRead keeps milestone 02's discard visible here: a
// policy the plan marked sensitive is not readable, so no conclusion follows
// from it.
func TestARedactedPolicyCannotBeRead(t *testing.T) {
	if got := bucket(t, "redacted-policy").ObjectStorage.PublicAccess.State; got != model.FactRedacted {
		t.Fatalf("state = %q, want %q", got, model.FactRedacted)
	}
}

// TestTheAccountLevelBlockIsReportedWhenAbsent covers the control that decides
// the real answer on AWS and is almost never in a plan.
func TestTheAccountLevelBlockIsReportedWhenAbsent(t *testing.T) {
	withoutIt := bucket(t, "private").ObjectStorage
	if len(withoutIt.Unresolved) != 1 {
		t.Fatalf("unresolved = %v, want the account-level block", withoutIt.Unresolved)
	}
	if withoutIt.Unresolved[0].CheckID != "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK" {
		t.Fatalf("check id = %q", withoutIt.Unresolved[0].CheckID)
	}

	withIt := bucket(t, "private-with-account-block").ObjectStorage
	if len(withIt.Unresolved) != 0 {
		t.Fatalf("unresolved = %v, want none when the account block is in the plan", withIt.Unresolved)
	}
}

// TestEveryFactNamesItsProvenance is an acceptance criterion: a finding has to
// be traceable to the provider attribute it came from.
func TestEveryFactNamesItsProvenance(t *testing.T) {
	for _, fixture := range []string{"public-acl", "public-policy", "private"} {
		t.Run(fixture, func(t *testing.T) {
			fact := bucket(t, fixture).ObjectStorage.PublicAccess
			if len(fact.Sources) == 0 {
				t.Fatal("the fact names no source")
			}
			for _, source := range fact.Sources {
				if source.ResourceAddress == "" || source.AttributePath == "" {
					t.Fatalf("incomplete provenance: %+v", source)
				}
				if source.Cloud != model.CloudAWS {
					t.Fatalf("provenance cloud = %q, want %q", source.Cloud, model.CloudAWS)
				}
			}
		})
	}
}

func TestPublicAclProvenanceNamesTheAcl(t *testing.T) {
	fact := bucket(t, "public-acl").ObjectStorage.PublicAccess

	var found bool
	for _, source := range fact.Sources {
		if source.ResourceAddress == "aws_s3_bucket_acl.assets" && source.AttributePath == "acl" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the finding does not point at the ACL that grants access: %v", fact.Sources)
	}
}

// TestSatelliteResourcesStayInTheGraph keeps every change visible. A control
// resource is folded into its bucket's capabilities, but dropping it would hide
// a change from a reader.
func TestSatelliteResourcesStayInTheGraph(t *testing.T) {
	graph := normalize(t, "public-acl")

	if len(graph.Resources) != 3 {
		t.Fatalf("graph has %d resources, want all three from the plan", len(graph.Resources))
	}
	block, ok := graph.At("aws_s3_bucket_public_access_block.assets")
	if !ok {
		t.Fatal("the public access block is missing from the graph")
	}
	if !block.Interpreted {
		t.Fatal("a resource a mapper understood must not read as unsupported")
	}
	if block.ObjectStorage != nil {
		t.Fatal("a control resource has no capabilities of its own")
	}
}

// TestAResourceNoMapperClaimsStaysOpaque is the criterion carried from
// milestone 02 into this layer. An unrecognized resource is retained, is
// labelled as belonging to no cloud and no family, and does not report itself
// as understood — because "we did not look at this" and "we looked and it is
// fine" are different claims.
func TestAResourceNoMapperClaimsStaysOpaque(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "acme_widget.unrecognized", "mode": "managed", "type": "acme_widget",
	    "name": "unrecognized", "provider_name": "registry.terraform.io/acme/acme",
	    "change": {"actions": ["delete"], "before": {"shape": "hexagon"}, "after": null}
	  }]
	}`)

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	graph := providers.Normalize(plan, providers.Default())

	resource, ok := graph.At("acme_widget.unrecognized")
	if !ok {
		t.Fatal("an unrecognized resource was dropped from the graph")
	}
	if resource.Cloud != model.CloudUnknown {
		t.Fatalf("cloud = %q, want %q", resource.Cloud, model.CloudUnknown)
	}
	if resource.Family != model.FamilyUnknown {
		t.Fatalf("family = %q, want %q", resource.Family, model.FamilyUnknown)
	}
	if resource.Interpreted {
		t.Fatal("a resource no mapper claimed must not report itself understood")
	}
	if resource.ObjectStorage != nil {
		t.Fatal("an opaque resource has no capabilities")
	}
	if !resource.Destructive {
		t.Fatal("a delete is destructive whether or not any mapper understood it")
	}
}

// TestThreeOfFourFlagsDoNotProvePrevention pins why all four are required.
// restrict_public_buckets is the flag that neutralises a policy that already
// exists on the bucket; block_public_policy only rejects new ones. Proving
// prevention on three flags would claim more than the plan shows.
func TestThreeOfFourFlagsDoNotProvePrevention(t *testing.T) {
	flags := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}

	for _, omitted := range flags {
		t.Run("without "+omitted, func(t *testing.T) {
			set := map[string]bool{}
			for _, flag := range flags {
				set[flag] = flag != omitted
			}
			fact := bucketFromBlock(t, set, "")
			if fact.IsKnown() && !fact.Get() {
				t.Fatalf("prevention was proved with %s false", omitted)
			}
		})
	}

	all := map[string]bool{}
	for _, flag := range flags {
		all[flag] = true
	}
	if fact := bucketFromBlock(t, all, ""); !fact.IsKnown() || fact.Get() {
		t.Fatalf("all four flags true should prove prevention, got state=%q grants=%v", fact.State, fact.Get())
	}
}

// TestANonPublicAclIsNotAGrant covers the ACL negative on its own, with a
// permissive block, so the ACL reading is exercised rather than masked.
func TestANonPublicAclIsNotAGrant(t *testing.T) {
	permissive := map[string]bool{
		"block_public_acls": false, "block_public_policy": false,
		"ignore_public_acls": false, "restrict_public_buckets": false,
	}

	if fact := bucketFromBlock(t, permissive, "private"); fact.IsKnown() && fact.Get() {
		t.Fatal("a private ACL was read as a grant")
	}
	if fact := bucketFromBlock(t, permissive, "public-read"); !fact.IsKnown() || !fact.Get() {
		t.Fatal("this test is only meaningful if a public ACL is still detected")
	}
}

// TestASubjectReportsItselfInterpreted keeps "a mapper understood this" visible
// on the normalized resource, not only on the control resources.
func TestASubjectReportsItselfInterpreted(t *testing.T) {
	graph := normalize(t, "private")

	resource, ok := graph.At("aws_s3_bucket.assets")
	if !ok {
		t.Fatal("no bucket in the graph")
	}
	if !resource.Interpreted {
		t.Fatal("a normalized subject must report itself understood")
	}
}

// bucketFromBlock builds a one-bucket plan with a public access block set to
// the given flags, and optionally an ACL.
func bucketFromBlock(t *testing.T, flags map[string]bool, acl string) model.Fact[bool] {
	t.Helper()

	block := ""
	for flag, value := range flags {
		if block != "" {
			block += ", "
		}
		block += fmt.Sprintf("%q: %v", flag, value)
	}

	changes := fmt.Sprintf(`
	  {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	   "provider_name": "p", "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	  {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	   "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": {%s}}}`, block)
	configs := `
	  {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	   "expressions": {}},
	  {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	   "type": "aws_s3_bucket_public_access_block", "name": "assets",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	if acl != "" {
		changes += fmt.Sprintf(`,
	  {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	   "name": "assets", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": {"acl": %q}}}`, acl)
		configs += `,
	  {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	   "name": "assets",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`
	}

	raw := []byte(fmt.Sprintf(`{"format_version": "1.2", "resource_changes": [%s],
	  "configuration": {"root_module": {"resources": [%s]}}}`, changes, configs))

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At("aws_s3_bucket.assets")
	if !ok || resource.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	return resource.ObjectStorage.PublicAccess
}

// TestOwnershipControlsDisableAcls covers a resource the mapper claimed to
// interpret but never read. BucketOwnerEnforced turns ACLs off for the bucket,
// so an ACL granting public access cannot take effect — and the apply would
// fail. Reporting it as public is a finding nobody can act on.
func TestOwnershipControlsDisableAcls(t *testing.T) {
	permissive := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`

	enforced := bucketWithOwnership(t, permissive, "public-read", "BucketOwnerEnforced")
	if enforced.IsKnown() && enforced.Get() {
		t.Fatal("an ACL cannot grant access on a bucket where ACLs are disabled")
	}

	preferred := bucketWithOwnership(t, permissive, "public-read", "BucketOwnerPreferred")
	if !preferred.IsKnown() || !preferred.Get() {
		t.Fatalf("BucketOwnerPreferred leaves ACLs working: state=%q grants=%v", preferred.State, preferred.Get())
	}
}

// TestTheAccountBlockIsReadNotJustCounted covers the control that overrides
// every bucket-level setting. Treating its presence as reassurance while
// ignoring its contents gets it backwards in both directions: a plan that
// switches it off loses the caveat, and one that switches it on proves
// prevention the mapper never used.
func TestTheAccountBlockIsReadNotJustCounted(t *testing.T) {
	permissive := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`
	blocking := `{"block_public_acls": true, "block_public_policy": true,
	              "ignore_public_acls": true, "restrict_public_buckets": true}`

	t.Run("an account block that blocks everything proves prevention", func(t *testing.T) {
		fact := bucketWithAccountBlock(t, permissive, "public-read", blocking)
		if !fact.IsKnown() || fact.Get() {
			t.Fatalf("state=%q grants=%v, want a known false", fact.State, fact.Get())
		}
	})

	t.Run("an account block that blocks nothing does not", func(t *testing.T) {
		fact := bucketWithAccountBlock(t, permissive, "public-read", permissive)
		if !fact.IsKnown() || !fact.Get() {
			t.Fatalf("state=%q grants=%v, want a known true", fact.State, fact.Get())
		}
	})
}

func bucketWithOwnership(t *testing.T, block, acl, ownership string) model.Fact[bool] {
	t.Helper()
	extra := fmt.Sprintf(`,
	  {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
	   "type": "aws_s3_bucket_ownership_controls", "name": "assets", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null,
	              "after": {"rule": [{"object_ownership": %q}]}}}`, ownership)
	extraCfg := `,
	  {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
	   "type": "aws_s3_bucket_ownership_controls", "name": "assets",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`
	return bucketPlan(t, block, acl, extra, extraCfg)
}

func bucketWithAccountBlock(t *testing.T, block, acl, account string) model.Fact[bool] {
	t.Helper()
	extra := fmt.Sprintf(`,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": %s}}`, account)
	extraCfg := `,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "expressions": {}}`
	return bucketPlan(t, block, acl, extra, extraCfg)
}

// bucketPlan builds a bucket with a public access block, an ACL, and whatever
// extra resource a case needs.
func bucketPlan(t *testing.T, block, acl, extraChange, extraConfig string) model.Fact[bool] {
	t.Helper()

	raw := []byte(fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "provider_name": "p", "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": %s}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": %q}}}%s
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}%s
	  ]}}
	}`, block, acl, extraChange, extraConfig))

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At("aws_s3_bucket.assets")
	if !ok || resource.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	return resource.ObjectStorage.PublicAccess
}

// TestTheAccountBlockShutsThePolicyRouteToo covers the other half of the
// account-level control. A public bucket policy is stopped by the account
// block just as an ACL is, and testing only one route leaves the other
// unexercised.
func TestTheAccountBlockShutsThePolicyRouteToo(t *testing.T) {
	permissive := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`
	blocking := `{"block_public_acls": true, "block_public_policy": true,
	              "ignore_public_acls": true, "restrict_public_buckets": true}`
	publicPolicy := `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\"}]}`

	policyChange := fmt.Sprintf(`,
	  {"address": "aws_s3_bucket_policy.assets", "mode": "managed", "type": "aws_s3_bucket_policy",
	   "name": "assets", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": {"policy": "%s"}}}`, publicPolicy)
	policyConfig := `,
	  {"address": "aws_s3_bucket_policy.assets", "mode": "managed", "type": "aws_s3_bucket_policy",
	   "name": "assets",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	accountChange := fmt.Sprintf(`,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": %s}}`, blocking)
	accountConfig := `,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "expressions": {}}`

	withAccount := bucketPlan(t, permissive, "private", policyChange+accountChange, policyConfig+accountConfig)
	if !withAccount.IsKnown() || withAccount.Get() {
		t.Fatalf("the account block shuts the policy route: state=%q grants=%v", withAccount.State, withAccount.Get())
	}

	without := bucketPlan(t, permissive, "private", policyChange, policyConfig)
	if !without.IsKnown() || !without.Get() {
		t.Fatalf("without it the policy grants access: state=%q grants=%v", without.State, without.Get())
	}
}

// TestTwoControlsOfOneKindCannotBeResolved covers a plan that contradicts
// itself. Two ACLs on one bucket is a configuration that will fail at apply;
// picking one of them arbitrarily would report a determination the plan does
// not support.
func TestTwoControlsOfOneKindCannotBeResolved(t *testing.T) {
	permissive := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`

	second := `,
	  {"address": "aws_s3_bucket_acl.other", "mode": "managed", "type": "aws_s3_bucket_acl",
	   "name": "other", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}`
	secondConfig := `,
	  {"address": "aws_s3_bucket_acl.other", "mode": "managed", "type": "aws_s3_bucket_acl",
	   "name": "other",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	fact := bucketPlan(t, permissive, "private", second, secondConfig)
	if fact.IsKnown() {
		t.Fatalf("two conflicting ACLs cannot yield a determination, got state=%q grants=%v", fact.State, fact.Get())
	}
}

// TestTheAccountBlockAppliesOnlyToItsOwnAccount covers a control that reaches
// across a boundary it does not have. An account-wide block belongs to the AWS
// account its provider instance points at; a bucket created through a different
// provider instance is in a different account, and the block proves nothing
// about it. An organization baseline alongside workload buckets in another
// account is an ordinary shape, and it is exactly when this resource gets used.
func TestTheAccountBlockAppliesOnlyToItsOwnAccount(t *testing.T) {
	plan := func(bucketKey, accountKey string) model.NormalizedResource {
		t.Helper()
		raw := []byte(fmt.Sprintf(`{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.elsewhere", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "elsewhere", "provider_name": "registry.terraform.io/hashicorp/aws",
		     "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}},
		    {"address": "aws_s3_bucket_acl.elsewhere", "mode": "managed", "type": "aws_s3_bucket_acl",
		     "name": "elsewhere", "provider_name": "registry.terraform.io/hashicorp/aws",
		     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}},
		    {"address": "aws_s3_account_public_access_block.baseline", "mode": "managed",
		     "type": "aws_s3_account_public_access_block", "name": "baseline",
		     "provider_name": "registry.terraform.io/hashicorp/aws",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"block_public_acls": true, "block_public_policy": true,
		                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
		  ],
		  "configuration": {
		    "provider_config": {
		      "aws": {"name": "aws", "full_name": "registry.terraform.io/hashicorp/aws"},
		      "aws.other": {"name": "aws", "alias": "other",
		                    "full_name": "registry.terraform.io/hashicorp/aws"}
		    },
		    "root_module": {"resources": [
		      {"address": "aws_s3_bucket.elsewhere", "mode": "managed", "type": "aws_s3_bucket",
		       "name": "elsewhere", "provider_config_key": %q, "expressions": {}},
		      {"address": "aws_s3_bucket_acl.elsewhere", "mode": "managed", "type": "aws_s3_bucket_acl",
		       "name": "elsewhere", "provider_config_key": %q,
		       "expressions": {"bucket": {"references": ["aws_s3_bucket.elsewhere.id", "aws_s3_bucket.elsewhere"]}}},
		      {"address": "aws_s3_account_public_access_block.baseline", "mode": "managed",
		       "type": "aws_s3_account_public_access_block", "name": "baseline",
		       "provider_config_key": %q, "expressions": {}}
		    ]}
		  }
		}`, bucketKey, bucketKey, accountKey))

		parsed, err := terraformplan.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		resource, ok := providers.Normalize(parsed, providers.Default()).At("aws_s3_bucket.elsewhere")
		if !ok || resource.ObjectStorage == nil {
			t.Fatal("no normalized bucket")
		}
		return resource
	}

	t.Run("a different provider instance is a different account", func(t *testing.T) {
		resource := plan("aws.other", "aws")

		fact := resource.ObjectStorage.PublicAccess
		if !fact.IsKnown() || !fact.Get() {
			t.Fatalf("a public bucket in another account: state=%q grants=%v", fact.State, fact.Get())
		}
		if len(resource.ObjectStorage.Unresolved) != 1 {
			t.Fatalf("the account-level control for this bucket's account is still unknown: %v",
				resource.ObjectStorage.Unresolved)
		}
	})

	t.Run("the same provider instance is the same account", func(t *testing.T) {
		resource := plan("aws", "aws")

		fact := resource.ObjectStorage.PublicAccess
		if !fact.IsKnown() || fact.Get() {
			t.Fatalf("the account block shuts every route: state=%q grants=%v", fact.State, fact.Get())
		}
		if len(resource.ObjectStorage.Unresolved) != 0 {
			t.Fatalf("unresolved = %v, want none", resource.ObjectStorage.Unresolved)
		}
	})
}

// TestAnUnreadableBlockFlagDoesNotReadAsPermission covers the combinator. A
// flag nobody can read is not a flag set to false, and treating it as one turns
// an open question into a finding.
func TestAnUnreadableBlockFlagDoesNotReadAsPermission(t *testing.T) {
	unreadable := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`
	accountChange := `,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": {},
	              "after_unknown": {"block_public_acls": true, "ignore_public_acls": true}}}`
	accountConfig := `,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "expressions": {}}`

	fact := bucketPlan(t, unreadable, "public-read", accountChange, accountConfig)
	if fact.IsKnown() {
		t.Fatalf("an account flag that is not yet known leaves the route open to doubt, got state=%q grants=%v",
			fact.State, fact.Get())
	}
}

// TestUnreadableOwnershipControlsLeaveTheAclRouteOpen covers the same rule for
// the resource that can disable ACLs entirely.
func TestUnreadableOwnershipControlsLeaveTheAclRouteOpen(t *testing.T) {
	permissive := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`
	controls := `,
	  {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
	   "type": "aws_s3_bucket_ownership_controls", "name": "assets", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": {}, "after_unknown": {"rule": true}}}`
	controlsConfig := `,
	  {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
	   "type": "aws_s3_bucket_ownership_controls", "name": "assets",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	fact := bucketPlan(t, permissive, "public-read", controls, controlsConfig)
	if fact.IsKnown() {
		t.Fatalf("ownership controls that are not yet known could still disable ACLs, got state=%q grants=%v",
			fact.State, fact.Get())
	}
}

// TestTwoPublicAccessBlocksCannotBeResolved covers the AWS ambiguity guard,
// which had none of its own.
func TestTwoPublicAccessBlocksCannotBeResolved(t *testing.T) {
	blocking := `{"block_public_acls": true, "block_public_policy": true,
	              "ignore_public_acls": true, "restrict_public_buckets": true}`
	second := `,
	  {"address": "aws_s3_bucket_public_access_block.other", "mode": "managed",
	   "type": "aws_s3_bucket_public_access_block", "name": "other", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null,
	              "after": {"block_public_acls": false, "block_public_policy": false,
	                        "ignore_public_acls": false, "restrict_public_buckets": false}}}`
	secondConfig := `,
	  {"address": "aws_s3_bucket_public_access_block.other", "mode": "managed",
	   "type": "aws_s3_bucket_public_access_block", "name": "other",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	fact := bucketPlan(t, blocking, "private", second, secondConfig)
	if fact.IsKnown() {
		t.Fatalf("two contradictory blocks support no determination, got state=%q grants=%v",
			fact.State, fact.Get())
	}
}

// TestTwoAccountBlocksForOneProviderCannotBeResolved covers the ambiguity guard
// on the account-wide control. One AWS account has one such block; a plan
// declaring two for the same provider instance contradicts itself, and picking
// one would state a determination about every bucket in the account.
func TestTwoAccountBlocksForOneProviderCannotBeResolved(t *testing.T) {
	permissive := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`
	// The permissive block sorts first and the blocking one last, so a
	// resolution that picked either end would differ from declining to choose.
	blocks := `,
	  {"address": "aws_s3_account_public_access_block.first", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "first", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null,
	              "after": {"block_public_acls": false, "block_public_policy": false,
	                        "ignore_public_acls": false, "restrict_public_buckets": false}}},
	  {"address": "aws_s3_account_public_access_block.second", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "second", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null,
	              "after": {"block_public_acls": true, "block_public_policy": true,
	                        "ignore_public_acls": true, "restrict_public_buckets": true}}}`
	blocksConfig := `,
	  {"address": "aws_s3_account_public_access_block.first", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "first", "expressions": {}},
	  {"address": "aws_s3_account_public_access_block.second", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "second", "expressions": {}}`

	fact := bucketPlan(t, permissive, "public-read", blocks, blocksConfig)
	if fact.IsKnown() {
		t.Fatalf("two contradictory account blocks support no determination, got state=%q grants=%v",
			fact.State, fact.Get())
	}
}

// TestAControlBeingDestroyedDoesNotProtect covers a change the mapper was
// reading backwards. A public access block the plan destroys will not exist
// after apply, so it cannot block anything — and the plan that removes it while
// granting a public ACL is exactly the change worth reporting.
func TestAControlBeingDestroyedDoesNotProtect(t *testing.T) {
	blocking := `{"block_public_acls": true, "block_public_policy": true,
	              "ignore_public_acls": true, "restrict_public_buckets": true}`

	destroyed := fmt.Sprintf(`,
	  {"address": "aws_s3_bucket_public_access_block.going", "mode": "managed",
	   "type": "aws_s3_bucket_public_access_block", "name": "going", "provider_name": "p",
	   "change": {"actions": ["delete"], "before": %s, "after": null}}`, blocking)
	destroyedConfig := `,
	  {"address": "aws_s3_bucket_public_access_block.going", "mode": "managed",
	   "type": "aws_s3_bucket_public_access_block", "name": "going",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	fact := bucketPlanNoBlock(t, "public-read", destroyed, destroyedConfig)
	if !fact.IsKnown() || !fact.Get() {
		t.Fatalf("removing the block while granting a public ACL is public: state=%q grants=%v",
			fact.State, fact.Get())
	}
}

// TestOwnershipControlsAreReadOrNotConcluded covers the resource that can turn
// ACLs off, in both directions. A rule nobody can read leaves the ACL route in
// doubt; a rule that is simply not there does not disable anything, so the ACL
// still grants — a false alarm if the setting was enforced elsewhere, which is
// the safe way to be wrong here.
func TestOwnershipControlsAreReadOrNotConcluded(t *testing.T) {
	cases := map[string]struct {
		body   string
		public bool
	}{
		"the rule is not yet known": {`"after": {}, "after_unknown": {"rule": true}`, false},
		"the rule is sensitive": {
			`"after": {"rule": [{"object_ownership": "x"}]}, "after_sensitive": {"rule": true}`, false,
		},
		"the rule is absent":   {`"after": {}`, true},
		"the rule is a scalar": {`"after": {"rule": "BucketOwnerEnforced"}`, true},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			controls := fmt.Sprintf(`,
			  {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
			   "type": "aws_s3_bucket_ownership_controls", "name": "assets", "provider_name": "p",
			   "change": {"actions": ["create"], "before": null, %s}}`, c.body)
			controlsConfig := `,
			  {"address": "aws_s3_bucket_ownership_controls.assets", "mode": "managed",
			   "type": "aws_s3_bucket_ownership_controls", "name": "assets",
			   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

			fact := bucketPlanNoBlock(t, "public-read", controls, controlsConfig)
			if got := fact.IsKnown() && fact.Get(); got != c.public {
				t.Fatalf("public = %v, want %v (state %q)", got, c.public, fact.State)
			}
			if !c.public && fact.IsKnown() {
				t.Fatalf("an unreadable rule cannot settle the question, got state=%q", fact.State)
			}
		})
	}
}

// bucketPlanNoBlock builds a bucket with an ACL and one extra resource, and no
// public access block of its own.
func bucketPlanNoBlock(t *testing.T, acl, extraChange, extraConfig string) model.Fact[bool] {
	t.Helper()

	raw := []byte(fmt.Sprintf(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "provider_name": "p", "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": %q}}}%s
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "expressions": {}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}%s
	  ]}}
	}`, acl, extraChange, extraConfig))

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At("aws_s3_bucket.assets")
	if !ok || resource.ObjectStorage == nil {
		t.Fatal("no normalized bucket")
	}
	return resource.ObjectStorage.PublicAccess
}

// TestASensitiveAccountFlagIsReportedAsRedacted keeps the two non-conclusive
// states apart. Both prevent a conclusion, but a reader can act on "the plan
// marked this sensitive" and cannot act on "the plan does not say".
func TestASensitiveAccountFlagIsReportedAsRedacted(t *testing.T) {
	permissive := `{"block_public_acls": false, "block_public_policy": false,
	                "ignore_public_acls": false, "restrict_public_buckets": false}`
	account := `,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null,
	              "after": {"block_public_acls": true, "block_public_policy": false,
	                        "ignore_public_acls": false, "restrict_public_buckets": false},
	              "after_sensitive": {"block_public_policy": true}}}`
	accountConfig := `,
	  {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	   "type": "aws_s3_account_public_access_block", "name": "this", "expressions": {}}`

	publicPolicy := `{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\"}]}`
	policyChange := fmt.Sprintf(`,
	  {"address": "aws_s3_bucket_policy.assets", "mode": "managed", "type": "aws_s3_bucket_policy",
	   "name": "assets", "provider_name": "p",
	   "change": {"actions": ["create"], "before": null, "after": {"policy": "%s"}}}`, publicPolicy)
	policyConfig := `,
	  {"address": "aws_s3_bucket_policy.assets", "mode": "managed", "type": "aws_s3_bucket_policy",
	   "name": "assets",
	   "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	fact := bucketPlan(t, permissive, "private", policyChange+account, policyConfig+accountConfig)
	if fact.State != model.FactRedacted {
		t.Fatalf("state = %q, want %q — the deciding flag was marked sensitive", fact.State, model.FactRedacted)
	}
}
