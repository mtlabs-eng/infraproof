package aws_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

func at(t *testing.T, fixture, address string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At(address)
	if !ok {
		t.Fatalf("%s has no %s", fixture, address)
	}
	return found
}

func wantMethod[T any](t *testing.T, what string, fact model.Fact[T], method model.Method) {
	t.Helper()
	if !fact.IsKnown() || fact.Method() != method {
		t.Errorf("%s: %s method = %q, want known %q", what, fact.State, fact.Method(), method)
	}
}

// Real plans of lifecycle { ignore_changes }, planned against hand-written
// state. Terraform keeps the prior value in after whatever the configuration
// writes, and the configuration does not record the lifecycle block, so none
// of these values is one the author under review wrote.
func TestValuesIgnoreChangesKeepsArePriorState(t *testing.T) {
	// The bucket writes no tags and the state holds environment = prod; the
	// ACL writes private and the state holds public-read; the group writes
	// 443 from 10.0.0.0/8 and the state holds 22 from 0.0.0.0/0.
	b := at(t, "real-ignore-changes", "aws_s3_bucket.b")
	wantMethod(t, "an ACL the state overrides", b.ObjectStorage.PublicAccess, model.MethodPriorState)
	wantMethod(t, "tags nobody wrote", b.Environment, model.MethodPriorState)
	wantMethod(t, "an inline rule the state overrides",
		at(t, "real-ignore-changes", "aws_security_group.web").Network.PublicIngress, model.MethodPriorState)
	// A group that writes no tags, with environment = production in state.
	wantMethod(t, "a group's tags nobody wrote",
		at(t, "real-sg-tags-ignored", "aws_security_group.web").Environment, model.MethodPriorState)
}

// The module idiom: an argument written as a variable that defaults to null.
// Terraform treats the null as unwritten and carries the state's value, so the
// plan is the one an omitted argument gives: prior state, not stated.
func TestAnArgumentWrittenAsANullVariableReadsAsUnwritten(t *testing.T) {
	cluster := at(t, "real-null-variables-update", "aws_rds_cluster_instance.i").Database
	wantMethod(t, "publicly_accessible = var.x, null", cluster.PublicEndpoint, model.MethodPriorState)
	instance := at(t, "real-null-variables-update", "aws_db_instance.d").Database
	wantMethod(t, "port = var.x, null", instance.Port, model.MethodPriorState)
	// The instance writes publicly_accessible = true, which is a value.
	wantMethod(t, "a written switch", instance.PublicEndpoint, model.MethodStated)
}

// An update that writes one block flag, against a state holding all four
// true: Terraform plans the three unwritten ones back to their default, false.
// The value is the provider's default, and not one carried from state.
func TestBlockFlagsAnUpdateResetsAreTheProvidersDefault(t *testing.T) {
	wantMethod(t, "flags reset by an update",
		at(t, "real-acl-block-flags-reset", "aws_s3_bucket.b").ObjectStorage.PublicAccess, model.MethodProviderDefault)
}

// A grant through an ACL rests on the ownership rule that leaves ACLs enabled.
// Written as a dynamic block, the rule is one the configuration does not
// record, and neither is the grant.
func TestAnOwnershipRuleNobodyRecordedEntersTheACLGrant(t *testing.T) {
	wantMethod(t, "a dynamic ownership rule",
		at(t, "real-ownership-dynamic-rule", "aws_s3_bucket.b").ObjectStorage.PublicAccess,
		model.MethodConfigurationUnrecorded)
}

// A group open through a written inline rule and through a separate rule whose
// address ignore_changes keeps from state is proven twice, and a grant needs
// one proof: it takes the best. A third rule that opens nothing to every
// address proves nothing.
func TestAGroupGrantTakesItsBestProof(t *testing.T) {
	wantMethod(t, "a stated rule beside a carried one",
		at(t, "real-sg-inline-and-carried-rule", "aws_security_group.web").Network.PublicIngress, model.MethodStated)
}

// A configuration that lists only the ACL's bucket. acl is not Computed and
// has no default, so a canned ACL on a new resource is a value the plan does
// not record anybody writing -- and the flags beside it, written by nobody and
// false, are the provider's default.
func TestAnACLTheConfigurationDoesNotRecordIsUnrecorded(t *testing.T) {
	flags := map[string]bool{"block_public_acls": false, "ignore_public_acls": false,
		"block_public_policy": false, "restrict_public_buckets": false}
	wantMethod(t, "an ACL listed only by its bucket", bucketFromBlock(t, flags, "public-read"),
		model.MethodConfigurationUnrecorded)
}

// A value written by a reference, a variable or a function is one whose value
// the plan does not record: `lower(var.acl)` is recorded exactly as `var.acl`.
// Where an update keeps the value the object had, nothing in the plan separates
// the author's write from a value `lifecycle { ignore_changes }` kept from
// state, so the method is configuration-unrecorded, not stated -- with
// ignore_changes and, by the decision recorded in milestone 10, without it: a
// write that evaluates to what the object already had loses "stated" too.
func TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue(t *testing.T) {
	for _, fixture := range []string{"real-reference-write-ignored", "real-reference-write-unchanged"} {
		b := at(t, fixture, "aws_s3_bucket.b")
		wantMethod(t, fixture+": an ACL written from a variable", b.ObjectStorage.PublicAccess,
			model.MethodConfigurationUnrecorded)
		wantMethod(t, fixture+": tags written from a variable", b.Environment, model.MethodConfigurationUnrecorded)
		wantMethod(t, fixture+": an inline rule written from a reference",
			at(t, fixture, "aws_security_group.web").Network.PublicIngress, model.MethodConfigurationUnrecorded)
	}
	// A function of constants records neither a value nor a reference.
	wantMethod(t, "tags written by a function", at(t, "real-function-write-unchanged", "aws_s3_bucket.b").Environment,
		model.MethodConfigurationUnrecorded)
	// The same rule written as constants: the plan records the value, and the
	// value the update keeps is it.
	wantMethod(t, "an inline rule written as constants",
		at(t, "real-reference-write-unchanged", "aws_security_group.const").Network.PublicIngress, model.MethodStated)
}

// The same writes on an update that moves each value to the configuration's.
// ignore_changes keeps the prior value, so a value the update moves is not one
// it kept: the plan is applying what the configuration evaluates to. The plan
// does not record that value, so this is the one place a write it does not
// evaluate is still stated -- on the strength of the move, not of a comparison.
func TestAWriteThePlanDoesNotEvaluateIsStatedWhereTheUpdateMovesTheValue(t *testing.T) {
	b := at(t, "real-reference-write-moved", "aws_s3_bucket.b")
	wantMethod(t, "an ACL moved to a variable's value", b.ObjectStorage.PublicAccess, model.MethodStated)
	wantMethod(t, "tags moved to a variable's value", b.Environment, model.MethodStated)
	wantMethod(t, "an inline rule moved to a variable's value",
		at(t, "real-reference-write-moved", "aws_security_group.web").Network.PublicIngress, model.MethodStated)
}
