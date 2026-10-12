package aws_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
)

func TestAnUnwrittenSwitchIsTheProvidersDefault(t *testing.T) {
	endpoint := database(t, "rds-switch-stated-nowhere", "aws_rds_cluster_instance.ax").Database.PublicEndpoint
	if !endpoint.IsKnown() || endpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q (state %s), want %q", endpoint.Method(), endpoint.State, model.MethodProviderDefault)
	}
}

func TestAWrittenSwitchIsStated(t *testing.T) {
	endpoint := database(t, "real-databases", "aws_db_instance.reachable").Database.PublicEndpoint
	if endpoint.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", endpoint.Method(), model.MethodStated)
	}
}

func TestAnEngineDerivedPortIsFromTheTable(t *testing.T) {
	port := database(t, "real-databases", "aws_db_instance.reachable").Database.Port
	if !port.IsKnown() || port.Method() != model.MethodDocumentedTable {
		t.Errorf("method = %q (state %s), want %q", port.Method(), port.State, model.MethodDocumentedTable)
	}
}

func TestAStatedPortIsStated(t *testing.T) {
	graph := normalize(t, "rds-port-written")
	for _, r := range graph.Resources {
		if r.Database == nil || !r.Database.Port.IsKnown() {
			continue
		}
		if r.Database.Port.Method() != model.MethodStated {
			t.Errorf("%s: method = %q, want %q", r.Address, r.Database.Port.Method(), model.MethodStated)
		}
		return
	}
	t.Fatal("no database with a known port in rds-port-written")
}

func TestAPolicyGrantIsInterpreted(t *testing.T) {
	access := bucket(t, "public-policy").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodPolicyDocument {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodPolicyDocument)
	}
}

// An ACL grant settles only because no block flag shuts the route. With every
// flag written, each input the grant rests on is stated.
func TestAnACLGrantIsStated(t *testing.T) {
	access := bucket(t, "public-acl-flags-written").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// public-acl writes none of the block flags: the provider writes its default,
// false, into the plan, and the grant rests on that default.
func TestAnACLGrantThroughDefaultedBucketFlagsIsTheProvidersDefault(t *testing.T) {
	access := bucket(t, "public-acl").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q (state %s), want known true %q", access.Method(), access.State, model.MethodProviderDefault)
	}
}

// The account-wide block's flags decide the route as well, and an unwritten one
// is the provider's default just the same.
func TestAnACLGrantThroughDefaultedAccountFlagsIsTheProvidersDefault(t *testing.T) {
	access := bucket(t, "public-acl-account-flags-defaulted").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q (state %s), want known true %q", access.Method(), access.State, model.MethodProviderDefault)
	}
}

// public-policy writes none of the block flags either. The grant rests on two
// inputs that are not stated, the defaulted flags and the interpreted document,
// and the spec says such a site is reported, not ordered: the method stays the
// document's. Recorded under the milestone's limitations.
func TestAPolicyGrantThroughDefaultedFlagsStaysInterpreted(t *testing.T) {
	access := bucket(t, "public-policy").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodPolicyDocument {
		t.Errorf("method = %q (state %s), want known true %q", access.Method(), access.State, model.MethodPolicyDocument)
	}
}

// Two proofs, one stated and one interpreted. The finding cites the stated one,
// so the method is stated. The fixture writes every block flag, so the ACL
// proof rests on nothing the provider defaulted.
func TestAGrantProvenTwiceTakesTheStatedProof(t *testing.T) {
	access := bucket(t, "public-acl-and-policy").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// A real plan emits publicly_accessible as known false when nobody wrote it.
func TestAKnownSwitchNobodyWroteIsTheProvidersDefault(t *testing.T) {
	endpoint := database(t, "real-databases", "aws_db_instance.private").Database.PublicEndpoint
	if !endpoint.IsKnown() || endpoint.Get() || endpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q (state %s), want %q", endpoint.Method(), endpoint.State, model.MethodProviderDefault)
	}
}

// A real plan emits publicly_accessible as unknown on an Aurora instance nobody
// wrote it on. That unknown is the provider's default, and the method says so.
func TestAComputedSwitchNobodyWroteIsTheProvidersDefault(t *testing.T) {
	endpoint := database(t, "real-aurora-defaults", "aws_rds_cluster_instance.ax").Database.PublicEndpoint
	if !endpoint.IsKnown() || endpoint.Get() || endpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q (state %s), want known false %q", endpoint.Method(), endpoint.State, model.MethodProviderDefault)
	}
}

// Real update plans, planned against a hand-written state with -refresh=false:
// the configuration of real-rds-unwritten-update writes neither
// publicly_accessible on the Aurora instance nor port anywhere, and the state
// holds publicly_accessible = true and port 5432. Terraform carries both into
// after as known values. Neither is stated, and the Aurora switch is not the
// provider's default either -- its default is false.
func TestAnUnwrittenComputedSwitchCarriedFromStateIsPriorState(t *testing.T) {
	endpoint := database(t, "real-rds-unwritten-update", "aws_rds_cluster_instance.i").Database.PublicEndpoint
	if !endpoint.IsKnown() || !endpoint.Get() || endpoint.Method() != model.MethodPriorState {
		t.Errorf("method = %q (state %s, value %v), want known true %q",
			endpoint.Method(), endpoint.State, endpoint.Get(), model.MethodPriorState)
	}
}

// The same switch written on the plain instance stays stated on an update.
func TestAWrittenSwitchOnAnUpdateIsStated(t *testing.T) {
	endpoint := database(t, "real-rds-unwritten-update", "aws_db_instance.d").Database.PublicEndpoint
	if endpoint.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", endpoint.Method(), model.MethodStated)
	}
}

// A port nobody wrote, carried from state, is the deployed port: prior-state,
// not stated and not the table. On the create twin, identical HCL, it is
// unknown and the engine table supplies it.
func TestAnUnwrittenPortCarriedFromStateIsPriorState(t *testing.T) {
	for _, address := range []string{"aws_db_instance.d", "aws_rds_cluster_instance.i"} {
		port := database(t, "real-rds-unwritten-update", address).Database.Port
		if !port.IsKnown() || port.Method() != model.MethodPriorState {
			t.Errorf("%s update: method = %q (state %s), want %q", address, port.Method(), port.State, model.MethodPriorState)
		}
		port = database(t, "real-rds-unwritten-create", address).Database.Port
		if !port.IsKnown() || port.Method() != model.MethodDocumentedTable {
			t.Errorf("%s create: method = %q (state %s), want %q", address, port.Method(), port.State, model.MethodDocumentedTable)
		}
	}
}

// A real update plan: the group's configuration writes name, vpc_id and tags and
// no ingress, and the state holds one inline rule, tcp 22 from 0.0.0.0/0, which
// Terraform carries into after because `ingress` is Optional and Computed. The
// grant is real and nobody under review wrote it. The configuration cannot say
// whether a dynamic ingress block wrote it either -- Terraform does not record
// one -- so the method is that the plan does not record it.
func TestAnInlineGrantNobodyRecordedIsConfigurationUnrecorded(t *testing.T) {
	ingress := group(t, "real-sg-ingress-from-state", "aws_security_group.web").Network.PublicIngress
	if !ingress.IsKnown() || !ingress.Get() || ingress.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q (state %s), want known true %q", ingress.Method(), ingress.State, model.MethodConfigurationUnrecorded)
	}
}

// Written inline, the grant is stated; written as a separate rule whose address
// is written, it is stated too.
func TestAWrittenGrantIsStatedInlineOrSeparate(t *testing.T) {
	for _, address := range []string{"aws_security_group.mixed", "aws_security_group.protoall", "aws_security_group.ipv6"} {
		ingress := group(t, "real-groups", address).Network.PublicIngress
		if !ingress.IsKnown() || !ingress.Get() || ingress.Method() != model.MethodStated {
			t.Errorf("%s: method = %q (state %s, value %v), want known true %q",
				address, ingress.Method(), ingress.State, ingress.Get(), model.MethodStated)
		}
	}
}

func group(t *testing.T, fixture, address string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At(address)
	if !ok || found.Network == nil {
		t.Fatalf("fixture %s has no network resource at %s", fixture, address)
	}
	return found
}

// A pair of real create plans. In the first the account block is
// `resource "aws_s3_account_public_access_block" "acct" {}`, which Terraform
// records with no expressions at all; in the second it writes one flag the ACL
// route does not read. In both, the two flags the grant rests on are unwritten
// and the provider wrote its default, false. Writing more must not make the
// claim stronger: both are the provider's default.
func TestAnEmptyAccountBlockIsAsDefaultedAsOneThatWritesSomethingElse(t *testing.T) {
	for _, fixture := range []string{"real-acl-account-block-empty", "real-acl-account-block-one-flag"} {
		access := normalizeAt(t, fixture, "aws_s3_bucket.b").ObjectStorage.PublicAccess
		if !access.IsKnown() || !access.Get() || access.Method() != model.MethodProviderDefault {
			t.Errorf("%s: method = %q (state %s), want known true %q", fixture, access.Method(), access.State, model.MethodProviderDefault)
		}
	}
}

func normalizeAt(t *testing.T, fixture, address string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At(address)
	if !ok {
		t.Fatalf("fixture %s has no resource at %s", fixture, address)
	}
	return found
}

// A separate rule's address is stated where the configuration writes it.
func TestASeparateRuleAddressIsStatedWhereTheConfigurationWritesIt(t *testing.T) {
	ingress := securityGroup(t, "sg-public-rule-written").Network.PublicIngress
	if !ingress.IsKnown() || !ingress.Get() || ingress.Method() != model.MethodStated {
		t.Errorf("method = %q (state %s), want known true %q", ingress.Method(), ingress.State, model.MethodStated)
	}
}

// sg-public-rule's configuration lists only the rule's security_group_id, as a
// milestone 08 fixture written by hand. The address that opens is Optional, not
// Computed and without a default, so no real plan carries one nobody wrote on a
// new rule -- and a value the configuration does not record as written is never
// stated. Until the fourth review this read stated, on the premise that the
// shape proves the value was written; ignore_changes falsified that premise.
func TestASeparateRuleAddressTheConfigurationDoesNotRecordIsUnrecorded(t *testing.T) {
	ingress := securityGroup(t, "sg-public-rule").Network.PublicIngress
	if !ingress.IsKnown() || !ingress.Get() || ingress.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q (state %s), want known true %q", ingress.Method(), ingress.State, model.MethodConfigurationUnrecorded)
	}
}

// The proof of prevention rests on four flags read as true, and is stated where
// the configuration writes them.
func TestAProofOfPreventionRestsOnFlagsSomebodyWrote(t *testing.T) {
	access := bucket(t, "private-flags-written").ObjectStorage.PublicAccess
	if !access.IsKnown() || access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q (state %s), want known false %q", access.Method(), access.State, model.MethodStated)
	}
}

// private.json's configuration lists only the block's bucket. Each flag defaults
// to false and none is Computed, so a true on a new block is a value the plan
// does not record anybody writing.
func TestAProofOfPreventionOnFlagsTheConfigurationDoesNotRecordIsUnrecorded(t *testing.T) {
	access := bucket(t, "private").ObjectStorage.PublicAccess
	if !access.IsKnown() || access.Get() || access.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q (state %s), want known false %q", access.Method(), access.State, model.MethodConfigurationUnrecorded)
	}
}

// The same plan without its configuration records nothing about who wrote the
// flags, so the proof is not stated.
func TestAProofOfPreventionWithoutConfigurationIsUnrecorded(t *testing.T) {
	parsed := plan(t, "private")
	for i := range parsed.ResourceChanges {
		parsed.ResourceChanges[i].Declared = false
		parsed.ResourceChanges[i].Configured = false
		parsed.ResourceChanges[i].Stated = nil
	}
	found, ok := providers.Normalize(parsed, providers.Default()).At("aws_s3_bucket.assets")
	if !ok || found.ObjectStorage == nil {
		t.Fatal("no bucket at aws_s3_bucket.assets")
	}
	access := found.ObjectStorage.PublicAccess
	if !access.IsKnown() || access.Get() || access.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q (state %s), want known false %q", access.Method(), access.State, model.MethodConfigurationUnrecorded)
	}
}
