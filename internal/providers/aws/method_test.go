package aws_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
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
