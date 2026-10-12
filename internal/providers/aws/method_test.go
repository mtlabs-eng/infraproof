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

func TestAnACLGrantIsStated(t *testing.T) {
	access := bucket(t, "public-acl").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// Two proofs, one stated and one interpreted. The finding cites the stated one,
// so the method is stated.
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
