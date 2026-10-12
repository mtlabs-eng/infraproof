package gcp_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

func TestAnUnwrittenIPv4SwitchIsTheProvidersDefault(t *testing.T) {
	db := instance(t, "real-databases-ipv4-unwritten", "default_endpoint").Database
	if !db.PublicEndpoint.IsKnown() || !db.PublicEndpoint.Get() {
		t.Fatalf("endpoint = %s; the provider default is a public IP", db.PublicEndpoint.State)
	}
	if db.PublicEndpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodProviderDefault)
	}
}

func TestAWrittenIPv4SwitchIsStated(t *testing.T) {
	db := instance(t, "real-databases", "reachable").Database
	if db.PublicEndpoint.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodStated)
	}
}

func TestAVersionDerivedPortIsFromTheTable(t *testing.T) {
	port := instance(t, "real-databases", "reachable").Database.Port
	if !port.IsKnown() || port.Method() != model.MethodDocumentedTable {
		t.Errorf("method = %q, want %q", port.Method(), model.MethodDocumentedTable)
	}
}

func TestAWrittenDirectionIsStated(t *testing.T) {
	stated := firewall(t, "fw-public-direction-written").Network.PublicIngress
	if !stated.IsKnown() || !stated.Get() || stated.Method() != model.MethodStated {
		t.Errorf("written direction: method = %q, want %q", stated.Method(), model.MethodStated)
	}
}

// The plan carries INGRESS in `after`, but nothing in the configuration wrote it.
func TestAKnownDirectionNobodyWroteIsTheProvidersDefault(t *testing.T) {
	got := firewall(t, "fw-public").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", got.Method(), model.MethodProviderDefault)
	}
}

func TestAnOmittedDirectionIsTheProvidersDefault(t *testing.T) {
	omitted := firewall(t, "fw-public-direction-omitted").Network.PublicIngress
	if !omitted.IsKnown() || !omitted.Get() || omitted.Method() != model.MethodProviderDefault {
		t.Errorf("omitted direction: method = %q, want %q", omitted.Method(), model.MethodProviderDefault)
	}
}

// The real plan's implicit firewall: direction unknown and unwritten.
func TestAnUnknownUnwrittenDirectionIsTheProvidersDefault(t *testing.T) {
	r, ok := graphOf(t, "real-firewalls").At("google_compute_firewall.implicit_public")
	if !ok {
		t.Fatal("implicit_public not in real-firewalls")
	}
	if r.Network.PublicIngress.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", r.Network.PublicIngress.Method(), model.MethodProviderDefault)
	}
}

// `web` writes its direction, so only the deny's own defaulted direction can make
// the closed verdict the provider's default.
func TestACancellingDenyWithADefaultedDirectionIsTheProvidersDefault(t *testing.T) {
	r, ok := graphOf(t, "fw-denied-lower-direction-omitted").At("google_compute_firewall.web")
	if !ok {
		t.Fatal("web not in fixture")
	}
	got := r.Network.PublicIngress
	if !got.IsKnown() || got.Get() {
		t.Fatalf("web = %s; the deny should cancel the grant", got.State)
	}
	if got.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", got.Method(), model.MethodProviderDefault)
	}
}

// A deny with a defaulted direction that is skipped is never applied, so the
// stated verdict does not rest on it.
func TestASkippedDenyWithADefaultedDirectionLeavesTheVerdictStated(t *testing.T) {
	r, ok := graphOf(t, "fw-deny-above-direction-omitted").At("google_compute_firewall.web")
	if !ok {
		t.Fatal("web not in fixture")
	}
	got := r.Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodStated {
		t.Errorf("web = %s, method = %q, want known true %q", got.State, got.Method(), model.MethodStated)
	}
}

func TestAPolicyDataGrantIsInterpreted(t *testing.T) {
	access := bucket(t, "public-iam-policy-data").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodPolicyDocument {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodPolicyDocument)
	}
}

func TestAMemberGrantIsStated(t *testing.T) {
	access := bucket(t, "public-iam-member").ObjectStorage.PublicAccess
	if access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// Review Focus 2.
func TestAGrantProvenTwiceTakesTheStatedProof(t *testing.T) {
	access := bucket(t, "public-member-and-policy-data").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// `implicit` writes `settings` and no `ip_configuration`, and the plan carries no
// switch for it at all. The public IP is Google's default, so the method is too.
func TestAnAbsentIPv4SwitchIsTheProvidersDefault(t *testing.T) {
	db := instance(t, "real-databases", "implicit").Database
	if !db.PublicEndpoint.IsKnown() || !db.PublicEndpoint.Get() {
		t.Fatalf("endpoint = %s; the provider default is a public IP", db.PublicEndpoint.State)
	}
	if db.PublicEndpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodProviderDefault)
	}
}

// A binding's members are stated in the plan, so a grant proven by one is stated.
func TestABindingGrantIsStated(t *testing.T) {
	access := bucket(t, "public-iam-binding").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want known true %q", access.Method(), model.MethodStated)
	}
}
