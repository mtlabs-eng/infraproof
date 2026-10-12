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

// The priority pair. Every firewall writes its direction, so direction is not
// what can make a method the default. `web` is open because the deny sits above
// it at 1001, so the verdict rests on both priorities.
func TestAWrittenPriorityIsStated(t *testing.T) {
	got := firewall(t, "fw-priority-written").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodStated {
		t.Errorf("web = %s, method = %q, want known true %q", got.State, got.Method(), model.MethodStated)
	}
}

// `web` carries no priority at all, and the mapper applies the documented 1000.
func TestAnOmittedPriorityIsTheProvidersDefault(t *testing.T) {
	got := firewall(t, "fw-priority-omitted").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("web = %s, method = %q, want known true %q", got.State, got.Method(), model.MethodProviderDefault)
	}
}

// A real plan carries the default 1000 as a known value; the configuration says
// nobody wrote it.
func TestAKnownPriorityNobodyWroteIsTheProvidersDefault(t *testing.T) {
	got := firewall(t, "fw-priority-unwritten").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("web = %s, method = %q, want known true %q", got.State, got.Method(), model.MethodProviderDefault)
	}
}

// `web` writes its priority. The deny is skipped because its priority, which
// nobody wrote, puts it above `web`, so the open verdict rests on that default.
func TestADenySkippedOnADefaultedPriorityIsTheProvidersDefault(t *testing.T) {
	got := firewall(t, "fw-deny-above-priority-unwritten").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("web = %s, method = %q, want known true %q", got.State, got.Method(), model.MethodProviderDefault)
	}
}

// `web` writes its priority. The deny that cancels it applies because of a
// priority nobody wrote, so the closed verdict rests on that default.
func TestADenyAppliedOnADefaultedPriorityIsTheProvidersDefault(t *testing.T) {
	got := firewall(t, "fw-denied-lower-priority-unwritten").Network.PublicIngress
	if !got.IsKnown() || got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("web = %s, method = %q, want known false %q", got.State, got.Method(), model.MethodProviderDefault)
	}
}

// fw-public with its priority written: INGRESS is known in `after` and nobody
// wrote it, so direction alone makes the verdict the provider's default.
func TestAKnownDirectionNobodyWroteIsTheDefaultWithAWrittenPriority(t *testing.T) {
	got := firewall(t, "fw-public-priority-written").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("web = %s, method = %q, want known true %q", got.State, got.Method(), model.MethodProviderDefault)
	}
}

// The shape a real create plan emits for an unwritten direction, Computed and
// so unknown, with the priority written: direction alone is the default.
func TestAnUnknownUnwrittenDirectionIsTheDefaultWithAWrittenPriority(t *testing.T) {
	got := firewall(t, "fw-public-direction-computed").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("web = %s, method = %q, want known true %q", got.State, got.Method(), model.MethodProviderDefault)
	}
}
