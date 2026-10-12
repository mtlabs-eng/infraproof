package gcp_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
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

// The plan carries INGRESS in `after`, but nothing in the configuration wrote
// it -- and fw-public's configuration, written for milestone 08, records no
// allow and no source either. The grant rests on all of them, and the plan does
// not record who wrote the allow, so the method cannot be the default. It read
// provider-default until the adversarial review; the direction's default is
// pinned with every other input written by
// TestAKnownDirectionNobodyWroteIsTheDefaultWithAWrittenPriority.
func TestAFirewallWhoseAllowIsNotRecordedIsUnrecorded(t *testing.T) {
	got := firewall(t, "fw-public").Network.PublicIngress
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q, want %q", got.Method(), model.MethodConfigurationUnrecorded)
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

// A grant settles only because prevention is not enforced, so a member grant is
// stated only when prevention is too. The fixture writes it; public-iam-member,
// which does not, is the provider's default below.
func TestAMemberGrantIsStated(t *testing.T) {
	access := bucket(t, "public-iam-member-prevention-written").ObjectStorage.PublicAccess
	if access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// Review Focus 2.
func TestAGrantProvenTwiceTakesTheStatedProof(t *testing.T) {
	access := bucket(t, "public-member-and-policy-data-prevention-written").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodStated)
	}
}

// `implicit` writes `settings` and no `ip_configuration`, and the plan carries no
// switch for it at all. The value is milestone 09's -- Google's default, a public
// IP -- but the method cannot say "default": the configuration does not record
// ip_configuration, and a dynamic ip_configuration nobody can resolve leaves the
// identical plan. Until milestone 10's adversarial review this asserted
// provider-default, which is the claim D1 forbids for a block the plan does not
// record.
func TestAnAbsentIPv4SwitchInAnUnrecordedBlockIsUnrecorded(t *testing.T) {
	db := instance(t, "real-databases", "implicit").Database
	if !db.PublicEndpoint.IsKnown() || !db.PublicEndpoint.Get() {
		t.Fatalf("endpoint = %s; the provider default is a public IP", db.PublicEndpoint.State)
	}
	if db.PublicEndpoint.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodConfigurationUnrecorded)
	}
}

// A binding's members are stated in the plan, so a grant proven by one is stated
// -- with prevention written, which the grant also rests on.
func TestABindingGrantIsStated(t *testing.T) {
	access := bucket(t, "public-iam-binding-prevention-written").ObjectStorage.PublicAccess
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

// A real update plan: the configuration writes settings with a tier and labels
// and no ip_configuration, and the state holds ipv4_enabled = true and an
// authorized network 0.0.0.0/0, which Terraform carries into after because the
// block is Computed. Nobody under review wrote either, and the configuration
// cannot say whether a dynamic ip_configuration did: both halves of the verdict
// say so, and neither claims to be stated or the provider's default.
func TestAnIPConfigurationNobodyRecordedIsConfigurationUnrecorded(t *testing.T) {
	db := instance(t, "real-sql-ip-configuration-from-state", "db").Database
	if !db.PublicEndpoint.IsKnown() || db.PublicEndpoint.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("endpoint: method = %q (state %s), want %q",
			db.PublicEndpoint.Method(), db.PublicEndpoint.State, model.MethodConfigurationUnrecorded)
	}
	if !db.AdmitsAnyAddress.IsKnown() || !db.AdmitsAnyAddress.Get() ||
		db.AdmitsAnyAddress.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("admission: method = %q (state %s), want known true %q",
			db.AdmitsAnyAddress.Method(), db.AdmitsAnyAddress.State, model.MethodConfigurationUnrecorded)
	}
}

// Two instances in one real plan that differ only in how settings is written.
// The static one records the block, so its unwritten switch is the provider's
// default and its written allow list is stated. A dynamic settings block is not
// recorded at all, so neither half can be attributed.
func TestADynamicSettingsBlockIsConfigurationUnrecorded(t *testing.T) {
	static := instance(t, "real-sql-dynamic-settings", "static").Database
	if static.PublicEndpoint.Method() != model.MethodProviderDefault {
		t.Errorf("static endpoint: method = %q, want %q", static.PublicEndpoint.Method(), model.MethodProviderDefault)
	}
	if static.AdmitsAnyAddress.Method() != model.MethodStated {
		t.Errorf("static admission: method = %q, want %q", static.AdmitsAnyAddress.Method(), model.MethodStated)
	}
	dynamic := instance(t, "real-sql-dynamic-settings", "dyn").Database
	if !dynamic.PublicEndpoint.IsKnown() || dynamic.PublicEndpoint.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("dynamic endpoint: method = %q (state %s), want %q",
			dynamic.PublicEndpoint.Method(), dynamic.PublicEndpoint.State, model.MethodConfigurationUnrecorded)
	}
	if !dynamic.AdmitsAnyAddress.IsKnown() || dynamic.AdmitsAnyAddress.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("dynamic admission: method = %q (state %s), want %q",
			dynamic.AdmitsAnyAddress.Method(), dynamic.AdmitsAnyAddress.State, model.MethodConfigurationUnrecorded)
	}
}

// A grant settles only because public_access_prevention is not enforced, and
// that is the provider's value when nobody writes it. The hand-written
// public-iam-member writes only the bucket's name; real-bucket-prevention-pair
// is a real create plan of two buckets that differ only in writing it, where
// the unwritten one is unknown in after and the written one is "inherited".
func TestAGrantThroughAnUnwrittenPreventionIsTheProvidersDefault(t *testing.T) {
	access := bucket(t, "public-iam-member").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodProviderDefault {
		t.Errorf("public-iam-member: method = %q (state %s), want known true %q",
			access.Method(), access.State, model.MethodProviderDefault)
	}

	graph := graphOf(t, "real-bucket-prevention-pair")
	for address, want := range map[string]model.Method{
		"google_storage_bucket.unwritten": model.MethodProviderDefault,
		"google_storage_bucket.written":   model.MethodStated,
	} {
		found, ok := graph.At(address)
		if !ok || found.ObjectStorage == nil {
			t.Fatalf("real-bucket-prevention-pair has no bucket at %s", address)
		}
		access := found.ObjectStorage.PublicAccess
		if !access.IsKnown() || !access.Get() || access.Method() != want {
			t.Errorf("%s: method = %q (state %s), want known true %q", address, access.Method(), access.State, want)
		}
	}
}

// A real update plan: the state holds "inherited" and the configuration does
// not write the argument, which is Optional and Computed, so Terraform carries
// it. The grant rests on a value carried from state.
func TestAGrantThroughAPreventionCarriedFromStateIsPriorState(t *testing.T) {
	found, ok := graphOf(t, "real-bucket-prevention-from-state").At("google_storage_bucket.unwritten")
	if !ok || found.ObjectStorage == nil {
		t.Fatal("real-bucket-prevention-from-state has no bucket at google_storage_bucket.unwritten")
	}
	access := found.ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodPriorState {
		t.Errorf("method = %q (state %s), want known true %q", access.Method(), access.State, model.MethodPriorState)
	}
}

// The interpreted document keeps its method beside a defaulted prevention, as
// the AWS policy channel does beside a defaulted flag.
func TestAPolicyDataGrantThroughAnUnwrittenPreventionStaysInterpreted(t *testing.T) {
	access := bucket(t, "public-iam-policy-data").ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodPolicyDocument {
		t.Errorf("method = %q, want %q", access.Method(), model.MethodPolicyDocument)
	}
}

// Two firewalls in one real plan, identical but for how `allow` is written. The
// grant rests on the allow as much as on the source and the direction, and a
// dynamic allow is not recorded in the configuration at all: the fully written
// rule is stated and the dynamic one cannot be attributed.
func TestAGrantThroughADynamicAllowIsConfigurationUnrecorded(t *testing.T) {
	graph := graphOf(t, "real-firewall-dynamic-allow")
	for address, want := range map[string]model.Method{
		"google_compute_firewall.written":       model.MethodStated,
		"google_compute_firewall.dynamic_allow": model.MethodConfigurationUnrecorded,
	} {
		found, ok := graph.At(address)
		if !ok || found.Network == nil {
			t.Fatalf("real-firewall-dynamic-allow has no firewall at %s", address)
		}
		ingress := found.Network.PublicIngress
		if !ingress.IsKnown() || !ingress.Get() || ingress.Method() != want {
			t.Errorf("%s: method = %q (state %s), want known true %q", address, ingress.Method(), ingress.State, want)
		}
	}
}

// A firewall nobody wrote a source for cannot reach every address, so the
// source the grant rests on is always somebody's -- unless the plan does not
// record it. With no configuration at all, nothing is stated.
func TestAFirewallInAPlanWithoutConfigurationIsUnrecorded(t *testing.T) {
	plan := planOf(t, "real-firewall-dynamic-allow")
	for i := range plan.ResourceChanges {
		plan.ResourceChanges[i].Configured = false
		plan.ResourceChanges[i].Declared = false
		plan.ResourceChanges[i].Stated = nil
	}
	found, ok := providers.Normalize(plan, providers.Default()).At("google_compute_firewall.written")
	if !ok || found.Network == nil {
		t.Fatal("no firewall at google_compute_firewall.written")
	}
	ingress := found.Network.PublicIngress
	if !ingress.IsKnown() || !ingress.Get() || ingress.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q (state %s), want known true %q", ingress.Method(), ingress.State, model.MethodConfigurationUnrecorded)
	}
}
