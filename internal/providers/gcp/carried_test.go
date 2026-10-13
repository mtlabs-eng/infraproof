package gcp_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

func methodAt(t *testing.T, fixture, address string) (model.NormalizedResource, bool) {
	t.Helper()
	return graphOf(t, fixture).At(address)
}

// Real plans of lifecycle { ignore_changes }, planned against hand-written
// state: Terraform keeps the prior value in after whatever the configuration
// writes, and the configuration does not record the lifecycle block. Each value
// below is one nobody under review wrote, so none of them is stated.
func TestValuesIgnoreChangesKeepsArePriorState(t *testing.T) {
	cases := []struct {
		fixture, address, why string
		fact                  func(model.NormalizedResource) model.Fact[bool]
	}{
		// The bucket writes prevention "enforced"; the state holds "inherited",
		// and allUsers is granted by a member that writes a single user.
		{"real-ignore-changes", "google_storage_bucket.b", "a grant through a member and a prevention the state overrides",
			func(r model.NormalizedResource) model.Fact[bool] { return r.ObjectStorage.PublicAccess }},
		// The firewall writes 10.0.0.0/8; the state holds 0.0.0.0/0.
		{"real-ignore-changes", "google_compute_firewall.fw", "a source the state overrides",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Network.PublicIngress }},
		// The firewall writes no source_ranges; the state holds 0.0.0.0/0.
		{"real-firewall-source-ignored", "google_compute_firewall.web", "a source nobody wrote",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Network.PublicIngress }},
		// The firewall writes no priority; the state holds 500, not the
		// documented 1000.
		{"real-firewall-priority-ignored", "google_compute_firewall.web", "a priority nobody wrote",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Network.PublicIngress }},
	}
	for _, c := range cases {
		r, ok := methodAt(t, c.fixture, c.address)
		if !ok {
			t.Fatalf("%s has no %s", c.fixture, c.address)
		}
		got := c.fact(r)
		if !got.IsKnown() || !got.Get() || got.Method() != model.MethodPriorState {
			t.Errorf("%s, %s: %s method = %q, want known true %q", c.fixture, c.why, got.State, got.Method(), model.MethodPriorState)
		}
	}

	r, _ := methodAt(t, "real-ignore-changes", "google_storage_bucket.b")
	if env := r.Environment; !env.IsKnown() || env.Method() != model.MethodPriorState {
		t.Errorf("labels kept by ignore_changes: %s method = %q, want %q", env.State, env.Method(), model.MethodPriorState)
	}
}

// The module idiom: public_access_prevention = var.x, with x defaulting to
// null. Terraform treats the null as unwritten, and the real create plan is the
// same as the one that omits the argument: the provider's default, not stated.
func TestAPreventionWrittenAsANullVariableIsTheProvidersDefault(t *testing.T) {
	r, ok := methodAt(t, "real-bucket-prevention-null-variable", "google_storage_bucket.b")
	if !ok {
		t.Fatal("no bucket")
	}
	got := r.ObjectStorage.PublicAccess
	if !got.IsKnown() || !got.Get() || got.Method() != model.MethodProviderDefault {
		t.Errorf("%s method = %q, want known true %q", got.State, got.Method(), model.MethodProviderDefault)
	}
}

// A deny the verdict skips is skipped on the strength of its own inputs, and the
// verdict rests on them as it rests on a deny it applies: carried from state,
// the skip is prior-state; written, it is stated. Two grounds that each suffice
// make the skip as strong as the better.
func TestADenySkippedRestsTheVerdictOnWhyItWasSkipped(t *testing.T) {
	cases := []struct {
		fixture string
		want    model.Method
	}{
		{"fw-deny-egress-carried", model.MethodPriorState},
		{"fw-deny-egress-written", model.MethodStated},
		{"fw-deny-disabled-carried", model.MethodPriorState},
		{"fw-deny-disabled-written", model.MethodStated},
		{"fw-deny-source-carried", model.MethodPriorState},
		{"fw-deny-source-written", model.MethodStated},
		{"fw-deny-network-carried", model.MethodPriorState},
		{"fw-deny-network-written", model.MethodStated},
		{"fw-deny-disabled-written-egress-carried", model.MethodStated},
		// Two networks differ only if both are what they say: web's own is
		// kept from state while its configuration writes another.
		{"fw-deny-network-subject-carried", model.MethodPriorState},
		// A deny scoped by a tag writes no source_ranges, and on a new
		// firewall the empty list is the provider's default.
		{"fw-deny-source-tags-only", model.MethodProviderDefault},
		{"fw-deny-source-tags-only-empty", model.MethodProviderDefault},
		// disabled is Optional, not Computed, defaulting to false: a new deny
		// holding true that the configuration does not record writing holds
		// a value nobody is recorded writing, which is not the default.
		{"fw-deny-disabled-unwritten-create", model.MethodConfigurationUnrecorded},
	}
	for _, c := range cases {
		got := firewall(t, c.fixture).Network.PublicIngress
		if !got.IsKnown() || !got.Get() || got.Method() != c.want {
			t.Errorf("%s: %s method = %q, want known true %q", c.fixture, got.State, got.Method(), c.want)
		}
	}
}

// Only a binding that grants is a proof of the grant. A member naming one user
// beside a policy document granting allUsers proves nothing, so the grant is the
// document's reading; a document naming one user beside a member ignore_changes
// keeps at allUsers proves nothing either, so the grant is prior state.
func TestOnlyABindingThatGrantsIsAProof(t *testing.T) {
	cases := []struct {
		fixture string
		want    model.Method
	}{
		{"real-policy-grant-beside-private-member", model.MethodPolicyDocument},
		{"real-carried-member-beside-private-policy", model.MethodPriorState},
	}
	for _, c := range cases {
		r, ok := methodAt(t, c.fixture, "google_storage_bucket.assets")
		if !ok {
			t.Fatalf("%s has no bucket", c.fixture)
		}
		got := r.ObjectStorage.PublicAccess
		if !got.IsKnown() || !got.Get() || got.Method() != c.want {
			t.Errorf("%s: %s method = %q, want known true %q", c.fixture, got.State, got.Method(), c.want)
		}
	}
}

// A deny the verdict applies rests it on the deny's source as well: one that
// reaches every address only because the state says so cancels the grant on
// the state's word.
func TestADenyAppliedThroughACarriedSourceIsPriorState(t *testing.T) {
	got := firewall(t, "fw-denied-lower-source-carried").Network.PublicIngress
	if !got.IsKnown() || got.Get() || got.Method() != model.MethodPriorState {
		t.Errorf("%s method = %q, want known false %q", got.State, got.Method(), model.MethodPriorState)
	}
}

// A value written by a reference, a variable or a function is one whose value
// the plan does not record. Where an update keeps the value the object had, the
// plan cannot separate the author's write from a value ignore_changes kept from
// state, so the method is configuration-unrecorded -- with ignore_changes and,
// by the decision recorded in milestone 10, without it. Block syntax is decided
// by the attributes inside the block: one written from a variable makes the
// block unrecorded; constants are compared with the value kept, as a constant
// in attribute syntax is.
func TestAWriteThePlanDoesNotEvaluateIsUnrecordedWhereTheUpdateKeepsTheValue(t *testing.T) {
	cases := []struct {
		fixture, address, why string
		fact                  func(model.NormalizedResource) model.Fact[bool]
		want                  model.Method
	}{
		{"real-reference-write-ignored", "google_storage_bucket.b", "a member and a prevention written from variables",
			func(r model.NormalizedResource) model.Fact[bool] { return r.ObjectStorage.PublicAccess },
			model.MethodConfigurationUnrecorded},
		{"real-reference-write-ignored", "google_compute_firewall.fw", "a source written from a local",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Network.PublicIngress },
			model.MethodConfigurationUnrecorded},
		// The allow block writes 443 in constants and the state holds 22.
		{"real-reference-write-ignored", "google_compute_firewall.blocks", "constant blocks the state overrides",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Network.PublicIngress },
			model.MethodPriorState},
		{"real-block-reference-unchanged", "google_compute_firewall.fw", "a block with a port written from a variable",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Network.PublicIngress },
			model.MethodConfigurationUnrecorded},
		{"real-block-reference-unchanged", "google_compute_firewall.const", "the same block in constants",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Network.PublicIngress },
			model.MethodStated},
		{"real-sql-networks-carried", "google_sql_database_instance.ref", "a network written from a variable",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Database.AdmitsAnyAddress },
			model.MethodConfigurationUnrecorded},
		{"real-sql-networks-carried", "google_sql_database_instance.const", "the same network in constants",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Database.AdmitsAnyAddress },
			model.MethodStated},
		// The network writes 10.0.0.0/8 in constants and the state holds
		// 0.0.0.0/0.
		{"real-sql-networks-carried", "google_sql_database_instance.ignored", "a constant network the state overrides",
			func(r model.NormalizedResource) model.Fact[bool] { return r.Database.AdmitsAnyAddress },
			model.MethodPriorState},
	}
	for _, c := range cases {
		r, ok := methodAt(t, c.fixture, c.address)
		if !ok {
			t.Fatalf("%s has no %s", c.fixture, c.address)
		}
		got := c.fact(r)
		if !got.IsKnown() || !got.Get() || got.Method() != c.want {
			t.Errorf("%s, %s: %s %v method = %q, want known true %q",
				c.fixture, c.why, got.State, got.IsKnown() && got.Get(), got.Method(), c.want)
		}
	}
}

// Real plans from the fifth review, where the method was decided at a place
// other than the one the verdict reads.

// ignore_changes = [labels["environment"]] beside a label the configuration
// moves: the map moves, the key the verdict reads does not.
func TestALabelTheLifecycleKeepsIsPriorStateWhileTheMapMoves(t *testing.T) {
	r, ok := methodAt(t, "real-labels-partial-ignore", "google_storage_bucket.b")
	if !ok {
		t.Fatal("no bucket")
	}
	if got := r.Environment; !got.IsKnown() || got.Method() != model.MethodPriorState {
		t.Errorf("%s method = %q, want known %q", got.State, got.Method(), model.MethodPriorState)
	}
}

// A block written in block syntax records only the attributes the author
// wrote, and Terraform plans the others empty. allow { protocol = "tcp" } is
// every TCP port; under ignore_changes = [allow] the state's ports = ["22"]
// stand, which nobody under review wrote. The firewall whose state adds a
// block the configuration does not write, and the Cloud SQL network list the
// state widens, read the same way.
func TestAnAttributeABlockDoesNotWriteIsNotStated(t *testing.T) {
	for _, address := range []string{"google_compute_firewall.fw2", "google_compute_firewall.fw"} {
		r, ok := methodAt(t, "real-blocks-unwritten-from-state", address)
		if !ok {
			t.Fatalf("no %s", address)
		}
		if got := r.Network.PublicIngress; !got.IsKnown() || !got.Get() || got.Method() != model.MethodPriorState {
			t.Errorf("%s: %s method = %q, want known true %q", address, got.State, got.Method(), model.MethodPriorState)
		}
	}
	db, ok := methodAt(t, "real-blocks-unwritten-from-state", "google_sql_database_instance.db")
	if !ok {
		t.Fatal("no instance")
	}
	if got := db.Database.AdmitsAnyAddress; !got.IsKnown() || got.Method() != model.MethodPriorState {
		t.Errorf("admits any address: %s method = %q, want known %q", got.State, got.Method(), model.MethodPriorState)
	}
}

// allow { protocol = "TCP" } against a state holding "tcp": the provider
// treats the two as one and the plan is a no-op -- measured -- but this build
// compares the constant as Terraform converts it, so the method understates it
// as prior-state.
func TestAProtocolTheProviderCanonicalizesReadsPriorState(t *testing.T) {
	r, ok := methodAt(t, "real-labels-partial-ignore", "google_compute_firewall.fw")
	if !ok {
		t.Fatal("no firewall")
	}
	if got := r.Network.PublicIngress; !got.IsKnown() || !got.Get() || got.Method() != model.MethodPriorState {
		t.Errorf("%s method = %q, want known true %q", got.State, got.Method(), model.MethodPriorState)
	}
}

// Real plans of the sixth review. source_ranges is a legacy-SDK set whose
// provider suppresses removing 0.0.0.0/0, so a range written by a variable, a
// variable element or a local is planned beside the state's public range, with
// no lifecycle block anywhere. The update moves the set and keeps the element
// the grant rests on, which nobody under review wrote: a write that is not a
// constant never makes it stated, and the plan does not record what the write
// evaluates to. The constant the plan contradicts is prior-state, and a
// configuration that writes nothing is a no-op keeping it.
func TestAPublicRangeTheProviderKeepsBesideAWriteIsNotStated(t *testing.T) {
	cases := []struct {
		fixture, address, why string
		want                  model.Method
	}{
		{"real-source-ranges-union-variable", "google_compute_firewall.a", "source_ranges = var.a",
			model.MethodConfigurationUnrecorded},
		{"real-source-ranges-union-variable", "google_compute_firewall.f", "[var.f], 0.0.0.0/1",
			model.MethodConfigurationUnrecorded},
		{"real-source-ranges-union-variable-element", "google_compute_firewall.a", "[var.a]",
			model.MethodConfigurationUnrecorded},
		{"real-source-ranges-union-variable-element", "google_compute_firewall.f", "[var.f], 10.0.0.1/8",
			model.MethodConfigurationUnrecorded},
		{"real-source-ranges-union-local", "google_compute_firewall.a", "[var.a]",
			model.MethodConfigurationUnrecorded},
		{"real-source-ranges-union-local", "google_compute_firewall.c", "[local.c]",
			model.MethodConfigurationUnrecorded},
		{"real-source-ranges-union-local", "google_compute_firewall.b", "the constant [\"10.0.0.0/8\"]",
			model.MethodPriorState},
		{"real-source-ranges-union-variable", "google_compute_firewall.c", "source_ranges = null",
			model.MethodPriorState},
	}
	for _, c := range cases {
		r, ok := methodAt(t, c.fixture, c.address)
		if !ok {
			t.Fatalf("%s has no %s", c.fixture, c.address)
		}
		got := r.Network.PublicIngress
		if !got.IsKnown() || !got.Get() || got.Method() != c.want {
			t.Errorf("%s, %s: %s %v method = %q, want known true %q",
				c.fixture, c.why, got.State, got.IsKnown() && got.Get(), got.Method(), c.want)
		}
	}

	// The controls replace the set: what the plan holds is new in this
	// update, the configuration's, and opens nothing.
	for _, address := range []string{"google_compute_firewall.d", "google_compute_firewall.e", "google_compute_firewall.g"} {
		r, _ := methodAt(t, "real-source-ranges-union-variable", address)
		if got := r.Network.PublicIngress; !got.IsKnown() || got.Get() {
			t.Errorf("%s: %s %v, want known false", address, got.State, got.IsKnown() && got.Get())
		}
	}
}
