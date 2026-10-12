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
