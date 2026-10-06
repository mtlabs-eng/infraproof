package gcp_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// TestTheMapperAgreesWithARealPlan is this milestone's authority test, and the
// thing it was missing.
//
// Every other fixture here is hand-authored from provider documentation, which
// is how this mapper shipped reading an unknown `direction` as unreadable: the
// attribute is Optional and Computed, a real create plan emits it as unknown,
// and all 25 hand-written fixtures wrote `direction = "INGRESS"` explicitly. The
// mapper answered UNKNOWN for every idiomatic firewall and nothing noticed,
// because nothing here had ever seen what Terraform actually emits.
//
// real-firewalls.json is genuine `terraform show -json` output: Terraform 1.14.0,
// hashicorp/google v6, `terraform plan` only -- never applied, no cloud
// contacted, a placeholder credentials filename. Each scenario sits on its own
// network so the firewalls do not interact, because a firewall's rule set is
// scoped to one network.
//
// The expectations are written from what Google Cloud does, not from what this
// mapper says. Where the two disagree, the mapper is wrong.
func TestTheMapperAgreesWithARealPlan(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		grants bool
		opens  string
		why    string
	}{
		// The case that was broken: no `direction` written anywhere, so the
		// provider's documented INGRESS default applies and SSH is open to the
		// whole internet.
		"implicit_public": {model.FactKnown, true, "tcp/22",
			"an allow from 0.0.0.0/0 with direction unwritten is an ingress rule by the provider's default"},
		// An allow block with no ports reaches every port, and the real plan
		// spells the unset list as [] -- neither null nor an absent key, which
		// is what the hand-written fixtures used.
		"every_port": {model.FactKnown, true, "tcp/0-65535",
			"an allow block with no ports reaches every port"},
		// A deny reaching only private addresses cannot cancel a grant open to
		// the world.
		"narrow_deny_allow": {model.FactKnown, true, "tcp/22",
			"a deny sourced from 10.0.0.0/8 does not touch traffic from the internet"},
		"narrow_deny":     {model.FactKnown, false, "", "a deny firewall opens nothing"},
		"wide_deny_allow": {model.FactKnown, false, "", "a deny from any address at a lower priority number wins"},
		"wide_deny":       {model.FactKnown, false, "", "a deny firewall opens nothing"},
		"disabled":        {model.FactKnown, false, "", "a disabled rule is not enforced"},
		"targeted_allow":  {model.FactKnown, false, "", "a deny reaching every instance covers an allow reaching a few"},
		"untargeted_deny": {model.FactKnown, false, "", "a deny firewall opens nothing"},
		// sctp is a protocol this build cannot name, and unlike ICMP it does
		// carry ports -- so reporting it as a port-less grant would be wrong in
		// kind. AWS already answers UNKNOWN for an unnameable protocol.
		"sctp": {model.FactUnknown, false, "",
			"a protocol this build cannot name is not a protocol it may report on"},
		// The provider accepts an IANA protocol number verbatim. 6 is TCP by a
		// closed, documented assignment, so this is readable.
		"protocol_number": {model.FactKnown, true, "tcp/22",
			"protocol 6 is TCP by IANA assignment"},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			found, ok := graphOf(t, "real-firewalls").At("google_compute_firewall." + name)
			if !ok {
				t.Fatalf("the real plan holds no firewall at google_compute_firewall.%s", name)
			}
			if found.Network == nil {
				t.Fatal("the mapper produced no network capabilities")
			}
			if got := found.Network.PublicIngress.State; got != want.state {
				t.Fatalf("state = %q, want %q: %s", got, want.state, want.why)
			}
			if want.state == model.FactKnown && found.Network.PublicIngress.Get() != want.grants {
				t.Fatalf("grants = %v, want %v: %s",
					found.Network.PublicIngress.Get(), want.grants, want.why)
			}
			if got := rendered(found.Network.OpenToAnyAddress); got != want.opens {
				t.Fatalf("opens %q, want %q: %s", got, want.opens, want.why)
			}
		})
	}
}

// TestTheRealPlanStatesNoDirectionAnywhere guards the premise of the test above.
//
// If a future re-generation of the fixture happened to write `direction`, the
// authority test would still pass while proving nothing about the case it exists
// for. The fixture's value is that it carries the shape nobody would author by
// hand.
func TestTheRealPlanStatesNoDirectionAnywhere(t *testing.T) {
	plan := planOf(t, "real-firewalls")

	var firewalls int
	for _, change := range plan.ResourceChanges {
		if change.Type != "google_compute_firewall" {
			continue
		}
		firewalls++
		if !change.Configured {
			t.Fatalf("%s carries no configuration, so what the author wrote is unrecorded", change.Address)
		}
		if change.States("direction") {
			t.Errorf("%s writes direction, so this fixture no longer carries the shape it exists for",
				change.Address)
		}
		if change.After.Field("direction").State() == terraformplan.StateKnown {
			t.Errorf("%s has a determined direction, which a real create plan does not emit", change.Address)
		}
	}
	if firewalls == 0 {
		t.Fatal("the fixture holds no firewall")
	}
}

// TestTheMapperAgreesWithARealPlanAboutWhatIsGenuinelyUndetermined is the other
// half of the direction fix, and the half that keeps it honest.
//
// An unknown attribute nobody wrote is the provider's documented default. An
// unknown attribute somebody did write is a value nothing can resolve yet, and
// applying a default to it would invent the one fact the plan withheld. Both
// shapes are real Terraform output -- `terraform plan` against an interpolated
// `direction` and `priority` -- and the fix is only sound if the second answers
// UNKNOWN.
func TestTheMapperAgreesWithARealPlanAboutWhatIsGenuinelyUndetermined(t *testing.T) {
	cases := map[string]struct {
		state model.FactState
		why   string
	}{
		"interpolated_direction": {model.FactUnknown,
			"a direction the author wrote and the plan cannot resolve is a gap, not a default"},
		"interpolated_priority": {model.FactUnknown,
			"which rule wins cannot be decided without the priority"},
		"unnameable_number": {model.FactUnknown,
			"IANA assigns 47 to a protocol this build cannot name"},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			found, ok := graphOf(t, "real-undetermined").At("google_compute_firewall." + name)
			if !ok {
				t.Fatalf("the real plan holds no firewall at google_compute_firewall.%s", name)
			}
			if found.Network == nil {
				t.Fatal("the mapper produced no network capabilities")
			}
			if got := found.Network.PublicIngress.State; got != want.state {
				t.Fatalf("state = %q, want %q: %s", got, want.state, want.why)
			}
			if len(found.Network.OpenToAnyAddress) != 0 {
				t.Fatalf("an undetermined set opens %v", found.Network.OpenToAnyAddress)
			}
		})
	}
}

// TestTheUndeterminedFixtureWritesTheAttributesItInterpolates guards that
// fixture's premise the same way, from the opposite side: if the configuration
// stopped writing `direction`, the unknown would become a default and the test
// above would pass while proving the reverse of what it claims.
func TestTheUndeterminedFixtureWritesTheAttributesItInterpolates(t *testing.T) {
	plan := planOf(t, "real-undetermined")

	for _, name := range []string{"direction", "priority"} {
		address := "google_compute_firewall.interpolated_" + name
		found := false
		for _, change := range plan.ResourceChanges {
			if change.Address != address {
				continue
			}
			found = true
			if !change.States(name) {
				t.Errorf("%s does not write %s, so its unknown is a default and not a gap", address, name)
			}
			if change.After.Field(name).State() != terraformplan.StateUnknown {
				t.Errorf("%s has a determined %s, so the fixture no longer carries the shape it exists for",
					address, name)
			}
		}
		if !found {
			t.Errorf("the fixture holds no resource at %s", address)
		}
	}
}
