package gcp_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// graphOf builds the graph of a fixture. Tests name fixtures; production code
// never does.
func graphOf(t *testing.T, fixture string) model.Graph {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture+".json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return providers.Normalize(plan, providers.Default())
}

// firewall returns the normalized firewall every fixture is about.
func firewall(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	found, ok := graphOf(t, fixture).At("google_compute_firewall.web")
	if !ok {
		t.Fatalf("fixture %s has no firewall at google_compute_firewall.web", fixture)
	}
	return found
}

// rendered writes the open ranges the way a reader sees them.
func rendered(ranges []model.OpenRange) string {
	texts := make([]string, 0, len(ranges))
	for _, open := range ranges {
		if !open.Protocol.HasPorts() {
			texts = append(texts, string(open.Protocol))
			continue
		}
		if open.Ports.From == open.Ports.To {
			texts = append(texts, string(open.Protocol)+"/"+itoa(open.Ports.From))
			continue
		}
		texts = append(texts, string(open.Protocol)+"/"+itoa(open.Ports.From)+"-"+itoa(open.Ports.To))
	}
	return strings.Join(texts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// TestIngressDetermination is the mapper's job for the third cloud, and the one
// where the ordered set spans resources: a firewall is both a rule and a subject,
// so what overrides it is another firewall on the same network.
func TestIngressDetermination(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		grants bool
		opens  string
	}{
		"fw-public":         {model.FactKnown, true, "tcp/22"},
		"fw-closed":         {model.FactKnown, false, ""},
		"fw-ipv6":           {model.FactKnown, true, "tcp/443"},
		"fw-every-protocol": {model.FactKnown, true, "every/0-65535"},
		"fw-no-ports":       {model.FactKnown, true, "tcp/0-65535"},
		// The same questions with the key omitted rather than written null. A
		// plan states an unset optional list either way, and the two have to be
		// one answer or this build is reading the plan's spelling instead of
		// what it says.
		"fw-ports-omitted":  {model.FactKnown, true, "tcp/0-65535"},
		"fw-source-omitted": {model.FactKnown, false, ""},
		"fw-icmp":           {model.FactKnown, true, "icmp"},
		"fw-port-range":     {model.FactKnown, true, "tcp/8000-8100"},
		// A rule the network behaves as if it did not have.
		"fw-disabled": {model.FactKnown, false, ""},
		// Egress and source tags each narrow it to something that is not every
		// address.
		"fw-egress":      {model.FactKnown, false, ""},
		"fw-source-tags": {model.FactKnown, false, ""},
		// The ordering across resources, in all three directions.
		"fw-denied-lower": {model.FactKnown, false, ""},
		// Both firewalls take their network from a resource created in the same
		// plan, so the attribute is unknown until apply and only the reference
		// says which network either of them is on. This is the ordinary shape,
		// not an edge one.
		"fw-denied-unknown-network": {model.FactKnown, false, ""},
		"fw-denied-equal":           {model.FactKnown, false, ""},
		"fw-deny-above":             {model.FactKnown, true, "tcp/22"},
		"fw-deny-other-network":     {model.FactKnown, true, "tcp/22"},
		// The same pair with no references anywhere, where only the literal
		// network names separate them.
		"fw-deny-other-network-literal": {model.FactKnown, true, "tcp/22"},
		"fw-deny-covers-targets":        {model.FactKnown, false, ""},
		"fw-deny-narrow-targets":        {model.FactKnown, true, "tcp/22"},
		"fw-deny-partial-ports":         {model.FactKnown, true, "tcp/20-21, tcp/23-30"},
		// A deny that does not overlap leaves the range exactly as it was.
		"fw-deny-disjoint": {model.FactKnown, true, "tcp/20-30"},
		// Ports on a protocol that has none cannot decide anything, including
		// whether the rule could be read: the provider refuses the pairing and
		// this build ignores the field rather than failing on it.
		"fw-icmp-with-ports": {model.FactKnown, true, "icmp"},
		// What the plan has not determined.
		"fw-unknown-direction": {model.FactUnknown, false, ""},
		"fw-unknown-source":    {model.FactUnknown, false, ""},
		// A priority the plan has not determined, so nothing can be ordered
		// against it, and a port that is not a port.
		"fw-unknown-priority": {model.FactUnknown, false, ""},
		"fw-unreadable-port":  {model.FactUnknown, false, ""},
	}

	for fixture, want := range cases {
		t.Run(fixture, func(t *testing.T) {
			found := firewall(t, fixture)
			if found.Family != model.FamilyNetwork {
				t.Fatalf("family = %q, want %q", found.Family, model.FamilyNetwork)
			}
			if found.Network == nil {
				t.Fatal("the mapper produced no network capabilities")
			}
			if got := found.Network.PublicIngress.State; got != want.state {
				t.Fatalf("state = %q, want %q", got, want.state)
			}
			if want.state == model.FactKnown && found.Network.PublicIngress.Get() != want.grants {
				t.Fatalf("grants = %v, want %v", found.Network.PublicIngress.Get(), want.grants)
			}
			if got := rendered(found.Network.OpenToAnyAddress); got != want.opens {
				t.Fatalf("opens %q, want %q", got, want.opens)
			}
		})
	}
}

// TestDenyWinsAtEqualPriority is this cloud's own rule, and the one a mapper
// written from the other two would get wrong. GCP gives a deny precedence over an
// allow of the same priority; Azure forbids the tie altogether.
//
// Both directions, because one fixture would pass just as well if every deny won.
func TestDenyWinsAtEqualPriority(t *testing.T) {
	equal := firewall(t, "fw-denied-equal").Network
	above := firewall(t, "fw-deny-above").Network

	if equal.PublicIngress.Get() {
		t.Error("a deny at the same priority did not take precedence, which is this cloud's rule")
	}
	if !above.PublicIngress.Get() {
		t.Error("a deny at a higher priority number took precedence, which is the ordering backwards")
	}
}

// TestADenyOnAnotherNetworkReachesNothing covers the scope of the ordered set. A
// firewall applies to one network, and a deny somewhere else is not part of this
// set at all -- reading it as one would report a change as closed because of a
// rule that cannot reach it.
func TestADenyOnAnotherNetworkReachesNothing(t *testing.T) {
	capabilities := firewall(t, "fw-deny-other-network").Network

	if !capabilities.PublicIngress.Get() {
		t.Fatal("a deny on another network closed this one")
	}
}

// TestADenyThatCannotBeShownToCoverTheAllowIsNotApplied covers the direction this
// mapper refuses to guess in. A deny narrowed to tagged instances reaches some of
// what an untargeted allow reaches, and "some" cannot prove prevention -- so the
// grant stands, which is the safe direction, and the narrowing is reported.
//
// The reverse is provable and is applied: a deny that applies to every instance
// covers an allow narrowed to a few.
func TestADenyThatCannotBeShownToCoverTheAllowIsNotApplied(t *testing.T) {
	narrow := firewall(t, "fw-deny-narrow-targets").Network
	if !narrow.PublicIngress.Get() {
		t.Fatal("a deny that reaches only some of the allow's instances was treated as covering it")
	}
	var said bool
	for _, control := range narrow.Unresolved {
		if strings.Contains(control.Reason, "target") {
			said = true
		}
	}
	if !said {
		t.Error("the narrowing is not reported, so a reader cannot tell why the grant stands")
	}

	covering := firewall(t, "fw-deny-covers-targets").Network
	if covering.PublicIngress.Get() {
		t.Fatal("a deny applying to every instance did not cover an allow applying to a few")
	}
}

// TestEveryFactNamesTheAttributeItCameFrom is the milestone's criterion made
// mechanical for this cloud.
func TestEveryFactNamesTheAttributeItCameFrom(t *testing.T) {
	for _, fixture := range []string{"fw-public", "fw-closed", "fw-denied-lower"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := firewall(t, fixture).Network

			if len(capabilities.PublicIngress.Sources) == 0 {
				t.Fatal("the deciding fact cites nothing")
			}
			for _, source := range capabilities.PublicIngress.Sources {
				if source.ResourceAddress == "" || source.AttributePath == "" {
					t.Fatalf("a source names no attribute: %+v", source)
				}
				if source.Cloud != model.CloudGCP {
					t.Fatalf("a source names cloud %q", source.Cloud)
				}
			}
			for _, open := range capabilities.OpenToAnyAddress {
				if len(open.Sources) == 0 {
					t.Fatalf("the range %v cites nothing", open)
				}
			}
		})
	}
}

// TestADenyFirewallIsASubjectThatOpensNothing covers the resource that is a rule
// and a subject at once. The deny firewall is judged in its own right, and what it
// opens is nothing -- it must not be reported as a resource nothing understood,
// and it must not be reported as a grant either.
func TestADenyFirewallIsASubjectThatOpensNothing(t *testing.T) {
	found, ok := graphOf(t, "fw-denied-lower").At("google_compute_firewall.block")
	if !ok {
		t.Fatal("the deny firewall is not in the graph")
	}
	if !found.Interpreted || found.Family != model.FamilyNetwork {
		t.Fatalf("interpreted = %v, family = %q", found.Interpreted, found.Family)
	}
	if found.Network == nil {
		t.Fatal("a firewall is a subject and carries its own capabilities")
	}
	if found.Network.PublicIngress.IsKnown() && found.Network.PublicIngress.Get() {
		t.Fatal("a deny firewall was read as permitting ingress")
	}
	if len(found.Network.OpenToAnyAddress) != 0 {
		t.Fatalf("a deny firewall opens %v", found.Network.OpenToAnyAddress)
	}
}

// TestObjectStorageIsUntouched keeps the two families apart in this mapper too.
func TestObjectStorageIsUntouched(t *testing.T) {
	found, ok := graphOf(t, "public-iam-member").At("google_storage_bucket.assets")
	if !ok {
		t.Skip("this fixture has no bucket to compare against")
	}
	if found.Family != model.FamilyObjectStorage || found.Network != nil {
		t.Fatalf("family = %q, network = %v", found.Family, found.Network)
	}
}
