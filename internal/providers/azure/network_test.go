package azure_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// normalize builds the graph of a fixture. Tests name fixtures; production code
// never does.
func normalize(t *testing.T, fixture string) model.Graph {
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

// securityGroup returns the normalized network security group of a fixture.
func securityGroup(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At("azurerm_network_security_group.web")
	if !ok {
		t.Fatalf("fixture %s has no network security group", fixture)
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

// TestIngressDetermination is the mapper's job, and the half of it that AWS does
// not have: an ordered set where a deny at a lower priority number takes
// precedence over an allow at a higher one.
//
// The verdict is about the set, not about any rule in it. A permissive rule
// overridden by a deny below it permits nothing; the same deny above it changes
// nothing.
func TestIngressDetermination(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		grants bool
		opens  string
	}{
		"nsg-public-inline": {model.FactKnown, true, "tcp/22"},
		"nsg-closed-inline": {model.FactKnown, false, ""},
		// The service tag for every public address, which only the singular
		// field may carry.
		"nsg-internet-tag":   {model.FactKnown, true, "tcp/22"},
		"nsg-prefix-list":    {model.FactKnown, true, "tcp/22"},
		"nsg-ipv6":           {model.FactKnown, true, "tcp/443"},
		"nsg-every-protocol": {model.FactKnown, true, "every/0-65535"},
		"nsg-icmp":           {model.FactKnown, true, "icmp"},
		// In the order the fields state them. Sorting for a reader is the
		// rule's job; a mapper that reordered would make the plan's own order
		// unrecoverable.
		"nsg-port-list": {model.FactKnown, true, "tcp/80, tcp/443"},
		// The ordering, read rather than assumed.
		"nsg-denied-below": {model.FactKnown, false, ""},
		"nsg-deny-above":   {model.FactKnown, true, "tcp/22"},
		// A deny covering part of the range leaves the rest open, exactly.
		"nsg-deny-partial-ports": {model.FactKnown, true, "tcp/20-21, tcp/23-30"},
		// Outbound says nothing about who can reach in.
		"nsg-outbound-only": {model.FactKnown, false, ""},
		// Separate rule resources: a grant is provable, closure is not.
		"nsg-separate-open":   {model.FactKnown, true, "tcp/22"},
		"nsg-separate-closed": {model.FactUnknown, false, ""},
		"nsg-no-rules":        {model.FactUnknown, false, ""},
		// Which rule wins cannot be decided without the priority.
		"nsg-unreadable-priority": {model.FactUnknown, false, ""},
		// A port, a source and a protocol the plan or this build cannot read.
		// Each is unknown rather than absent: an unreadable value could be the
		// one that opens everything.
		"nsg-unreadable-port":     {model.FactUnknown, false, ""},
		"nsg-unreadable-source":   {model.FactUnknown, false, ""},
		"nsg-unreadable-protocol": {model.FactUnknown, false, ""},
		// A service tag this build does not interpret. Azure adds them, and one
		// nobody here has heard of could be every address.
		"nsg-unknown-service-tag": {model.FactUnknown, false, ""},
		// Two rules at one priority, which Azure refuses. The grant stands,
		// because letting an equal deny win would hide a grant on a set the
		// platform would not have accepted in the first place.
		"nsg-equal-priority": {model.FactKnown, true, "tcp/22"},
		// Two allows: the ranges come out in the set's own order, lowest
		// priority number first.
		"nsg-two-allows": {model.FactKnown, true, "tcp/8080, tcp/22"},
		// A deny that does not overlap leaves the range exactly as it was.
		"nsg-deny-disjoint": {model.FactKnown, true, "tcp/20-30"},
		// A deny reaching a protocol with no ports reaches all of it.
		"nsg-icmp-denied": {model.FactKnown, false, ""},
	}

	for fixture, want := range cases {
		t.Run(fixture, func(t *testing.T) {
			group := securityGroup(t, fixture)
			if group.Family != model.FamilyNetwork {
				t.Fatalf("family = %q, want %q", group.Family, model.FamilyNetwork)
			}
			if group.Network == nil {
				t.Fatal("the mapper produced no network capabilities")
			}
			if got := group.Network.PublicIngress.State; got != want.state {
				t.Fatalf("state = %q, want %q", got, want.state)
			}
			if want.state == model.FactKnown && group.Network.PublicIngress.Get() != want.grants {
				t.Fatalf("grants = %v, want %v", group.Network.PublicIngress.Get(), want.grants)
			}
			if got := rendered(group.Network.OpenToAnyAddress); got != want.opens {
				t.Fatalf("opens %q, want %q", got, want.opens)
			}
		})
	}
}

// TestTheOrderingIsReadAndNotAssumed is the milestone's criterion, and it needs
// both directions to mean anything. One fixture proving a deny wins would pass
// just as well if this mapper ignored priority and let every deny win; the pair
// is what shows the number was read.
func TestTheOrderingIsReadAndNotAssumed(t *testing.T) {
	below := securityGroup(t, "nsg-denied-below").Network
	above := securityGroup(t, "nsg-deny-above").Network

	if below.PublicIngress.Get() {
		t.Error("a deny at a lower priority number did not take precedence")
	}
	if !above.PublicIngress.Get() {
		t.Error("a deny at a higher priority number took precedence, which is the ordering backwards")
	}

	// And the two fixtures differ in nothing but the two numbers, or the pair
	// proves something else.
	if len(below.PublicIngress.Sources) == 0 || len(above.PublicIngress.Sources) == 0 {
		t.Fatal("one of the pair cites nothing, so what it read cannot be compared")
	}
}

// TestADenyNarrowerByProtocolDoesNotSilentlyNarrowTheAnswer covers the one case
// this mapper approximates, and the approximation is upward: an allow on every
// protocol with a deny on one of them opens less than the range says, and the
// range says the wider thing with a recorded reason.
//
// Reporting the deny as covering the allow would hide a grant -- UDP and ICMP are
// still open -- and the remainder is not expressible, because a range carries one
// protocol and "every protocol except TCP" is not one.
func TestADenyNarrowerByProtocolDoesNotSilentlyNarrowTheAnswer(t *testing.T) {
	capabilities := securityGroup(t, "nsg-deny-partial-protocol").Network

	if !capabilities.PublicIngress.IsKnown() || !capabilities.PublicIngress.Get() {
		t.Fatal("a deny on one protocol hid a grant on the others")
	}
	if got := rendered(capabilities.OpenToAnyAddress); got != "every/0-65535" {
		t.Fatalf("opens %q, want the wider range the model can express", got)
	}
	var said bool
	for _, control := range capabilities.Unresolved {
		if strings.Contains(control.Reason, "narrower") || strings.Contains(control.Reason, "deny") {
			said = true
		}
	}
	if !said {
		t.Fatal("the approximation is not reported, so a reader reads the range as exact")
	}
}

// TestEveryFactNamesTheAttributeItCameFrom is the milestone's criterion made
// mechanical for this cloud.
func TestEveryFactNamesTheAttributeItCameFrom(t *testing.T) {
	for _, fixture := range []string{"nsg-public-inline", "nsg-separate-open", "nsg-closed-inline"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := securityGroup(t, fixture).Network

			if len(capabilities.PublicIngress.Sources) == 0 {
				t.Fatal("the deciding fact cites nothing")
			}
			for _, source := range capabilities.PublicIngress.Sources {
				if source.ResourceAddress == "" || source.AttributePath == "" {
					t.Fatalf("a source names no attribute: %+v", source)
				}
				if source.Cloud != model.CloudAzure {
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

// TestTheRuleResourceDefersToItsGroup covers the control resource of this cloud.
func TestTheRuleResourceDefersToItsGroup(t *testing.T) {
	graph := normalize(t, "nsg-separate-open")

	rule, ok := graph.At("azurerm_network_security_rule.open")
	if !ok {
		t.Fatal("the rule resource is not in the graph")
	}
	if !rule.Interpreted || rule.Family != model.FamilyNetwork {
		t.Fatalf("interpreted = %v, family = %q", rule.Interpreted, rule.Family)
	}
	if rule.Network != nil {
		t.Error("the rule resource carries capabilities of its own")
	}
	if len(rule.DefersTo) != 1 || rule.DefersTo[0] != "azurerm_network_security_group.web" {
		t.Errorf("defers to %v, want the group", rule.DefersTo)
	}
}

// TestObjectStorageIsUntouched keeps the two families apart in this mapper too.
func TestObjectStorageIsUntouched(t *testing.T) {
	graph := normalize(t, "public-container")

	found, ok := graph.At("azurerm_storage_container.assets")
	if !ok {
		t.Skip("this fixture has no container to compare against")
	}
	if found.Family != model.FamilyObjectStorage || found.Network != nil {
		t.Fatalf("family = %q, network = %v", found.Family, found.Network)
	}
}

// TestAProtocolThisBuildDoesNotInterpretStaysUnrecognized covers the two real
// protocols this provider accepts and this build does not read: Esp and Ah.
//
// They carry no ports, which ICMP also does not, and folding them into ICMP
// would make a report say a set permits ping when it permits IPsec. The rule
// treats both the same way -- a protocol a port list cannot describe needs a
// human -- so nothing downstream changes, and that is exactly why the mapper has
// to be the thing that keeps them apart.
func TestAProtocolThisBuildDoesNotInterpretStaysUnrecognized(t *testing.T) {
	capabilities := securityGroup(t, "nsg-esp").Network

	if !capabilities.PublicIngress.IsKnown() || !capabilities.PublicIngress.Get() {
		t.Fatal("a rule opening Esp to any address was not read as a grant")
	}
	if len(capabilities.OpenToAnyAddress) != 1 {
		t.Fatalf("opens %+v, want one range", capabilities.OpenToAnyAddress)
	}
	open := capabilities.OpenToAnyAddress[0]
	if open.Protocol != model.ProtocolUnrecognized {
		t.Fatalf("protocol = %q, want it unrecognized rather than folded into another", open.Protocol)
	}
	if open.Protocol.HasPorts() {
		t.Fatal("a protocol this build does not interpret claims to have ports")
	}
}
