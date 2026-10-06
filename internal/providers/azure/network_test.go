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
		// A deny that reaches only private addresses cannot cancel a grant open
		// to the world. This mapper was right about it and nothing proved it,
		// which is how its GCP twin shipped wrong.
		"nsg-deny-private-source": {model.FactKnown, true, "tcp/22"},
		"nsg-deny-above":          {model.FactKnown, true, "tcp/22"},
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
		// Esp and Ah are real protocols this build cannot name. It used to
		// report them as a grant on an unnameable protocol, which made two
		// different protocols compare equal; they are undetermined now, as AWS
		// already reported them.
		"nsg-esp": {model.FactUnknown, false, ""},
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
func TestAProtocolThisBuildCannotNameIsUndetermined(t *testing.T) {
	capabilities := securityGroup(t, "nsg-esp").Network

	if capabilities.PublicIngress.IsKnown() {
		t.Fatalf("a protocol this build cannot name was settled as %v", capabilities.PublicIngress.Get())
	}
	if len(capabilities.OpenToAnyAddress) != 0 {
		t.Fatalf("opens %+v, want nothing: a range whose protocol has no name renders as an empty string",
			capabilities.OpenToAnyAddress)
	}
}

// TestASourceSplitIntoHalvesIsEveryAddress covers address arithmetic, which this
// mapper did not do.
//
// What a rule admits is the union of its source entries. Asking one entry at a
// time, `0.0.0.0/1, 128.0.0.0/1` is two prefixes that each constrain a bit, so
// each read as narrower than any address and the set read as proven closed --
// Known(false), meaning the plan proves nothing is open, on a rule admitting
// every address in IPv4.
//
// A split of the space is not an exotic spelling. It is what a pair of halves
// looks like, and the answer must not depend on how the author chose to write
// the same set.
func TestASourceSplitIntoHalvesIsEveryAddress(t *testing.T) {
	capabilities := securityGroup(t, "nsg-split-source").Network

	if !capabilities.PublicIngress.IsKnown() {
		t.Fatalf("a readable pair of prefixes was not settled: %v", capabilities.PublicIngress.State)
	}
	if !capabilities.PublicIngress.Get() {
		t.Fatal("a source covering every IPv4 address was read as narrower than any address")
	}
	if got := rendered(capabilities.OpenToAnyAddress); got != "tcp/22" {
		t.Fatalf("opens %q, want tcp/22", got)
	}
}

// TestADenyNarrowedToOneDestinationCannotProvePrevention covers the half of an
// Azure rule this mapper never read.
//
// A rule has a destination as well as a source. For an allow, a narrow
// destination narrows what is reachable rather than whether ingress is permitted,
// which the milestone says and which is sound. For a deny it inverts: ignoring
// the destination makes a deny scoped to one host look like a deny covering the
// whole subnet, and the grant it cancels is one that reaches every other address
// in it.
//
// Measured before the fix: allow Tcp/22 from any address at priority 200, deny
// everything from any address to 10.0.0.5 at priority 100, reported Known(false)
// -- a deterministic proof that nothing is open, on a port reachable from the
// internet at every address but one.
func TestADenyNarrowedToOneDestinationCannotProvePrevention(t *testing.T) {
	for _, fixture := range []string{"nsg-deny-one-host", "nsg-deny-destination-list"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := securityGroup(t, fixture).Network

			if !capabilities.PublicIngress.IsKnown() || !capabilities.PublicIngress.Get() {
				t.Fatalf("a deny reaching one host cancelled a grant reaching the subnet: %v",
					capabilities.PublicIngress.State)
			}
			if got := rendered(capabilities.OpenToAnyAddress); got != "tcp/22" {
				t.Fatalf("opens %q, want tcp/22", got)
			}
			var said bool
			for _, control := range capabilities.Unresolved {
				if strings.Contains(control.Reason, "destination") {
					said = true
				}
			}
			if !said {
				t.Error("the narrowing is not reported, so a reader cannot tell why the grant stands")
			}
		})
	}

	// The other direction, or the fix is just "no deny ever covers anything": a
	// deny whose destination is every address does cover, whichever of the two
	// legal spellings it uses.
	for _, fixture := range []string{"nsg-denied-below", "nsg-deny-destination-any"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := securityGroup(t, fixture).Network

			if !capabilities.PublicIngress.IsKnown() {
				t.Fatalf("a deny reaching every address was not read: %v", capabilities.PublicIngress.State)
			}
			if capabilities.PublicIngress.Get() {
				t.Fatal("a deny reaching every destination did not cover the allow")
			}
		})
	}
}

// TestTheTwoTagsThatAreNotTheInternetAreRead covers Azure's most common benign
// rule.
//
// The provider documents three service tags for this field, and only Internet
// means every public address. VirtualNetwork is the address space of the virtual
// network and AzureLoadBalancer is the platform's probe; neither is reachable
// from the internet. Reading them as tags this build does not know turned an
// otherwise provable set into UNKNOWN -- safe, and a false unknown on the rule
// most Azure deployments carry.
//
// A tag nobody here has heard of stays unreadable, because Azure adds them and
// one of them could be every address.
func TestTheTwoTagsThatAreNotTheInternetAreRead(t *testing.T) {
	for _, fixture := range []string{"nsg-virtual-network-tag", "nsg-load-balancer-tag"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := securityGroup(t, fixture).Network

			if !capabilities.PublicIngress.IsKnown() {
				t.Fatalf("a documented tag that is not the internet was read as unreadable: %v",
					capabilities.PublicIngress.State)
			}
			if capabilities.PublicIngress.Get() {
				t.Fatal("a tag that is not the internet was read as every address")
			}
		})
	}

	// And the two that must not move: Internet is every public address, and a
	// tag this build cannot name could be.
	if internet := securityGroup(t, "nsg-internet-tag").Network; !internet.PublicIngress.Get() {
		t.Error("the Internet tag stopped meaning every public address")
	}
	if unknown := securityGroup(t, "nsg-unknown-service-tag").Network; unknown.PublicIngress.IsKnown() {
		t.Error("a service tag this build does not know was settled")
	}
}

// TestAnInlineSetTheAuthorNeverWroteIsNotAnUnreadableSet covers the fixture shape
// this mapper had never seen.
//
// `security_rule` is Optional and Computed, so a group writing no inline rules has
// the attribute emitted as unknown rather than empty. Every hand-written fixture
// here spelled it `[]`. Reading the unknown as an unreadable rule set threw away
// a grant provable from a separate rule resource -- and the most common Azure
// pattern is exactly that: one NSG plus separate azurerm_network_security_rule
// resources.
func TestAnInlineSetTheAuthorNeverWroteIsNotAnUnreadableSet(t *testing.T) {
	open := securityGroup(t, "nsg-inline-unwritten").Network
	if !open.PublicIngress.IsKnown() || !open.PublicIngress.Get() {
		t.Fatalf("a grant stated by a separate rule was discarded as unreadable: %v",
			open.PublicIngress.State)
	}
	if got := rendered(open.OpenToAnyAddress); got != "tcp/22" {
		t.Fatalf("opens %q, want tcp/22", got)
	}

	// Closure is still not provable: the separate rules are only part of the set.
	closed := securityGroup(t, "nsg-inline-unwritten-closed").Network
	if closed.PublicIngress.IsKnown() {
		t.Fatalf("a set the plan holds only part of was settled as %v", closed.PublicIngress.Get())
	}
	var said bool
	for _, control := range closed.Unresolved {
		if control.CheckID == "AZURE_NSG_RULES_INCOMPLETE" {
			said = true
		}
	}
	if !said {
		t.Error("the incomplete set is not named, so the unknown has no explanation")
	}
}

// TestAGrantFromPartOfTheSetSaysWhatCouldStillOverrideIt covers the bound on the
// other branch.
//
// GCP attaches a deny-may-exist-elsewhere unknown to every firewall for exactly
// this risk. Azure said nothing on the grant branch: a group whose rules are
// separate resources and whose plan holds only an allow reported Known(true) with
// no mention that a deny at a lower priority could be declared elsewhere.
func TestAGrantFromPartOfTheSetSaysWhatCouldStillOverrideIt(t *testing.T) {
	capabilities := securityGroup(t, "nsg-separate-open").Network

	if !capabilities.PublicIngress.Get() {
		t.Fatal("the grant is gone, so this test is about something else now")
	}
	var said bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_NSG_RULES_INCOMPLETE" {
			said = true
		}
	}
	if !said {
		t.Error("a grant proven from part of a set does not say the rest of the set is not here")
	}
}

// TestADenyThatRemovesNothingIsNotAnApproximation covers the flag's absence,
// which nothing asserted.
//
// The approximation is real when a deny on one protocol sits below an allow on
// every protocol and their ports meet: the remainder is not expressible, so the
// range says the wider thing and the reason records it. When the ports are
// disjoint the deny removes nothing, the range is exact, and warning that it may
// be wider than reality is a warning about nothing -- which teaches a reader to
// ignore the one that matters.
func TestADenyThatRemovesNothingIsNotAnApproximation(t *testing.T) {
	capabilities := securityGroup(t, "nsg-deny-disjoint-protocol").Network

	if got := rendered(capabilities.OpenToAnyAddress); got != "every/443" {
		t.Fatalf("opens %q, want every/443", got)
	}
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_NSG_DENY_NARROWER_THAN_ALLOW" {
			t.Fatalf("an exact range is reported as an approximation: %q", control.Reason)
		}
	}

	// And the real approximation still reports, or this is just the flag
	// removed.
	real := securityGroup(t, "nsg-deny-partial-protocol").Network
	var said bool
	for _, control := range real.Unresolved {
		if control.CheckID == "AZURE_NSG_DENY_NARROWER_THAN_ALLOW" {
			said = true
		}
	}
	if !said {
		t.Error("the approximation that is real stopped being reported")
	}
}

// TestARuleBeingReplacedIsTheRuleThatWillExist is the same correction in this
// cloud. A replacement is spelled as a delete and a create together, so testing
// for a delete alone dropped a rule resource that will exist after apply.
//
// Here it under-reported: the dropped rule was the one stating the grant, so a
// port open to the internet came out as an unsettled set.
func TestARuleBeingReplacedIsTheRuleThatWillExist(t *testing.T) {
	capabilities := securityGroup(t, "nsg-rule-replaced").Network

	if !capabilities.PublicIngress.IsKnown() || !capabilities.PublicIngress.Get() {
		t.Fatalf("a rule being replaced was dropped, so its grant went unreported: %v",
			capabilities.PublicIngress.State)
	}
	if got := rendered(capabilities.OpenToAnyAddress); got != "tcp/22" {
		t.Fatalf("opens %q, want tcp/22", got)
	}
}

// TestASpellingThisBuildDoesNotRecognizeIsNotTheOpposite covers two fields where
// a reading failure fell to the quiet answer.
//
// `direction` was read as `read.inbound = EqualFold(text, "Inbound")`, so any
// other text -- a spelling the provider does not produce today, a value from a
// future API version -- was read as outbound, and an outbound rule says nothing
// about who can reach in. `access` had the same shape: anything that is not
// "Allow" was a deny, and a deny opens nothing. Both hide a grant.
//
// Neither mutation was caught, because every fixture uses the exact spelling the
// provider writes. A value this build cannot name is undetermined now, which is
// what it does for a protocol and an address.
func TestASpellingThisBuildDoesNotRecognizeIsNotTheOpposite(t *testing.T) {
	for _, fixture := range []string{"nsg-unreadable-direction", "nsg-unreadable-access"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := securityGroup(t, fixture).Network

			if capabilities.PublicIngress.IsKnown() {
				t.Fatalf("a value this build cannot name was settled as %v",
					capabilities.PublicIngress.Get())
			}
		})
	}

	// And the spellings that are real still read, in either case, because the
	// cure must not be refusing everything.
	if open := securityGroup(t, "nsg-public-inline").Network; !open.PublicIngress.Get() {
		t.Error("an Inbound Allow rule stopped being read")
	}
	if closed := securityGroup(t, "nsg-outbound-only").Network; closed.PublicIngress.Get() {
		t.Error("an Outbound rule was read as permitting ingress")
	}
}

// TestARuleStatingNoDestinationPortIsUnreadable covers the field the provider
// requires and this build must not read as a rule opening nothing. Reading it
// that way is the quiet answer again: a grant disappears rather than being
// reported as undetermined.
func TestARuleStatingNoDestinationPortIsUnreadable(t *testing.T) {
	capabilities := securityGroup(t, "nsg-no-destination-port").Network

	if capabilities.PublicIngress.IsKnown() {
		t.Fatalf("a rule with no destination port was settled as %v", capabilities.PublicIngress.Get())
	}
	if len(capabilities.OpenToAnyAddress) != 0 {
		t.Fatalf("it opens %v", capabilities.OpenToAnyAddress)
	}
}

// TestTheAsymmetryBetweenTheTwoSourceFieldsIsRead covers what the provider
// documents and this build has to respect: the singular prefix field accepts a
// service tag and the plural one does not.
//
// "Internet" in the plural field is not the tag; it is a string where an address
// belongs, so the rule is undetermined rather than open to the world. Accepting
// it there would be reading a grammar the provider does not have.
func TestTheAsymmetryBetweenTheTwoSourceFieldsIsRead(t *testing.T) {
	plural := securityGroup(t, "nsg-tag-in-plural").Network
	if plural.PublicIngress.IsKnown() {
		t.Fatalf("a service tag in the plural field was settled as %v", plural.PublicIngress.Get())
	}

	// The singular field does carry it, which is the half that must not move.
	if singular := securityGroup(t, "nsg-internet-tag").Network; !singular.PublicIngress.Get() {
		t.Error("the Internet tag stopped being read in the field that accepts it")
	}
}

// TestAnInlineSetWrittenAsEmptyIsAProvenClosure is the same statement in this
// cloud: `security_rule = []` writes the attribute and the plan carries the
// value, so the set is stated in full and it is empty.
func TestAnInlineSetWrittenAsEmptyIsAProvenClosure(t *testing.T) {
	capabilities := securityGroup(t, "nsg-explicitly-empty").Network

	if !capabilities.PublicIngress.IsKnown() {
		t.Fatalf("a rule set stated in full was not settled: %v", capabilities.PublicIngress.State)
	}
	if capabilities.PublicIngress.Get() {
		t.Fatal("an empty rule set was read as permitting ingress")
	}
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_NSG_RULES_INCOMPLETE" {
			t.Errorf("a set stated in full is reported incomplete: %q", control.Reason)
		}
	}
}

// TestADenyLimitedToOnePortCannotCoverAProtocolWithNoPorts covers the one place
// a deny was applied without its ports being looked at.
//
// A protocol with no ports has nothing to subtract, so the code took "the deny
// reaches this protocol" to mean "the deny reaches all of it" and dropped the
// grant whole. A deny written `protocol = "*"` with `destination_port_range =
// "80"` -- an ordinary rule -- therefore cancelled an ICMP-from-anywhere allow,
// and the set came out as a proven closure with no approximation reported.
//
// Azure requires a port range of `*` for ICMP, so a port-limited rule is not
// about ICMP at all. The grant stands and the answer is exact: there is nothing
// approximate about a deny that cannot reach the traffic.
func TestADenyLimitedToOnePortCannotCoverAProtocolWithNoPorts(t *testing.T) {
	capabilities := securityGroup(t, "nsg-icmp-deny-one-port").Network

	if !capabilities.PublicIngress.IsKnown() {
		t.Fatalf("the set was not settled: %v", capabilities.PublicIngress.State)
	}
	if !capabilities.PublicIngress.Get() {
		t.Fatal("a deny limited to port 80 cancelled a grant on a protocol that has no ports")
	}
	if got := rendered(capabilities.OpenToAnyAddress); got != "icmp" {
		t.Fatalf("opens %q, want icmp", got)
	}

	// The deny that does reach every port still covers it, or this is just every
	// deny disabled for port-less protocols.
	if covered := securityGroup(t, "nsg-icmp-denied").Network; covered.PublicIngress.Get() {
		t.Error("a deny reaching every port stopped covering a protocol with no ports")
	}
}
