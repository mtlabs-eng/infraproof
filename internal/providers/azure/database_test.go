package azure_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// databaseAt returns the normalized database of a fixture.
func databaseAt(t *testing.T, fixture, address string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At(address)
	if !ok {
		t.Fatalf("fixture %s has no resource at %s", fixture, address)
	}
	return found
}

// TestReachabilityOnThisCloud is the mapper's job, and the half of it this cloud
// answers itself.
//
// Unlike AWS, the allow list here belongs to the database's own control
// resources -- firewall rules joined to the server -- so the mapper settles the
// admission rather than naming another subject's verdict. And unlike either of
// the others, the rules are written as a start and an end address, so a range is
// the only grammar in play.
//
// These fixtures are hand-authored from the authoritative provider schema, not
// from a plan: the azurerm provider acquires an AAD token before it finishes
// building, so it cannot be planned offline. What that costs is recorded beside
// the fixtures.
func TestReachabilityOnThisCloud(t *testing.T) {
	cases := map[string]struct {
		address  string
		endpoint model.FactState
		public   bool
		admits   model.FactState
		open     bool
		port     int
		why      string
	}{
		"sql-reachable": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactKnown, true, 1433,
			"a public endpoint and a rule admitting every address"},
		// The rule Azure writes to mean "services inside Azure". Reading its
		// start address as a zero-bit prefix would make the most common benign
		// rule in this cloud mean the whole internet.
		"sql-azure-services": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactKnown, false, 1433,
			"0.0.0.0 to 0.0.0.0 is one address, not every address"},
		"sql-one-office": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactKnown, false, 1433,
			"a range that is eleven addresses"},
		// Two ranges that are each narrow and together are everything, which is
		// the arithmetic this grammar needed.
		"sql-split-halves": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactKnown, true, 1433,
			"the union of the two halves is every address"},
		"sql-no-endpoint": {"azurerm_mssql_server.db",
			model.FactKnown, false, model.FactKnown, true, 1433,
			"the allow list still reads; it just reaches no endpoint"},
		// The rules are separate resources, so a plan holding none of them holds
		// none of the set: a grant is provable from part of a set and closure is
		// not.
		"sql-no-rules": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactUnknown, false, 1433,
			"no rule in the plan cannot show that no rule admits everything"},
		// The switch stated nowhere. This build cannot measure what the provider
		// defaults it to, so it does not guess.
		"sql-switch-absent": {"azurerm_mssql_server.db",
			model.FactUnknown, false, model.FactKnown, true, 1433,
			"a default this build cannot measure is not a default it may apply"},
		"pg-reachable": {"azurerm_postgresql_flexible_server.db",
			model.FactKnown, true, model.FactKnown, true, 5432,
			"the other type in scope, and its own port"},
		// A range nobody could read could be the one that admits everything.
		"sql-unreadable-range": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactUnknown, false, 1433,
			"an unreadable rule leaves the set open"},
	}

	for fixture, want := range cases {
		t.Run(fixture, func(t *testing.T) {
			found := databaseAt(t, fixture, want.address)
			if found.Family != model.FamilyDatabase {
				t.Fatalf("family = %q, want %q", found.Family, model.FamilyDatabase)
			}
			if found.Database == nil {
				t.Fatal("the mapper produced no database capabilities")
			}
			capabilities := *found.Database

			if got := capabilities.PublicEndpoint.State; got != want.endpoint {
				t.Fatalf("endpoint state = %q, want %q: %s", got, want.endpoint, want.why)
			}
			if want.endpoint == model.FactKnown && capabilities.PublicEndpoint.Get() != want.public {
				t.Fatalf("public endpoint = %v, want %v: %s",
					capabilities.PublicEndpoint.Get(), want.public, want.why)
			}
			if got := capabilities.AdmitsAnyAddress.State; got != want.admits {
				t.Fatalf("admission state = %q, want %q: %s", got, want.admits, want.why)
			}
			if want.admits == model.FactKnown && capabilities.AdmitsAnyAddress.Get() != want.open {
				t.Fatalf("admits every address = %v, want %v: %s",
					capabilities.AdmitsAnyAddress.Get(), want.open, want.why)
			}
			if !capabilities.Port.IsKnown() || capabilities.Port.Get() != want.port {
				t.Errorf("port = %v, want %d; the engine is the resource type on this cloud",
					capabilities.Port, want.port)
			}
			// The allow list belongs to this subject's own controls, so nothing
			// is deferred to another subject.
			if len(capabilities.GatedBy) != 0 {
				t.Errorf("gated by %v, and the rules are this server's own controls",
					capabilities.GatedBy)
			}
		})
	}
}

// TestAFirewallRuleDefersToItsServer covers the control resource. Its meaning
// belongs to the server it names, and the deferral is recorded so coverage can
// check that something answered for it.
func TestAFirewallRuleDefersToItsServer(t *testing.T) {
	rule, ok := normalize(t, "sql-reachable").At("azurerm_mssql_firewall_rule.open")
	if !ok {
		t.Fatal("the rule resource is not in the graph")
	}

	if !rule.Interpreted {
		t.Error("a firewall rule reads as a resource nothing understood")
	}
	if rule.Family != model.FamilyDatabase {
		t.Errorf("family = %q, want %q", rule.Family, model.FamilyDatabase)
	}
	if rule.Database != nil {
		t.Error("a rule carries a reachability verdict of its own")
	}
	if len(rule.DefersTo) != 1 || rule.DefersTo[0] != "azurerm_mssql_server.db" {
		t.Errorf("defers to %v, want the server", rule.DefersTo)
	}
}

// TestAnUnsettledAllowListSaysWhyItCannotBeSettled covers what a reader does
// next, for the two shapes that leave it open.
func TestAnUnsettledAllowListSaysWhyItCannotBeSettled(t *testing.T) {
	for _, fixture := range []string{"sql-no-rules", "sql-unreadable-range"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := databaseAt(t, fixture, "azurerm_mssql_server.db").Database

			if len(capabilities.Unresolved) == 0 {
				t.Fatal("an unsettled allow list reports no missing control")
			}
			for _, control := range capabilities.Unresolved {
				if control.CheckID == "" || control.Reason == "" {
					t.Fatalf("a missing control says nothing: %+v", control)
				}
				if strings.Contains(control.Reason, "azurerm_mssql_server") {
					t.Fatalf("the reason interpolates a plan value: %q", control.Reason)
				}
			}
		})
	}
}

// TestTheOtherTwoFamiliesAreUntouched is acceptance criterion 5 in this package.
func TestTheOtherTwoFamiliesAreUntouched(t *testing.T) {
	group := securityGroup(t, "nsg-public-inline")
	if group.Family != model.FamilyNetwork || group.Database != nil {
		t.Errorf("a network security group is %q with database = %v", group.Family, group.Database)
	}
	if group.Network == nil || !group.Network.PublicIngress.Get() {
		t.Error("the network family's verdict changed")
	}
	container, ok := normalize(t, "public-container").At("azurerm_storage_container.assets")
	if ok && (container.Family != model.FamilyObjectStorage || container.Database != nil) {
		t.Errorf("a container is %q with database = %v", container.Family, container.Database)
	}
}

// TestOnlyAFirewallRuleReachesTheServersRelatedSet pins the correlator's
// discipline, which is what keeps this mapper from having to decide it.
//
// A server references more than its firewall rules -- its resource group, at the
// least. None of those reach the related set, because the only binding pointing
// at a server is from its own rule type, and an interpreted resource's edges are
// its declared bindings and nothing else.
//
// The mapper still checks the type, as a guard against a binding added later.
// This test is about the reason that guard is unreachable today, so that if the
// reason stops being true something fails here rather than inside the mapper.
func TestOnlyAFirewallRuleReachesTheServersRelatedSet(t *testing.T) {
	capabilities := databaseAt(t, "sql-with-resource-group", "azurerm_mssql_server.db").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if !capabilities.AdmitsAnyAddress.IsKnown() || !capabilities.AdmitsAnyAddress.Get() {
		t.Fatalf("a resource group was read as a firewall rule: %v",
			capabilities.AdmitsAnyAddress.State)
	}
	// And no spurious gap is reported for it. The verdict survives reading a
	// resource group as a rule, because another rule proves the grant -- so the
	// control is the only place the mistake shows, and the only place a test can
	// see it.
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_DATABASE_FIREWALL_RANGE_UNREADABLE" {
			t.Errorf("a resource group is reported as a rule whose range could not be read: %q",
				control.Reason)
		}
	}
}

// TestAGrantStandsBesideARuleThisBuildCannotRead covers the asymmetry this family
// shares with the network one, in the one shape that separates it from closure.
//
// A rule admitting every address settles the question whatever else is missing: a
// grant is provable from part of a set. An unreadable rule beside it cannot take
// that away -- it could only admit more. The reverse is what cannot be proven,
// and a plan holding only unreadable rules stays open.
func TestAGrantStandsBesideARuleThisBuildCannotRead(t *testing.T) {
	capabilities := databaseAt(t, "sql-open-beside-unreadable", "azurerm_mssql_server.db").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if !capabilities.AdmitsAnyAddress.IsKnown() || !capabilities.AdmitsAnyAddress.Get() {
		t.Fatalf("an unreadable rule took away a grant another rule proved: %v",
			capabilities.AdmitsAnyAddress.State)
	}
	// And the unreadable rule is still reported, because it bounds how far the
	// evidence reaches even where it cannot change the verdict.
	var said bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_DATABASE_FIREWALL_RANGE_UNREADABLE" {
			said = true
		}
	}
	if !said {
		t.Error("the unreadable rule is not reported, so the evidence is unbounded")
	}
}

// TestAServersRelatedSetHoldsOnlyItsOwnRules is the assertion the test above
// rests on, made directly against the graph rather than through a verdict.
//
// A verdict can survive reading the wrong resource as a rule -- another rule may
// prove the grant anyway -- so the verdict is the wrong place to check this. The
// edge set is the right place.
func TestAServersRelatedSetHoldsOnlyItsOwnRules(t *testing.T) {
	graph := normalize(t, "sql-with-resource-group")

	// The resource group is in the plan and is not interpreted, so it is its own
	// resource and reaches no server.
	if group, ok := graph.At("azurerm_resource_group.rg"); !ok {
		t.Fatal("the resource group is not in the graph")
	} else if group.Interpreted {
		t.Error("a resource group is claimed by a mapper")
	}

	// And the rule defers to the server, which is the only edge that exists.
	rule, ok := graph.At("azurerm_mssql_firewall_rule.open")
	if !ok {
		t.Fatal("the rule is not in the graph")
	}
	if len(rule.DefersTo) != 1 || rule.DefersTo[0] != "azurerm_mssql_server.db" {
		t.Errorf("the rule defers to %v, want the server alone", rule.DefersTo)
	}
	server, ok := graph.At("azurerm_mssql_server.db")
	if !ok || server.Database == nil {
		t.Fatal("the server is not in the graph")
	}
	if !server.Database.AdmitsAnyAddress.Get() {
		t.Error("the rule did not reach the server, so the binding is not working")
	}
}
