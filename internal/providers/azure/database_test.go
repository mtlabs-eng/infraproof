package azure_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/azure"
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
		// rule in this cloud mean the whole internet -- so the arithmetic says
		// one address, and the admission stays open because closure on this
		// cloud is never provable.
		"sql-azure-services": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactUnknown, false, 1433,
			"one address by arithmetic, and a rule elsewhere could still admit everything"},
		"sql-one-office": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactUnknown, false, 1433,
			"eleven addresses, and the rules are separate resources so the set cannot be complete"},
		// Two ranges that are each narrow and together are everything, which is
		// the arithmetic this grammar needed.
		"sql-split-halves": {"azurerm_mssql_server.db",
			model.FactKnown, true, model.FactKnown, true, 1433,
			"the union of the two halves is every address"},
		"sql-no-endpoint": {"azurerm_mssql_server.db",
			model.FactKnown, false, model.FactKnown, true, 1433,
			"a rule admitting every address still proves the grant half; it reaches no endpoint"},
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
			if found.Removed {
				// Every case in this table is a create. Reporting one as removed
				// would make the rule skip it, which is silence on exactly the
				// change worth reporting.
				t.Fatal("a database being created is reported as removed")
			}
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

// TestClosureIsNeverProvenFromRulesThatLiveElsewhere covers a contradiction two
// committed fixtures had with each other.
//
// Azure's database firewall rules are *always* separate resources -- there is no
// inline form -- so a plan never holds the whole set. Zero rules in the plan gave
// a required UNKNOWN saying as much; one benign rule gave PASS, while the same
// build still reported that "a rule declared outside this plan could admit
// more". Nothing about what lies outside the plan differed between the two.
//
// PRODUCT.md states the rule for the whole product: a set whose rules live in
// separate resources is UNKNOWN rather than closed. The AWS network mapper
// refuses closure the moment any rule is a separate resource, which is Azure's
// permanent condition. This cloud now answers the same way: a grant is provable
// from one rule, and closure is not provable at all.
func TestClosureIsNeverProvenFromRulesThatLiveElsewhere(t *testing.T) {
	for _, fixture := range []string{"sql-no-rules", "sql-one-office", "sql-azure-services"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := databaseAt(t, fixture, "azurerm_mssql_server.db").Database

			if capabilities.AdmitsAnyAddress.IsKnown() {
				t.Fatalf("closure was proven from a set that cannot be complete: admits = %v",
					capabilities.AdmitsAnyAddress.Get())
			}
			var said bool
			for _, control := range capabilities.Unresolved {
				if control.CheckID == "AZURE_DATABASE_FIREWALL_RULES_INCOMPLETE" {
					said = true
				}
			}
			if !said {
				t.Error("nothing says the rule set cannot be complete")
			}
		})
	}

	// And a grant is still provable from one rule, which is the half of the
	// asymmetry that must not move.
	for _, fixture := range []string{"sql-reachable", "sql-split-halves", "pg-reachable"} {
		t.Run(fixture, func(t *testing.T) {
			var capabilities *model.DatabaseCapabilities
			if fixture == "pg-reachable" {
				capabilities = databaseAt(t, fixture, "azurerm_postgresql_flexible_server.db").Database
			} else {
				capabilities = databaseAt(t, fixture, "azurerm_mssql_server.db").Database
			}
			if !capabilities.AdmitsAnyAddress.IsKnown() || !capabilities.AdmitsAnyAddress.Get() {
				t.Fatalf("a rule admitting every address stopped proving the grant: %v",
					capabilities.AdmitsAnyAddress.State)
			}
		})
	}
}

// TestARuleBeingRemovedIsNotARuleThisBuildCannotRead covers a plan whose whole
// purpose is to close the hole.
//
// A rule being destroyed has `after: null`, so its start and end addresses are
// absent -- which read as a range this build could not read, and reopened the
// question with a sentence saying the range was unreadable. It was perfectly
// readable in `before`; it is going away. The AWS network mapper filters
// removals for this reason.
func TestARuleBeingRemovedIsNotARuleThisBuildCannotRead(t *testing.T) {
	capabilities := databaseAt(t, "sql-rule-being-removed", "azurerm_mssql_server.db").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_DATABASE_FIREWALL_RANGE_UNREADABLE" {
			t.Errorf("a rule being destroyed is reported as one whose range could not be read: %q",
				control.Reason)
		}
	}
}

// TestTheAzureServicesRuleIsReportedForWhatItIs covers the one rule the milestone
// singles out as not meaning what it literally says.
//
// `0.0.0.0`-`0.0.0.0` is one address by the arithmetic, which is right: it is not
// `0.0.0.0/0`. In Azure it means "any Azure-hosted address", which is anyone who
// can rent a virtual machine. The arithmetic stays and the reader is told,
// because a verdict resting on a provider's convention needs to say so -- the
// same reason the inferred port is disclosed.
func TestTheAzureServicesRuleIsReportedForWhatItIs(t *testing.T) {
	capabilities := databaseAt(t, "sql-azure-services", "azurerm_mssql_server.db").Database

	var said bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_DATABASE_ALLOWS_AZURE_SERVICES" {
			said = true
			if !strings.Contains(control.Reason, "Azure") {
				t.Errorf("the reason does not say what the rule means: %q", control.Reason)
			}
		}
	}
	if !said {
		t.Error("the rule that admits every Azure-hosted address is reported as one address " +
			"and nothing says what it means")
	}
}

// TestADestroyedServerIsDistinguishedFromAReplacedOne pins the distinction the
// rule needs: a change that removes a server permits nothing through it, and a
// replacement creates one whose reachability is the verdict.
//
// This provider cannot be planned offline -- it acquires an AAD token before it
// finishes building -- so these two fixtures are shaped, like the rest of this
// cloud's, from the authoritative schema. What is *not* guessed is the action
// grammar they turn on: `["delete"]` with `after` null for a destroy and
// `["delete","create"]` with a full `after` for a replacement are Terraform core
// rather than provider behaviour, and both were measured on real `terraform
// show -json` output for AWS and GCP, where the plan could be produced.
func TestADestroyedServerIsDistinguishedFromAReplacedOne(t *testing.T) {
	cases := map[string]struct {
		fixture string
		removed bool
	}{
		"a destroy-only change": {"sql-server-destroyed", true},
		"a replacement":         {"sql-server-replaced", false},
	}

	for label, want := range cases {
		t.Run(label, func(t *testing.T) {
			found := databaseAt(t, want.fixture, "azurerm_mssql_server.db")
			if found.Database == nil {
				t.Fatalf("%s produced no database capabilities, so the rule never "+
					"sees it and coverage reports it unjudged", label)
			}
			if found.Removed != want.removed {
				t.Fatalf("Removed = %v, want %v", found.Removed, want.removed)
			}
		})
	}
}

// TestTheAzureServicesRuleJoinsTheUnionItBelongsTo is the arithmetic criterion 7
// claims and did not have.
//
// The `0.0.0.0`-`0.0.0.0` rule really is one address by the arithmetic, and
// saying so is right: it is not `0.0.0.0/0`. But it was recorded as a disclosure
// and then skipped, so its one address never joined the union the cover sweep
// runs over. Removing a rule from the set makes the set smaller than what it
// admits, and a sentinel beside `0.0.0.1`-`255.255.255.255` -- which together
// admit every IPv4 address -- came out as no finding at all. Measured: exit 0
// under `unspecified`, against `sql-split-halves`, which the same arithmetic
// BLOCKs.
//
// A disclosure is not a subtraction. The reader still has to be told that this
// build reads the sentinel as one address while Azure admits every Azure-hosted
// machine through it, which is the reason the control stays.
func TestTheAzureServicesRuleJoinsTheUnionItBelongsTo(t *testing.T) {
	found := databaseAt(t, "sql-services-plus-rest", "azurerm_mssql_server.db")
	if found.Database == nil {
		t.Fatal("the mapper produced no database capabilities")
	}
	capabilities := *found.Database

	if !capabilities.AdmitsAnyAddress.IsKnown() || !capabilities.AdmitsAnyAddress.Get() {
		t.Fatalf("admits any address = %v, want a known true: 0.0.0.0-0.0.0.0 and "+
			"0.0.0.1-255.255.255.255 are every IPv4 address between them",
			capabilities.AdmitsAnyAddress)
	}

	var disclosed bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AZURE_DATABASE_ALLOWS_AZURE_SERVICES" {
			disclosed = true
		}
	}
	if !disclosed {
		t.Fatal("the sentinel joined the union but the reader is no longer told " +
			"this build reads it as one address")
	}
}

// TestAnUncorrelatedRuleIsNotCalledAbsent holds a requirement CLAUDE.md states
// about every finding: it carries observed facts.
//
// When the correlator cannot place a rule -- a server under `count` named as
// `db[count.index]`, so the reference names no instance -- the server's related
// set is empty, and the reason said "none of them is in this plan" about a rule
// the plan contains and that admits every address. The verdict was right, because
// closure is never provable on this cloud, but the sentence explaining it was the
// opposite of the fact.
//
// The two causes are different things to go and fix: a rule declared in another
// module is somewhere else, and a rule the plan holds but nobody could attach is
// right here and needs its instance named outright.
func TestAnUncorrelatedRuleIsNotCalledAbsent(t *testing.T) {
	const address = "azurerm_mssql_server.db[0]"

	found := databaseAt(t, "sql-server-repeated", address)
	if found.Database == nil {
		t.Fatal("the mapper produced no database capabilities")
	}
	if found.Database.AdmitsAnyAddress.IsKnown() {
		t.Fatalf("admits any address = %v, want undetermined: a rule nobody could "+
			"attach could be the one that admits everything",
			found.Database.AdmitsAnyAddress)
	}

	var said string
	for _, control := range found.Database.Unresolved {
		if control.CheckID == "AZURE_DATABASE_FIREWALL_RULES_INCOMPLETE" {
			said = control.Reason
		}
	}
	if said == "" {
		t.Fatal("the admission is undetermined and nothing names what would settle it")
	}
	if strings.Contains(said, "none of them is in") {
		t.Fatalf("the reason says the plan holds no rule, and it holds one that "+
			"admits every address: %q", said)
	}
	if !strings.Contains(said, "This plan holds a firewall rule") {
		t.Fatalf("the reason does not say the rule is here and could not be "+
			"attached, which is the thing to go and fix: %q", said)
	}
}

// TestARuleBeingReplacedIsStillARule is the distinction `sql-rule-being-removed`
// does not carry, and the one nothing defended.
//
// A rule being destroyed is skipped, because its addresses are absent from
// `after` for a reason that is not unreadability and a plan closing a hole should
// not report the hole as reopened. A rule being *replaced* is destroyed and
// created, and what it creates is what the verdict is about -- its `after` is a
// full object stating the addresses it will admit.
//
// Measured: dropping the replace half of that filter left the suite green and
// turned a server whose firewall rule is being replaced onto `0.0.0.0` through
// `255.255.255.255` from BLOCK into UNKNOWN. The rule the change is putting in
// place admits the whole internet.
func TestARuleBeingReplacedIsStillARule(t *testing.T) {
	found := databaseAt(t, "sql-rule-being-replaced", "azurerm_mssql_server.db")
	if found.Database == nil {
		t.Fatal("the mapper produced no database capabilities")
	}
	if !found.Database.AdmitsAnyAddress.IsKnown() || !found.Database.AdmitsAnyAddress.Get() {
		t.Fatalf("admits any address = %v, want a known true: the rule being put "+
			"in place spans the whole of IPv4", found.Database.AdmitsAnyAddress)
	}
}

// TestAServerTypeThisBuildDoesNotNameHasNoPort guards the refusal portOf makes.
//
// The port comes from the resource type on this cloud, and the switch used to
// answer the MSSQL port by default -- so a third server type added to Interprets
// without touching portOf would have inherited 1433 in silence. A wrong port
// makes a reachable database read as closed, which is the direction that hides a
// grant. `ruleTypeFor` next door already refuses the same way.
//
// Unreachable through the registry today, because Interprets names two types and
// portOf names the same two. The guard is for the next type, and this test is
// what makes the two lists stay in step.
func TestAServerTypeThisBuildDoesNotNameHasNoPort(t *testing.T) {
	for _, serverType := range []string{"azurerm_mysql_flexible_server", "azurerm_mssql_managed_instance"} {
		if (azure.Mapper{}).Interprets(serverType) {
			t.Fatalf("%s is interpreted now, so portOf must name it and this test "+
				"must take a type that is still outside the set", serverType)
		}
	}

	found := databaseAt(t, "sql-reachable", "azurerm_mssql_server.db")
	if found.Database == nil {
		t.Fatal("the mapper produced no database capabilities")
	}
	if !found.Database.Port.IsKnown() || found.Database.Port.Get() != 1433 {
		t.Fatalf("port = %v, want 1433: a type this build does name reads its own "+
			"port", found.Database.Port)
	}
	if found.Database.PortInferred {
		t.Fatal("the engine is the resource type on this cloud, so the port is " +
			"certain rather than read from a table of defaults")
	}
}
