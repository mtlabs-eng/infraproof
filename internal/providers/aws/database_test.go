package aws_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// database returns the normalized database of a fixture.
func database(t *testing.T, fixture, address string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At(address)
	if !ok {
		t.Fatalf("fixture %s has no resource at %s", fixture, address)
	}
	return found
}

// TestTheMapperAgreesWithARealPlanAboutDatabases is the authority for this
// family on this cloud, written before the mapper existed and from what AWS does rather than
// from what the mapper says.
//
// real-databases.json is genuine `terraform show -json` output: Terraform 1.14.0,
// hashicorp/aws v6, `terraform plan` only -- never applied, no cloud contacted,
// `skip_*` flags and placeholder strings, with the two placeholder credential
// arguments deleted from the provider block afterwards.
//
// Every expectation is the conjunction: a public endpoint and something admitting
// every address to it. The mapper answers the first half and names where the
// second half is; the rule resolves it.
func TestTheMapperAgreesWithARealPlanAboutDatabases(t *testing.T) {
	cases := map[string]struct {
		endpoint model.FactState
		public   bool
		gatedBy  []string
		port     int
		why      string
	}{
		// Written public, behind a group open to the world on the Postgres port.
		"reachable": {model.FactKnown, true, []string{"aws_security_group.postgres_open"}, 5432,
			"the switch is written and the group it names is in the plan"},
		// The shared-group shape: open to the world, but not on a database port.
		"shared_group": {model.FactKnown, true, []string{"aws_security_group.https_open"}, 5432,
			"the mapper names the group; whether 443 reaches 5432 is the rule's question"},
		"endpoint_closed_group": {model.FactKnown, true, []string{"aws_security_group.closed"}, 5432,
			"a group the network family will prove closed"},
		// Unwritten `publicly_accessible` on a plain instance: the provider
		// emits false, which is both its default and the safe answer.
		"private": {model.FactKnown, false, []string{"aws_security_group.postgres_open"}, 5432,
			"Optional and not Computed, so an unwritten switch is a determined false"},
		// No group written at all. AWS assigns the default VPC security group,
		// which is not in the plan, so there is nothing to name.
		"no_group": {model.FactKnown, true, nil, 5432,
			"the author named no group, so the allow list is not in the plan"},
		// An engine the port table cannot name leaves the port undetermined.
		"unnameable_engine": {model.FactKnown, true, []string{"aws_security_group.https_open"}, 0,
			"db2-se is a real engine whose port this build does not claim to know"},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			found := database(t, "real-databases", "aws_db_instance."+name)

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
			if got := strings.Join(capabilities.GatedBy, ","); got != strings.Join(want.gatedBy, ",") {
				t.Fatalf("gated by %q, want %q: %s", got, strings.Join(want.gatedBy, ","), want.why)
			}
			switch {
			case want.port == 0 && capabilities.Port.IsKnown():
				t.Fatalf("port = %d, want undetermined: %s", capabilities.Port.Get(), want.why)
			case want.port != 0 && !capabilities.Port.IsKnown():
				t.Fatalf("port is undetermined, want %d: %s", want.port, want.why)
			case want.port != 0 && capabilities.Port.Get() != want.port:
				t.Fatalf("port = %d, want %d", capabilities.Port.Get(), want.port)
			}
			// The mapper never answers the admission itself on this cloud: the
			// allow list is a security group, which is a subject the network
			// family judges in its own right.
			if capabilities.AdmitsAnyAddress.IsKnown() {
				t.Errorf("the mapper settled the allow list itself, which belongs to the group")
			}
		})
	}
}

// TestAnAuroraInstanceCarriesTheSwitchAndTheClusterCarriesTheAllowList covers the
// shape the design did not have and a real plan showed.
//
// The schema splits the conjunction across two resources:
// aws_rds_cluster_instance has `publicly_accessible` and no
// `vpc_security_group_ids`, and aws_rds_cluster has the reverse. So the mapper
// has to walk instance to cluster to security group -- two hops, where a
// subject's `related` carries one.
func TestAnAuroraInstanceCarriesTheSwitchAndTheClusterCarriesTheAllowList(t *testing.T) {
	found := database(t, "real-databases", "aws_rds_cluster_instance.aurora")

	if found.Family != model.FamilyDatabase || found.Database == nil {
		t.Fatalf("family = %q, database = %v", found.Family, found.Database)
	}
	capabilities := *found.Database

	if !capabilities.PublicEndpoint.IsKnown() || !capabilities.PublicEndpoint.Get() {
		t.Fatalf("the instance's own switch was not read: %v", capabilities.PublicEndpoint.State)
	}
	if got := strings.Join(capabilities.GatedBy, ","); got != "aws_security_group.postgres_open" {
		t.Fatalf("gated by %q; the allow list is on the cluster and takes two hops to reach", got)
	}
	if !capabilities.Port.IsKnown() || capabilities.Port.Get() != 5432 {
		t.Errorf("port = %v, want 5432 from aurora-postgresql", capabilities.Port)
	}
}

// TestAnAuroraClusterDefersToItsInstances covers the resource that carries half
// the question and no verdict of its own.
//
// A cluster has no `publicly_accessible` at all, so it cannot be reachable in its
// own right. It is interpreted -- otherwise it reads as a resource nothing
// understood -- and it defers, so coverage can check that something answered for
// it rather than believe it.
func TestAnAuroraClusterDefersToItsInstances(t *testing.T) {
	found := database(t, "real-databases", "aws_rds_cluster.aurora")

	if !found.Interpreted {
		t.Error("an Aurora cluster reads as a resource nothing understood")
	}
	if found.Family != model.FamilyDatabase {
		t.Errorf("family = %q, want %q", found.Family, model.FamilyDatabase)
	}
	if found.Database != nil {
		t.Error("a cluster carries a reachability verdict of its own, and it has no endpoint switch")
	}
	if len(found.DefersTo) != 1 || found.DefersTo[0] != "aws_rds_cluster_instance.aurora" {
		t.Errorf("defers to %v, want the instance that carries the switch", found.DefersTo)
	}
}

// TestObjectStorageAndNetworkAreUntouched is acceptance criterion 5 made
// mechanical in this package: adding a third family must not disturb the two
// that were here.
func TestObjectStorageAndNetworkAreUntouched(t *testing.T) {
	if assets := bucket(t, "public-acl"); assets.Family != model.FamilyObjectStorage ||
		assets.Database != nil {
		t.Errorf("a bucket is %q with database = %v", assets.Family, assets.Database)
	}
	group := securityGroup(t, "sg-public-inline")
	if group.Family != model.FamilyNetwork || group.Database != nil {
		t.Errorf("a security group is %q with database = %v", group.Family, group.Database)
	}
	if group.Network == nil || !group.Network.PublicIngress.Get() {
		t.Error("the network family's verdict changed")
	}
}

// TestAnAuroraInstanceWhoseClusterIsElsewhereSettlesNothing covers the half of
// the two-hop walk that a plan commonly does not contain.
//
// The allow list is on the cluster. A cluster managed in another module is not an
// absence of security groups -- the groups exist and this plan cannot see them --
// so the answer is that the allow list is unreadable, and the reason says the
// cluster is what would have named it.
func TestAnAuroraInstanceWhoseClusterIsElsewhereSettlesNothing(t *testing.T) {
	capabilities := database(t, "rds-cluster-elsewhere",
		"aws_rds_cluster_instance.aurora").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	// The instance's own switch is still readable: it is on the instance.
	if !capabilities.PublicEndpoint.IsKnown() || !capabilities.PublicEndpoint.Get() {
		t.Errorf("the instance's own switch was lost with its cluster: %v",
			capabilities.PublicEndpoint.State)
	}
	if len(capabilities.GatedBy) != 0 {
		t.Errorf("gated by %v, and the cluster that names the groups is not in the plan",
			capabilities.GatedBy)
	}
	var said bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AWS_DATABASE_CLUSTER_NOT_IN_PLAN" {
			said = true
			if !strings.Contains(control.Reason, "cluster") {
				t.Errorf("the reason does not name the cluster: %q", control.Reason)
			}
		}
	}
	if !said {
		t.Error("a cluster the plan does not hold is not reported, so the unknown has no reason")
	}
}

// TestAnAuroraClusterWithNoInstanceIsJudgedByNothing is the milestone's criterion
// 8: a cluster carries half the question and no verdict, so a plan holding only
// the cluster settles nothing -- and coverage is what has to say so, because the
// cluster deferred to an instance that is not here.
func TestAnAuroraClusterWithNoInstanceIsJudgedByNothing(t *testing.T) {
	found := database(t, "rds-cluster-without-instances", "aws_rds_cluster.aurora")

	if found.Database != nil {
		t.Error("a cluster with no instance produced a reachability verdict of its own")
	}
	if len(found.DefersTo) != 0 {
		t.Errorf("defers to %v, and no instance is in the plan", found.DefersTo)
	}
	if !found.Interpreted {
		t.Error("the cluster reads as a resource nothing understood")
	}
}

// TestAnAuroraInstanceThatWritesNoSwitchTakesTheProvidersDefault covers the trap
// the milestone first recorded the wrong way round, and the only one on this
// cloud.
//
// `publicly_accessible` is Optional and not Computed on `aws_db_instance`, where
// a real plan emits false when unwritten. On `aws_rds_cluster_instance` it is
// Optional **and Computed** and comes back unknown -- milestone 08's trap again,
// where reading an unknown as unreadable makes the idiomatic resource
// undeterminable.
//
// real-aurora-defaults.json carries the three shapes side by side from one real
// plan: the switch written true, written false, and not written at all.
func TestAnAuroraInstanceThatWritesNoSwitchTakesTheProvidersDefault(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		public bool
		why    string
	}{
		"aurora":   {model.FactKnown, true, "written true"},
		"ax_false": {model.FactKnown, false, "written false"},
		"ax": {model.FactKnown, false,
			"Computed and unwritten, so the provider's default applies: not publicly accessible"},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			capabilities := database(t, "real-aurora-defaults",
				"aws_rds_cluster_instance."+name).Database
			if capabilities == nil {
				t.Fatal("the mapper produced no database capabilities")
			}
			if got := capabilities.PublicEndpoint.State; got != want.state {
				t.Fatalf("state = %q, want %q: %s", got, want.state, want.why)
			}
			if capabilities.PublicEndpoint.Get() != want.public {
				t.Fatalf("public endpoint = %v, want %v: %s",
					capabilities.PublicEndpoint.Get(), want.public, want.why)
			}
		})
	}
}

// TestTheAuroraFixtureCarriesAnUnwrittenSwitch guards that fixture's premise. If
// a regeneration started writing the switch everywhere, the test above would pass
// while proving nothing about the case it exists for.
func TestTheAuroraFixtureCarriesAnUnwrittenSwitch(t *testing.T) {
	plan := plan(t, "real-aurora-defaults")

	var found bool
	for _, change := range plan.ResourceChanges {
		if change.Address != "aws_rds_cluster_instance.ax" {
			continue
		}
		found = true
		if !change.Configured {
			t.Fatal("the fixture records no arguments, so the silence is not the author's")
		}
		if change.States("publicly_accessible") {
			t.Error("the instance writes the switch, so the fixture lost the shape it exists for")
		}
		if change.After.Field("publicly_accessible").State() != terraformplan.StateUnknown {
			t.Error("the switch is determined, which a real plan does not emit for this resource")
		}
	}
	if !found {
		t.Fatal("the fixture holds no Aurora instance that writes no switch")
	}
}

// TestASwitchStatedNowhereIsTheProvidersDefaultToo covers the sanitized shape:
// the attribute in neither half of the change. The provider's default is a
// private endpoint, and an absent attribute is that default rather than a gap.
func TestASwitchStatedNowhereIsTheProvidersDefaultToo(t *testing.T) {
	capabilities := database(t, "rds-switch-stated-nowhere",
		"aws_rds_cluster_instance.ax").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if !capabilities.PublicEndpoint.IsKnown() {
		t.Fatalf("a switch stated nowhere left the endpoint undetermined: %v",
			capabilities.PublicEndpoint.State)
	}
	if capabilities.PublicEndpoint.Get() {
		t.Error("a switch stated nowhere was read as a public endpoint")
	}
}

// TestAnInterpolatedSwitchIsAGapAndNotADefault is the other half of the Aurora
// fix, and the half that keeps it honest.
//
// An unknown nobody wrote is the provider's documented default. An unknown
// somebody did write is a value nothing can resolve yet, and applying a default
// to it invents the one fact the plan withheld. Both shapes are real `terraform
// plan` output; the fix is only sound if the second answers UNKNOWN.
func TestAnInterpolatedSwitchIsAGapAndNotADefault(t *testing.T) {
	capabilities := database(t, "real-aurora-interpolated",
		"aws_rds_cluster_instance.interpolated").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if capabilities.PublicEndpoint.IsKnown() {
		t.Fatalf("a switch the author wrote and the plan cannot resolve was settled as %v",
			capabilities.PublicEndpoint.Get())
	}

	// And the fixture carries the shape, or the assertion above proves nothing.
	parsed := plan(t, "real-aurora-interpolated")
	var found bool
	for _, change := range parsed.ResourceChanges {
		if change.Address != "aws_rds_cluster_instance.interpolated" {
			continue
		}
		found = true
		if !change.States("publicly_accessible") {
			t.Error("the instance does not write the switch, so its unknown is a default")
		}
		if change.After.Field("publicly_accessible").State() != terraformplan.StateUnknown {
			t.Error("the switch is determined, so the fixture lost its shape")
		}
	}
	if !found {
		t.Fatal("the fixture holds no instance writing an unresolvable switch")
	}
}

// TestThePlansOwnPortBeatsTheEngineTable covers the authority this mapper threw
// away.
//
// `port` is Optional and Computed, so it comes back unknown when nobody writes
// it -- which is the common case and the reason the engine table exists. It is
// **known when somebody does** write it, and then it is the authoritative value:
// the engine table is a documented default and the plan is the plan.
//
// Reading the table anyway is the one direction `declared.DatabasePort`'s own
// comment calls dangerous: a wrong port makes a reachable database report as
// closed. A Postgres instance moved to 1433 behind a group open to the world on
// 1433 was ruled out against 5432, leaving only a non-required unknown.
func TestThePlansOwnPortBeatsTheEngineTable(t *testing.T) {
	capabilities := database(t, "rds-port-written", "aws_db_instance.offport").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if !capabilities.Port.IsKnown() {
		t.Fatal("the port the plan states was not read")
	}
	if got := capabilities.Port.Get(); got != 1433 {
		t.Fatalf("port = %d, want 1433: the plan states it and the engine table says 5432", got)
	}

	// And the engine table still answers when the plan does not, or the fix has
	// traded one authority for the other rather than ordering them.
	if port := database(t, "real-databases", "aws_db_instance.reachable").Database.Port; !port.IsKnown() ||
		port.Get() != 5432 {
		t.Errorf("port = %v, want 5432 from the engine when the plan states none", port)
	}
}

// TestAnAllowListThePlanDescribesOnlyPartOfIsNotAnAllowList covers the
// confidence this mapper had no right to.
//
// `vpc_security_group_ids` is a list, and a list can hold a reference beside a
// variable, a local, a module output or a literal id. The configuration records
// the reference and the variable; `References` keeps only the reference, because
// correlation is about resources. Reading what survives as the whole list made a
// publicly accessible Postgres instance behind one closed group and one unknown
// group report PASS, exit 0, with nothing said about it.
//
// Two different gaps, and only one is detectable. A variable or a module output
// leaves a trace the plan records, and that trace is now read. A literal id
// leaves none at all -- `["sg-0aaa"]` and a one-reference list are
// indistinguishable -- so closure here is never fully provable and every proven
// closure carries a bound, the way the network family already bounds its own.
func TestAnAllowListThePlanDescribesOnlyPartOfIsNotAnAllowList(t *testing.T) {
	capabilities := database(t, "rds-partial-allow-list", "aws_db_instance.partial").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if len(capabilities.GatedBy) != 0 {
		t.Errorf("gated by %v: the plan describes only part of this list, so naming part of it "+
			"as the whole gate is the mistake", capabilities.GatedBy)
	}
	var said bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AWS_DATABASE_SECURITY_GROUPS_UNKNOWN" {
			said = true
			if !strings.Contains(control.Reason, "part") && !strings.Contains(control.Reason, "not in this plan") {
				t.Errorf("the reason does not say the list is incomplete: %q", control.Reason)
			}
		}
	}
	if !said {
		t.Error("a half-described allow list reports no missing control")
	}
}

// TestAProvenClosureIsAlwaysBounded covers the gap no plan can show.
//
// A security group id written as a literal leaves no reference at all, so a list
// holding one reference and one literal is byte-identical to a list holding one
// reference. Closure on this cloud is therefore never fully provable, and saying
// so is the difference between a verdict a reader can act on and one they have to
// take on trust. The network family attaches exactly this bound to its own
// closure.
func TestAProvenClosureIsAlwaysBounded(t *testing.T) {
	capabilities := database(t, "real-databases", "aws_db_instance.endpoint_closed_group").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if len(capabilities.GatedBy) == 0 {
		t.Fatal("the gate is not named, so this test is about something else now")
	}
	var bounded bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "AWS_DATABASE_ALLOW_LIST_MAY_BE_PARTIAL" {
			bounded = true
		}
	}
	if !bounded {
		t.Error("a named allow list is presented as complete, and a literal group id leaves no " +
			"trace for this build to find")
	}
}
