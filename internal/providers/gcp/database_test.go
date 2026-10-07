package gcp_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// instance returns the normalized database of a fixture.
func instance(t *testing.T, fixture, name string) model.NormalizedResource {
	t.Helper()
	found, ok := graphOf(t, fixture).At("google_sql_database_instance." + name)
	if !ok {
		t.Fatalf("fixture %s has no instance named %s", fixture, name)
	}
	return found
}

// TestReachabilityFromARealPlan is the authority for this family on this cloud,
// and this is the cloud where the trap lives.
//
// An instance that writes no `ip_configuration` emits the whole block as
// unknown, and Google's documented default for `ipv4_enabled` is a public IP. So
// the idiomatic Cloud SQL instance has an endpoint and the plan does not say so
// in any readable attribute -- the same shape that made every idiomatic
// `google_compute_firewall` undeterminable in milestone 08, one level deeper
// than the machinery reached before this milestone extended it.
//
// real-databases.json is genuine `terraform show -json` output: Terraform 1.14.0,
// hashicorp/google v6, `terraform plan` only -- never applied, no cloud
// contacted, a placeholder credentials filename and a fake project.
func TestReachabilityFromARealPlan(t *testing.T) {
	cases := map[string]struct {
		endpoint model.FactState
		public   bool
		admits   model.FactState
		open     bool
		why      string
	}{
		// The trap: no ip_configuration written anywhere.
		"implicit": {model.FactKnown, true, model.FactKnown, false,
			"the block is unknown and nobody wrote it, so Google's default applies: a public IP"},
		"reachable": {model.FactKnown, true, model.FactKnown, true,
			"a public IP and an authorized network covering every address"},
		// Two authorized networks that are each narrow and together everything.
		"split_halves": {model.FactKnown, true, model.FactKnown, true,
			"the union of the two halves is every address"},
		"one_office": {model.FactKnown, true, model.FactKnown, false,
			"a single office, which is not every address"},
		"endpoint_only": {model.FactKnown, true, model.FactKnown, false,
			"a public IP that nobody is authorized to reach"},
		"no_endpoint": {model.FactKnown, false, model.FactKnown, true,
			"an authorized network covering the world in front of no public IP"},
		// The only shape in which the switch's unknown is a gap: the author
		// wrote it from something the plan cannot resolve.
		"interpolated": {model.FactUnknown, false, model.FactKnown, true,
			"a switch the author wrote and the plan cannot resolve is a gap, not a default"},
		// Cloud SQL writes a version, and every family it writes -- POSTGRES,
		// MYSQL, SQLSERVER -- is one the port table names. There is no
		// unnameable Cloud SQL version to make a fixture of; the refusal is
		// covered where the table lives.
		"unnameable_version": {model.FactKnown, true, model.FactKnown, true,
			"SQLSERVER_2022_EXPRESS is a version the table does name"},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			found := instance(t, "real-databases", name)
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
			// The allow list is inside the instance, so nothing is deferred.
			if len(capabilities.GatedBy) != 0 {
				t.Errorf("gated by %v, and the authorized networks are inside this resource",
					capabilities.GatedBy)
			}
		})
	}
}

// TestThePortComesFromTheDatabaseVersion covers the engine on this cloud, which
// is written as a version rather than a name.
func TestThePortComesFromTheDatabaseVersion(t *testing.T) {
	if port := instance(t, "real-databases", "reachable").Database.Port; !port.IsKnown() ||
		port.Get() != 5432 {
		t.Errorf("port = %v, want 5432 from POSTGRES_15", port)
	}
	// Every family Cloud SQL writes is one the table names, including the one
	// this fixture calls unnameable -- SQLSERVER_2022_EXPRESS is SQLSERVER, and
	// the table reads the family before the first underscore. The refusal is
	// covered where the table lives, because no Cloud SQL version reaches it.
	if port := instance(t, "real-databases", "unnameable_version").Database.Port; !port.IsKnown() ||
		port.Get() != 1433 {
		t.Errorf("port = %v, want 1433 from SQLSERVER_2022_EXPRESS", port)
	}
}

// TestTheFixtureCarriesBothShapesOfTheUnknownSwitch guards the premise the two
// most important cases rest on.
//
// `implicit` must write no `ipv4_enabled` and `interpolated` must write one, or
// the pair proves nothing: the first is a default and the second is a gap, and
// they are the same unknown in the plan.
func TestTheFixtureCarriesBothShapesOfTheUnknownSwitch(t *testing.T) {
	const path = "settings.ip_configuration.ipv4_enabled"
	plan := planOf(t, "real-databases")

	states := map[string]bool{}
	for _, change := range plan.ResourceChanges {
		if change.Type != "google_sql_database_instance" {
			continue
		}
		if !change.Configured {
			t.Fatalf("%s records no arguments, so the silence is not the author's", change.Address)
		}
		name := change.Address[strings.LastIndex(change.Address, ".")+1:]
		states[name] = change.States(path)
	}

	if states["implicit"] {
		t.Error("the implicit instance writes the switch, so its unknown is not a default")
	}
	if !states["interpolated"] {
		t.Error("the interpolated instance does not write the switch, so its unknown is a default")
	}
	// And both are genuinely unknown in the plan, or neither case is about an
	// unknown at all.
	for _, name := range []string{"implicit", "interpolated"} {
		for _, change := range plan.ResourceChanges {
			if !strings.HasSuffix(change.Address, "."+name) {
				continue
			}
			settings := change.After.Field("settings")
			if settings.Len() == 0 {
				t.Fatalf("%s states no settings block", name)
			}
			switch config := settings.At(0).Field("ip_configuration"); {
			case config.State() == terraformplan.StateUnknown:
				// The whole block, which is the `implicit` shape.
			case config.Len() > 0 &&
				config.At(0).Field("ipv4_enabled").State() == terraformplan.StateUnknown:
				// The leaf, which is the `interpolated` shape.
			default:
				t.Errorf("%s has a determined switch, so the fixture lost its shape", name)
			}
		}
	}
}

// TestTheOtherTwoFamiliesAreUntouched is acceptance criterion 5 in this package.
func TestTheOtherTwoFamiliesAreUntouched(t *testing.T) {
	web := firewall(t, "fw-public")
	if web.Family != model.FamilyNetwork || web.Database != nil {
		t.Errorf("a firewall is %q with database = %v", web.Family, web.Database)
	}
	if web.Network == nil || !web.Network.PublicIngress.Get() {
		t.Error("the network family's verdict changed")
	}
	if bucket, ok := graphOf(t, "public-iam-member").At("google_storage_bucket.assets"); ok {
		if bucket.Family != model.FamilyObjectStorage || bucket.Database != nil {
			t.Errorf("a bucket is %q with database = %v", bucket.Family, bucket.Database)
		}
	}
}

// TestWhatCannotBeReadIsNamedRatherThanAssumed covers the three shapes that leave
// this cloud's question open, and the controls a reader gets for each.
//
// Each one could be the thing that opens the instance, so each is undetermined
// rather than defaulted -- and each names what would settle it, because an
// unknown with no reason is a dead end.
func TestWhatCannotBeReadIsNamedRatherThanAssumed(t *testing.T) {
	cases := map[string]struct {
		fixture, name, control string
		why                    string
	}{
		"a version the plan cannot resolve": {
			"real-databases-unreadable", "version_unreadable",
			"GCP_SQL_DATABASE_VERSION_UNREADABLE",
			"database_version is Required and can still be written from an unresolvable value"},
		"an authorized address the plan cannot resolve": {
			"real-databases-unreadable", "network_unreadable",
			"GCP_SQL_AUTHORIZED_NETWORK_UNREADABLE",
			"an address nobody read could be every address"},
		// A clone, which writes no settings at all. This replaces a fixture that
		// encoded the block as unknown *and* written: measured against the
		// provider, a `dynamic "ip_configuration"` records nothing in the
		// configuration and resolves to a readable list, so that shape is not
		// one Terraform emits and the fixture was fiction.
		"an instance whose settings this plan does not describe": {
			"sql-cloned", "cloned",
			"GCP_SQL_IP_CONFIGURATION_UNREADABLE",
			"a clone inherits its configuration from an instance that is not here"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			capabilities := instance(t, c.fixture, c.name).Database
			if capabilities == nil {
				t.Fatal("the mapper produced no database capabilities")
			}

			var said bool
			for _, control := range capabilities.Unresolved {
				if control.CheckID == c.control {
					said = true
					if control.Reason == "" {
						t.Error("the control says nothing")
					}
				}
			}
			if !said {
				t.Fatalf("%s is not reported: %s\n%+v", c.control, c.why, capabilities.Unresolved)
			}
		})
	}

	// The two that must stay open, because the gap is in the deciding half.
	for _, name := range []string{"network_unreadable"} {
		if admits := instance(t, "real-databases-unreadable", name).Database.AdmitsAnyAddress; admits.IsKnown() {
			t.Errorf("%s settled the allow list as %v with an address nobody read", name, admits.Get())
		}
	}
	if admits := instance(t, "sql-cloned", "cloned").Database.AdmitsAnyAddress; admits.IsKnown() {
		t.Errorf("a clone's inherited allow list settled as %v", admits.Get())
	}
}

// TestAClonedInstanceInheritsWhatThisPlanCannotSee is the shape that turned an
// author's silence into a proof of privacy.
//
// Cloud SQL requires one of `clone` or `settings`. An instance created from a
// clone writes no `settings` at all, so `settings.ip_configuration` is unwritten
// -- and the mapper read that the same way it reads an instance that wrote
// `settings` and left `ip_configuration` out, which is a provider default of no
// authorized networks. A clone is not that. It inherits the source instance's IP
// configuration, authorized networks included, and the source is not in the plan.
//
// The result was PASS, exit 0, with no finding and no unknown, against a contract
// demanding privacy.
//
// The guard is the positive form: a silence about something inside a block is
// only the author's silence if the author wrote the block. ARCHITECTURE.md
// already says a decision that a rule set is complete must ask `Written` rather
// than `Unwritten`, and this is that decision.
func TestAClonedInstanceInheritsWhatThisPlanCannotSee(t *testing.T) {
	capabilities := instance(t, "sql-cloned", "cloned").Database
	if capabilities == nil {
		t.Fatal("the mapper produced no database capabilities")
	}

	if capabilities.AdmitsAnyAddress.IsKnown() {
		t.Fatalf("a clone's inherited allow list was settled as %v",
			capabilities.AdmitsAnyAddress.Get())
	}
	if capabilities.PublicEndpoint.IsKnown() {
		t.Errorf("a clone's inherited endpoint was settled as %v",
			capabilities.PublicEndpoint.Get())
	}
	var said bool
	for _, control := range capabilities.Unresolved {
		if control.CheckID == "GCP_SQL_IP_CONFIGURATION_UNREADABLE" {
			said = true
		}
	}
	if !said {
		t.Error("nothing says why the clone cannot be settled")
	}
}

// TestTheClonedFixtureWritesNoSettings guards that fixture's premise, and the
// distinction the fix turns on: a clone writes `clone` and no `settings`, while
// the instance criterion 6 is about writes `settings` and no `ip_configuration`.
// Both are silences and only one is the author's about the allow list.
func TestTheClonedFixtureWritesNoSettings(t *testing.T) {
	plan := planOf(t, "sql-cloned")

	var found bool
	for _, change := range plan.ResourceChanges {
		if change.Type != "google_sql_database_instance" {
			continue
		}
		found = true
		if !change.Configured {
			t.Fatal("the fixture records no arguments, so the silence is not the author's")
		}
		if change.States("settings") {
			t.Error("the clone writes settings, so the fixture lost the shape it exists for")
		}
		if !change.States("clone") {
			t.Error("the clone does not write clone, so it is not a clone")
		}
	}
	if !found {
		t.Fatal("the fixture holds no instance")
	}

	// And the shape it must stay distinguishable from.
	other := planOf(t, "real-databases")
	for _, change := range other.ResourceChanges {
		if !strings.HasSuffix(change.Address, ".implicit") {
			continue
		}
		if !change.States("settings") {
			t.Error("the implicit instance does not write settings, so the two shapes have merged")
		}
		if change.States("settings.ip_configuration") {
			t.Error("the implicit instance writes ip_configuration, so it is not the default case")
		}
	}
}

// TestADestroyedInstanceIsDistinguishedFromAReplacedOne pins, on this cloud, the
// distinction the rule needs: a change that removes a database permits nothing
// through it, and a replacement creates one whose reachability is the verdict.
//
// Both fixtures are genuine `terraform show -json`: Terraform 1.14.0,
// hashicorp/google v6, planned with `-refresh=false` against a hand-written
// state file so no cloud was contacted, provider credentials a placeholder and
// the argument deleted from the plan afterwards.
//
// The measured fact is the same one AWS shows: a destroy emits `after` as null,
// so `ipv4_enabled` is absent for the same reason as on an instance whose
// settings nothing can resolve. Without the action, the mapper cannot tell them
// apart -- and reported a database being deleted as one whose reachability could
// not be determined.
func TestADestroyedInstanceIsDistinguishedFromAReplacedOne(t *testing.T) {
	cases := map[string]struct {
		fixture string
		name    string
		removed bool
	}{
		"a destroy-only change": {"sql-destroyed", "going_away", true},
		"a replacement":         {"sql-replaced", "replaced", false},
	}

	for label, want := range cases {
		t.Run(label, func(t *testing.T) {
			found := instance(t, want.fixture, want.name)
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
