package azure_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// The port is from a table keyed on the type -- documented-table -- and is
// certain, so PortInferred stays false. Two questions, two fields.
func TestATypeDerivedPortIsFromTheTableAndNotInferred(t *testing.T) {
	db := databaseAt(t, "sql-reachable", "azurerm_mssql_server.db").Database
	if !db.Port.IsKnown() || db.Port.Method() != model.MethodDocumentedTable {
		t.Errorf("method = %q, want %q", db.Port.Method(), model.MethodDocumentedTable)
	}
	if db.PortInferred {
		t.Error("PortInferred = true; the type fixes the port, so it is not a default")
	}
}

// The method follows the configuration, not the after state: a switch the
// author wrote is stated, and one they left out is the provider's default even
// when the plan carries a known value for it.
func TestTheEndpointSwitchIsStated(t *testing.T) {
	db := databaseAt(t, "sql-reachable", "azurerm_mssql_server.db").Database
	if !db.PublicEndpoint.IsKnown() || db.PublicEndpoint.Method() != model.MethodStated {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodStated)
	}
}

func TestAnUnwrittenEndpointSwitchIsTheProviderDefault(t *testing.T) {
	db := databaseAt(t, "sql-switch-defaulted", "azurerm_mssql_server.db").Database
	if !db.PublicEndpoint.IsKnown() || !db.PublicEndpoint.Get() {
		t.Fatalf("switch = %s, want known true from the plan", db.PublicEndpoint.State)
	}
	if db.PublicEndpoint.Method() != model.MethodProviderDefault {
		t.Errorf("method = %q, want %q", db.PublicEndpoint.Method(), model.MethodProviderDefault)
	}
}

func TestStorageAccessSettingsFollowTheConfiguration(t *testing.T) {
	cases := []struct {
		fixture string
		want    bool
		method  model.Method
		why     string
	}{
		{"public-blob-written", true, model.MethodStated, "both settings written"},
		{"private-container-written-gate-unwritten", false, model.MethodStated, "private container written, gate unwritten"},
		{"private-container-unwritten-gate-written", false, model.MethodProviderDefault, "private container unwritten, gate written"},
		// Not a default. container_access_type defaults to "private" and is not
		// Computed, so Terraform plans an unwritten one as "private": a "blob"
		// beside a configuration that does not write it is a shape Terraform
		// cannot produce, and the value is somebody's. Until the adversarial
		// review this row said provider-default, defending a branch no real
		// plan reaches.
		{"public-blob-container-defaulted", true, model.MethodStated, "gate written, a public access type cannot be the default"},
		{"public-blob-gate-defaulted", true, model.MethodProviderDefault, "access type written, gate unwritten"},
		{"public-blob", true, model.MethodProviderDefault, "neither setting written"},
		{"private-account-forbids-written", false, model.MethodStated, "the deciding gate written"},
		{"private-account-forbids", false, model.MethodProviderDefault, "the deciding gate unwritten"},
	}
	for _, c := range cases {
		got := container(t, c.fixture).ObjectStorage.PublicAccess
		if !got.IsKnown() || got.Get() != c.want {
			t.Errorf("%s: %s = %v, want known %v", c.fixture, c.why, got.State, c.want)
			continue
		}
		if got.Method() != c.method {
			t.Errorf("%s (%s): method = %q, want %q", c.fixture, c.why, got.Method(), c.method)
		}
	}
}

// An account with no container is judged on its own gate, and a gate that says
// no takes the gate's method: stated when the configuration writes it, the
// provider's default when it does not.
func TestAnAccountAloneTakesItsGatesMethod(t *testing.T) {
	access := func(written string) model.Fact[bool] {
		t.Helper()
		raw := []byte(fmt.Sprintf(`{
		  "format_version": "1.2",
		  "resource_changes": [{
		    "address": "azurerm_storage_account.example", "mode": "managed",
		    "type": "azurerm_storage_account", "name": "example", "provider_name": "p",
		    "change": {"actions": ["create"], "before": null,
		               "after": {"name": "s", "allow_nested_items_to_be_public": false}}
		  }],
		  "configuration": {"root_module": {"resources": [{
		    "address": "azurerm_storage_account.example", "mode": "managed",
		    "type": "azurerm_storage_account", "name": "example",
		    "expressions": {"name": {"constant_value": "s"}%s}
		  }]}}
		}`, written))
		plan, err := terraformplan.Parse(raw)
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		account, ok := providers.Normalize(plan, providers.Default()).At("azurerm_storage_account.example")
		if !ok || account.ObjectStorage == nil {
			t.Fatal("the account is missing from the graph")
		}
		return account.ObjectStorage.PublicAccess
	}

	cases := []struct {
		why     string
		written string
		method  model.Method
	}{
		{"gate written", `, "allow_nested_items_to_be_public": {"constant_value": false}`, model.MethodStated},
		{"gate unwritten", ``, model.MethodProviderDefault},
	}
	for _, c := range cases {
		got := access(c.written)
		if !got.IsKnown() || got.Get() {
			t.Errorf("%s: state = %s, want known false", c.why, got.State)
			continue
		}
		if got.Method() != c.method {
			t.Errorf("%s: method = %q, want %q", c.why, got.Method(), c.method)
		}
	}
}

// D2: a firewall rule is joined to its server through server_id, and the join
// only locates where the grant applies. The grant itself is the rule's start
// and end address, Required arguments written on the rule's own resource, so it
// is stated wherever the configuration records the rule.
func TestADatabaseAdmissionThroughAFirewallRuleIsStated(t *testing.T) {
	for fixture, address := range map[string]string{
		"sql-reachable": "azurerm_mssql_server.db",
		"pg-reachable":  "azurerm_postgresql_flexible_server.db",
	} {
		admitted := databaseAt(t, fixture, address).Database.AdmitsAnyAddress
		if !admitted.IsKnown() || !admitted.Get() || admitted.Method() != model.MethodStated {
			t.Errorf("%s: method = %q (state %s), want known true %q", fixture, admitted.Method(), admitted.State, model.MethodStated)
		}
	}
}

// The same plans with their configuration stripped: nothing records who wrote
// the rule, so nothing is stated.
func TestADatabaseAdmissionInAPlanWithoutConfigurationIsUnrecorded(t *testing.T) {
	admitted := withoutConfiguration(t, "sql-reachable", "azurerm_mssql_server.db").Database.AdmitsAnyAddress
	if !admitted.IsKnown() || !admitted.Get() || admitted.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q (state %s), want known true %q", admitted.Method(), admitted.State, model.MethodConfigurationUnrecorded)
	}
}

// An inline rule the configuration writes is stated, and so is a separate rule
// whose source is not null: source_address_prefix is not Computed and has no
// default, so Terraform plans an unwritten one as null and a source somebody
// can reach through was written. Without a configuration, neither is recorded;
// and an inline set the configuration does not record -- Azure carries one
// across an update, and a dynamic block leaves no record -- is not either.
func TestANetworkSecurityGroupGrantSaysWhatTheConfigurationRecords(t *testing.T) {
	cases := []struct {
		name   string
		group  func() model.NormalizedResource
		method model.Method
	}{
		{"inline, written", func() model.NormalizedResource {
			return networkAt(t, "nsg-public-inline")
		}, model.MethodStated},
		{"separate rule", func() model.NormalizedResource {
			return networkAt(t, "nsg-separate-open")
		}, model.MethodStated},
		{"inline, no configuration", func() model.NormalizedResource {
			return withoutConfiguration(t, "nsg-public-inline", "azurerm_network_security_group.web")
		}, model.MethodConfigurationUnrecorded},
		{"inline, not recorded", func() model.NormalizedResource {
			return withStatedRemoved(t, "nsg-public-inline", "azurerm_network_security_group.web", "security_rule")
		}, model.MethodConfigurationUnrecorded},
	}
	for _, c := range cases {
		ingress := c.group().Network.PublicIngress
		if !ingress.IsKnown() || !ingress.Get() || ingress.Method() != c.method {
			t.Errorf("%s: method = %q (state %s), want known true %q", c.name, ingress.Method(), ingress.State, c.method)
		}
	}
}

func networkAt(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	found, ok := providers.Normalize(planOf(t, fixture), providers.Default()).At("azurerm_network_security_group.web")
	if !ok || found.Network == nil {
		t.Fatalf("%s has no network security group at azurerm_network_security_group.web", fixture)
	}
	return found
}

// withoutConfiguration normalizes a fixture as a plan with no configuration
// section would arrive: nothing declared, nothing recorded.
func withoutConfiguration(t *testing.T, fixture, address string) model.NormalizedResource {
	t.Helper()
	plan := planOf(t, fixture)
	for i := range plan.ResourceChanges {
		plan.ResourceChanges[i].Declared = false
		plan.ResourceChanges[i].Configured = false
		plan.ResourceChanges[i].Stated = nil
	}
	found, ok := providers.Normalize(plan, providers.Default()).At(address)
	if !ok {
		t.Fatalf("%s has no resource at %s", fixture, address)
	}
	return found
}

// withStatedRemoved normalizes a fixture whose configuration does not record
// one argument of one resource.
func withStatedRemoved(t *testing.T, fixture, address, argument string) model.NormalizedResource {
	t.Helper()
	plan := planOf(t, fixture)
	for i := range plan.ResourceChanges {
		if plan.ResourceChanges[i].Address != address {
			continue
		}
		var kept []string
		for _, name := range plan.ResourceChanges[i].Stated {
			if name != argument && !strings.HasPrefix(name, argument+".") {
				kept = append(kept, name)
			}
		}
		plan.ResourceChanges[i].Stated = kept
	}
	found, ok := providers.Normalize(plan, providers.Default()).At(address)
	if !ok {
		t.Fatalf("%s has no resource at %s", fixture, address)
	}
	return found
}

func planOf(t *testing.T, fixture string) terraformplan.Plan {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture+".json"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	return plan
}

// A grant needs both the gate and the container, so it is only as strong as the
// weaker. public-blob-written writes both; with the container missing from the
// configuration, the account's written gate cannot make the grant stated.
func TestAGrantIsOnlyAsStrongAsTheWeakerSetting(t *testing.T) {
	plan := planOf(t, "public-blob-written")
	for i := range plan.ResourceChanges {
		if plan.ResourceChanges[i].Type == "azurerm_storage_container" {
			plan.ResourceChanges[i].Declared = false
			plan.ResourceChanges[i].Configured = false
			plan.ResourceChanges[i].Stated = nil
		}
	}
	found, ok := providers.Normalize(plan, providers.Default()).At("azurerm_storage_container.assets")
	if !ok || found.ObjectStorage == nil {
		t.Fatal("no container at azurerm_storage_container.assets")
	}
	access := found.ObjectStorage.PublicAccess
	if !access.IsKnown() || !access.Get() || access.Method() != model.MethodConfigurationUnrecorded {
		t.Errorf("method = %q (state %s), want known true %q", access.Method(), access.State, model.MethodConfigurationUnrecorded)
	}
}
