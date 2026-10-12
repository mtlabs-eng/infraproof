package azure_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
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
		{"public-blob-container-defaulted", true, model.MethodProviderDefault, "gate written, access type unwritten"},
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
