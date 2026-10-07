package azure

import "testing"

// TestPortOfRefusesATypeItDoesNotName is an internal test because the refusal is
// unreachable from outside: Interprets gates which types arrive, and it names the
// same two portOf does.
//
// That is exactly why the test exists. The switch answered the MSSQL port by
// default, so a third server type added to Interprets without touching portOf
// would have inherited 1433 in silence -- and a wrong port makes a reachable
// database read as closed, which is the direction that hides a grant.
// `ruleTypeFor` next door already refuses the same way.
//
// Asserted from the other side too: every type Interprets claims as a server has
// a port here, so the two lists cannot drift apart without this failing.
func TestPortOfRefusesATypeItDoesNotName(t *testing.T) {
	if got := portOf("azurerm_mysql_flexible_server"); got != 0 {
		t.Fatalf("portOf(a type outside the set) = %d, want 0: a type this build "+
			"does not name must leave the port undetermined rather than take "+
			"another type's", got)
	}

	for _, named := range []string{typeSQLServer, typePostgresServer} {
		if !(Mapper{}).Interprets(named) {
			t.Fatalf("%s has a port here and is not interpreted, so one of the two "+
				"lists has moved", named)
		}
		if portOf(named) == 0 {
			t.Fatalf("%s is interpreted as a server and portOf does not name it, "+
				"so its port is undetermined for no reason", named)
		}
	}
}
