package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
)

// A database's port decides whether an allow list reaches it, and the port
// attribute is Optional and Computed on every provider measured: a real create
// plan emits it unknown even when the engine is written. So the port comes from
// the engine, through a table of documented defaults.
//
// This is the argument already accepted for declared.ProtocolNumber. The
// assignment is closed and published, reading it is reading a fact, and anything
// outside it is undetermined rather than guessed. The difference from protocol
// numbers is the consequence of being wrong: an engine mapped to the wrong port
// makes a reachable database report as closed, so each engine gets its own case
// rather than one test for the mechanism.
func TestEveryEngineThisBuildCanNameHasItsDocumentedPort(t *testing.T) {
	cases := map[string]int{
		// AWS RDS engine identifiers, as `aws_db_instance.engine` accepts them.
		"postgres":          5432,
		"mysql":             3306,
		"mariadb":           3306,
		"aurora-postgresql": 5432,
		"aurora-mysql":      3306,
		"oracle-se2":        1521,
		"oracle-se2-cdb":    1521,
		"oracle-ee":         1521,
		"oracle-ee-cdb":     1521,
		"sqlserver-ex":      1433,
		"sqlserver-web":     1433,
		"sqlserver-se":      1433,
		"sqlserver-ee":      1433,
		// Cloud SQL writes a version rather than an engine, and the family is
		// the prefix.
		"POSTGRES_15":             5432,
		"POSTGRES_16":             5432,
		"MYSQL_8_0":               3306,
		"SQLSERVER_2019_STANDARD": 1433,
	}

	for engine, want := range cases {
		t.Run(engine, func(t *testing.T) {
			got, named := declared.DatabasePort(engine)
			if !named {
				t.Fatalf("%q is an engine this build should name", engine)
			}
			if got != want {
				t.Fatalf("port = %d, want %d", got, want)
			}
		})
	}
}

// An engine outside the table is undetermined, not defaulted. A wrong port is
// worse than no port: no port makes any admitted address count, which
// over-reports, and a wrong one makes a reachable database report as closed.
func TestAnEngineOutsideTheTableHasNoPort(t *testing.T) {
	for _, engine := range []string{
		// Real engines this build does not claim to know the port of.
		"neptune", "docdb", "redis", "memcached", "clickhouse",
		// Spellings that are not engines.
		"", "postgres ", "Postgres", "POSTGRES", "postgresql", "mysql5",
		"../postgres", "postgres\n", "MYSQL", "SQLSERVER",
		// A Cloud SQL family name in the wrong case. The provider emits
		// POSTGRES_15 and nothing emits postgres_15, so matching it would be
		// accepting a spelling that does not exist -- and an upper-casing lookup
		// is the obvious way to write this wrong.
		"postgres_15", "mysql_8_0", "Postgres_15", "sqlserver_2019_standard",
		// The bare family name of a hyphenated AWS engine. The provider emits
		// `oracle-se2` and `sqlserver-ex`, never these, so reading them would be
		// accepting a spelling nothing writes -- and the prefix match is what
		// makes that possible to get wrong.
		"oracle", "sqlserver", "oracle_se2", "sqlserverex",
	} {
		t.Run(engine, func(t *testing.T) {
			if port, named := declared.DatabasePort(engine); named {
				t.Fatalf("%q was read as port %d", engine, port)
			}
		})
	}
}

// TestTheTableIsCaseSensitiveInEachProvidersOwnSpelling pins the one thing a
// case-insensitive lookup would get wrong.
//
// AWS writes its engines lower-case and Cloud SQL writes its versions
// upper-case, and both are what the provider puts in the plan. Accepting either
// spelling for either cloud would accept a value no provider emits, which is a
// grammar this build invented -- the defect class this repository keeps finding.
func TestTheTableIsCaseSensitiveInEachProvidersOwnSpelling(t *testing.T) {
	if _, named := declared.DatabasePort("postgres"); !named {
		t.Error("the AWS spelling is not read")
	}
	if _, named := declared.DatabasePort("POSTGRES_15"); !named {
		t.Error("the Cloud SQL spelling is not read")
	}
	if _, named := declared.DatabasePort("PostgreSQL"); named {
		t.Error("a spelling no provider emits is read")
	}
}
