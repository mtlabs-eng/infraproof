package declared

import "strings"

// Ports the engines this build can name listen on, by their published defaults.
const (
	portPostgres  = 5432
	portMySQL     = 3306
	portSQLServer = 1433
	portOracle    = 1521
)

// DatabasePort reads the port an engine listens on by default.
//
// It exists because the port itself is never in the plan: `port` is Optional and
// Computed on every provider measured and comes back unknown on every create,
// even when the engine is written. Without it, an allow list cannot be compared
// against anything, and every admitted address would count as reaching the
// database.
//
// This is the argument already accepted for ProtocolNumber: the assignment is
// closed and published, so reading it is reading a fact rather than guessing at
// one. The consequence of being wrong is worse here, though. A missing port
// over-reports -- any admitted address counts -- while a *wrong* port makes a
// reachable database report as closed, so the table is matched strictly and each
// engine is tested in its own right.
//
// Two spellings, because two clouds write this differently and neither is
// constrained by its schema. AWS writes an engine in lower case with hyphens
// (`postgres`, `oracle-se2`), which a real plan confirms. Cloud SQL writes a
// *version* in upper case with underscores (`POSTGRES_15`), where the family is
// the part before the first underscore. The two forms cannot collide, so one
// function reads both; a spelling in neither form is unnamed rather than
// coerced.
func DatabasePort(engine string) (int, bool) {
	switch engine {
	case "postgres", "aurora-postgresql":
		return portPostgres, true
	case "mysql", "mariadb", "aurora-mysql":
		return portMySQL, true
	}

	// AWS writes a variant after the family for these two, and every variant
	// listens on the family's port: `oracle-se2`, `oracle-ee-cdb`,
	// `sqlserver-ex`. The hyphen is required, so the bare family name -- which
	// no provider emits -- is not read.
	switch {
	case strings.HasPrefix(engine, "oracle-"):
		return portOracle, true
	case strings.HasPrefix(engine, "sqlserver-"):
		return portSQLServer, true
	}

	// Cloud SQL. The underscore is required for the same reason the hyphen is:
	// `POSTGRES` alone is not a version and Google does not emit it.
	family, _, versioned := strings.Cut(engine, "_")
	if !versioned {
		return 0, false
	}
	switch family {
	case "POSTGRES":
		return portPostgres, true
	case "MYSQL":
		return portMySQL, true
	case "SQLSERVER":
		return portSQLServer, true
	default:
		return 0, false
	}
}
