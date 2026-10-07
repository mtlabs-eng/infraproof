package intent_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/intent"
)

// database builds a contract whose only entry is a database one.
func database(fields string) string {
	return `{
  "schema_version": "1.2",
  "change_id": "c",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "database", ` + fields + `}]
}`
}

// TestADatabaseEntryDeclaresAnExposure covers the product decision this family
// was built on: the question is binary -- reachable from the internet, or not --
// so the contract says which, and says nothing about ports.
//
// Ports belong to the network family, where an author is describing a service
// they chose to publish. Nobody publishes a database port on purpose and then
// wants to name it.
func TestADatabaseEntryDeclaresAnExposure(t *testing.T) {
	for _, exposure := range []intent.Exposure{
		intent.ExposurePrivate, intent.ExposurePublic, intent.ExposureUnspecified,
	} {
		t.Run(string(exposure), func(t *testing.T) {
			contract, err := contractWith(t, database(`"exposure": "`+string(exposure)+`"`))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}

			declared, mentioned := contract.ExposureOf(intent.FamilyDatabase)
			if !mentioned {
				t.Fatal("the declaration was dropped")
			}
			if declared != exposure {
				t.Fatalf("exposure = %q, want %q", declared, exposure)
			}
			// The accessor is family-parameterised, so a database entry must not
			// answer for another family.
			if _, other := contract.ExposureOf(intent.FamilyObjectStorage); other {
				t.Error("a database entry answered an object-storage question")
			}
		})
	}
}

// TestADatabaseEntryRefusesPortsAndRequiresAnExposure covers the two refusals,
// because a contract that is wrong about which fields it may carry is a contract
// whose author believes it constrains something it does not.
func TestADatabaseEntryRefusesPortsAndRequiresAnExposure(t *testing.T) {
	cases := map[string]struct{ fields, says string }{
		"ports on a database": {
			`"exposure": "private", "public_ports": ["5432"]`,
			"public_ports does not apply",
		},
		"no exposure at all": {
			`"purpose": "the production database"`,
			"exposure is required",
		},
		"an exposure that is not one": {
			`"exposure": "internal"`,
			"exposure is",
		},
		"ports and no exposure": {
			`"public_ports": ["5432"]`,
			"public_ports does not apply",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := contractWith(t, database(c.fields))
			if err == nil {
				t.Fatalf("%s loaded", name)
			}
			if !strings.Contains(err.Error(), c.says) {
				t.Errorf("the message does not say %q:\n  %v", c.says, err)
			}
		})
	}
}

// TestTheThreeFamiliesCanBeDeclaredTogether covers the shape a real contract has
// once this build decides three families, and the thing that would break it: an
// accessor answering for the wrong entry.
func TestTheThreeFamiliesCanBeDeclaredTogether(t *testing.T) {
	contract, err := contractWith(t, `{
  "schema_version": "1.2",
  "change_id": "c",
  "environment": "production",
  "allowed_clouds": ["aws", "azure", "gcp"],
  "destructive_changes": "forbidden",
  "resources": [
    {"family": "object_storage", "exposure": "private"},
    {"family": "network", "public_ports": ["443"]},
    {"family": "database", "exposure": "private"}
  ]
}`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	storage, ok := contract.ExposureOf(intent.FamilyObjectStorage)
	if !ok || storage != intent.ExposurePrivate {
		t.Errorf("object storage declared %q (%v)", storage, ok)
	}
	databases, ok := contract.ExposureOf(intent.FamilyDatabase)
	if !ok || databases != intent.ExposurePrivate {
		t.Errorf("database declared %q (%v)", databases, ok)
	}
	ports, ok := contract.PublicPortsOf(intent.FamilyNetwork)
	if !ok || len(ports) != 1 {
		t.Errorf("network declared %v (%v)", ports, ok)
	}
	// And the family that declares ports must not answer an exposure question,
	// nor the reverse. The accessors skip an entry whose field is absent, and
	// that is what keeps three entries from bleeding into each other.
	if _, ok := contract.PublicPortsOf(intent.FamilyDatabase); ok {
		t.Error("a database entry answered a ports question")
	}
	if _, ok := contract.ExposureOf(intent.FamilyNetwork); ok {
		t.Error("a network entry answered an exposure question")
	}
}
