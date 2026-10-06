package intent_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// contractWith writes a contract and loads it, returning the error unchanged so
// a test can assert on what a reader is told.
func contractWith(t *testing.T, body string) (intent.Contract, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intent.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return intent.Load(path)
}

// network builds a contract whose only entry is a network one.
func network(ports string) string {
	return `{
  "schema_version": "1.1",
  "change_id": "c",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "network", ` + ports + `}]
}`
}

// TestANetworkEntryDeclaresPorts covers the product decision this family was
// built on: the contract says which ports may be reachable from any address, and
// says nothing else.
func TestANetworkEntryDeclaresPorts(t *testing.T) {
	contract, err := contractWith(t, network(`"public_ports": ["443", "80", "8000-8100"]`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	ports, declared := contract.PublicPortsOf(intent.FamilyNetwork)
	if !declared {
		t.Fatal("the contract declared ports and the accessor says it did not")
	}
	want := []model.PortRange{{From: 443, To: 443}, {From: 80, To: 80}, {From: 8000, To: 8100}}
	if len(ports) != len(want) {
		t.Fatalf("ports = %v, want %v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ports = %v, want %v", ports, want)
		}
	}
}

// TestAnEmptyPortListIsTheMostRestrictiveThingItCanSay is why the field is a
// pointer. An empty list declares that no port may be reachable from any address,
// which is a statement; an omitted field is the absence of one. Reading presence
// off the length collapses them, and the collapse favours the permissive reading.
func TestAnEmptyPortListIsTheMostRestrictiveThingItCanSay(t *testing.T) {
	declaredEmpty, err := contractWith(t, network(`"public_ports": []`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ports, declared := declaredEmpty.PublicPortsOf(intent.FamilyNetwork)
	if !declared {
		t.Fatal("an empty list was read as no declaration at all")
	}
	if len(ports) != 0 {
		t.Fatalf("an empty list declared %v", ports)
	}

	// And a contract with no network entry declares nothing about the family.
	storage, err := contractWith(t, `{
  "schema_version": "1.1",
  "change_id": "c",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage", "exposure": "private"}]
}`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, declared := storage.PublicPortsOf(intent.FamilyNetwork); declared {
		t.Fatal("a contract with no network entry claims to declare ports")
	}
}

// TestEachFamilyDeclaresWhatItsRuleReads covers the validation this family made
// family-dependent. A network entry carrying an exposure, or a storage entry
// carrying ports, is two fields that can contradict each other -- and refusing
// that is cheaper than deciding which one wins.
func TestEachFamilyDeclaresWhatItsRuleReads(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"network without ports": {network(`"purpose": "web"`), "public_ports is required"},
		"network with exposure": {network(`"public_ports": ["443"], "exposure": "public"`),
			"exposure does not apply"},
		"storage with ports": {`{
  "schema_version": "1.1", "change_id": "c", "environment": "staging",
  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage", "exposure": "private", "public_ports": ["443"]}]
}`, "public_ports does not apply"},
		"storage without exposure": {`{
  "schema_version": "1.1", "change_id": "c", "environment": "staging",
  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage"}]
}`, "exposure is required"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := contractWith(t, c.body)
			if err == nil {
				t.Fatal("accepted a contract declaring what its family's rule does not read")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not say %q", err, c.want)
			}
		})
	}
}

// TestAPortDeclarationIsValidatedAtTheBoundary covers every spelling the grammar
// refuses. A port this build cannot read is an invalid contract, not a defaulted
// one: a declaration nobody could parse must not quietly permit nothing, because
// a contract that was refused is a contract the author fixes.
func TestAPortDeclarationIsValidatedAtTheBoundary(t *testing.T) {
	refused := map[string]string{
		"blank":                         `""`,
		"only spaces":                   `" "`,
		"not a number":                  `"http"`,
		"negative":                      `"-1"`,
		"past the last port":            `"65536"`,
		"reversed range":                `"8100-8000"`,
		"three parts":                   `"1-2-3"`,
		"open range":                    `"8000-"`,
		"missing low end":               `"-8000"`,
		"inner space":                   `"80 00"`,
		"leading plus":                  `"+443"`,
		"hexadecimal":                   `"0x1bb"`,
		"past the last port in a range": `"65535-65536"`,
	}
	for name, port := range refused {
		t.Run(name, func(t *testing.T) {
			_, err := contractWith(t, network(`"public_ports": [`+port+`]`))
			if err == nil {
				t.Fatalf("accepted %s as a port", port)
			}
			if !strings.Contains(err.Error(), "public_ports") {
				t.Fatalf("error %q does not name the field", err)
			}
			// A blank declaration gets the message that tells an author what to
			// write, not the one about a range with an end missing. The two are
			// different mistakes and the second reads as nonsense for the first.
			if strings.TrimSpace(strings.Trim(port, `"`)) == "" &&
				!strings.Contains(err.Error(), "is blank") {
				t.Fatalf("a blank declaration was reported as %q", err)
			}
		})
	}
}

// TestAPortDeclarationAcceptsWhatAProviderCanOpen covers the other side: every
// range a provider rule can state has to be expressible, or a contract cannot
// describe what the plan does.
func TestAPortDeclarationAcceptsWhatAProviderCanOpen(t *testing.T) {
	accepted := map[string]model.PortRange{
		`"0"`:           {From: 0, To: 0},
		`"65535"`:       {From: 65535, To: 65535},
		`"0-65535"`:     {From: 0, To: 65535},
		`"443"`:         {From: 443, To: 443},
		`"  443  "`:     {From: 443, To: 443},
		`"8000 - 8100"`: {From: 8000, To: 8100},
		`"443-443"`:     {From: 443, To: 443},
	}
	for port, want := range accepted {
		t.Run(port, func(t *testing.T) {
			contract, err := contractWith(t, network(`"public_ports": [`+port+`]`))
			if err != nil {
				t.Fatalf("refused %s: %v", port, err)
			}
			ports, _ := contract.PublicPortsOf(intent.FamilyNetwork)
			if len(ports) != 1 || ports[0] != want {
				t.Fatalf("%s loaded as %v, want %v", port, ports, want)
			}
		})
	}
}

// TestTheNetworkFamilyIsKnown keeps the family list and the rules in step. A
// contract naming a family nothing evaluates would appear to constrain something
// unchecked, which is why the list exists.
func TestTheNetworkFamilyIsKnown(t *testing.T) {
	if _, err := contractWith(t, network(`"public_ports": ["443"]`)); err != nil {
		t.Fatalf("the network family is not accepted: %v", err)
	}
	if _, err := contractWith(t, `{
  "schema_version": "1.1", "change_id": "c", "environment": "staging",
  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
  "resources": [{"family": "nonsense", "exposure": "private"}]
}`); err == nil {
		t.Fatal("a family no rule evaluates was accepted")
	}
}

// TestAnEarlierMinorVersionStillLoads keeps the compatibility promise the
// contract document makes: the major version is the boundary, and a 1.0 contract
// is one this build still reads.
func TestAnEarlierMinorVersionStillLoads(t *testing.T) {
	if intent.SchemaVersion != "1.1" {
		t.Fatalf("this build writes contract version %q, want 1.1", intent.SchemaVersion)
	}
	if _, err := contractWith(t, `{
  "schema_version": "1.0", "change_id": "c", "environment": "staging",
  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage", "exposure": "private"}]
}`); err != nil {
		t.Fatalf("a 1.0 contract was refused: %v", err)
	}
}
