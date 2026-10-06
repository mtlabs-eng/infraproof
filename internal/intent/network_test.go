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

// loadWithPorts loads a contract declaring one port expression.
func loadWithPorts(t *testing.T, declared string) (intent.Contract, error) {
	t.Helper()
	return contractWith(t, network(`"public_ports": ["`+declared+`"]`))
}

// loadWithPortList loads a contract declaring several.
func loadWithPortList(t *testing.T, declared []string) (intent.Contract, error) {
	t.Helper()
	quoted := make([]string, 0, len(declared))
	for _, one := range declared {
		quoted = append(quoted, `"`+one+`"`)
	}
	return contractWith(t, network(`"public_ports": [`+strings.Join(quoted, ", ")+`]`))
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

// TestADiagnosticQuotesWhatTheAuthorWrote covers the port parser's messages,
// which sent a reader to look at text they did not write.
//
// "1-2-3" is cut at the first dash, so the second half reaches parsePort as
// "2-3" and the message quotes that. A reader searches their contract for "2-3"
// and does not find it. The declaration is one token and a diagnostic may only
// quote tokens the author wrote.
//
// Naming the failing end as well is help rather than noise, so the requirement
// is that the declaration appears, not that the fragment does not.
//
// The assertion is made against the diagnostic and not the whole error. The
// first version of this test checked Contains(err, "1-2-3") and passed against
// the broken code, because t.TempDir() puts the subtest's name in the path and
// the path is in the message -- the test was reading its own name back. That is
// the defect class this repository keeps finding, one layer up.
func TestADiagnosticQuotesWhatTheAuthorWrote(t *testing.T) {
	cases := map[string]string{
		"1-2-3":     `"1-2-3"`,
		"8000-abc":  `"8000-abc"`,
		"abc-8000":  `"abc-8000"`,
		"1-x-3":     `"1-x-3"`,
		"00443":     `"00443"`,
		"443-00444": `"443-00444"`,
		"8100-8000": `"8100-8000"`,
		"70000":     `70000`,
	}

	for declared, written := range cases {
		t.Run(declared, func(t *testing.T) {
			_, err := loadWithPorts(t, declared)
			if err == nil {
				t.Fatalf("%q loaded", declared)
			}
			message := diagnostic(t, err)
			if !strings.Contains(message, written) {
				t.Errorf("the message does not name what was written, so a reader cannot find it:"+
					"\n  message: %s\n  written: %s", message, written)
			}
		})
	}
}

// diagnostic returns the part of a load error after the file path, because the
// path carries the test's own name and asserting on the whole message means
// asserting on that.
func diagnostic(t *testing.T, err error) string {
	t.Helper()
	text := err.Error()
	_, after, found := strings.Cut(text, ".json: ")
	if !found {
		t.Fatalf("the error does not name a contract file, so its diagnostic cannot be separated "+
			"from its path: %q", text)
	}
	return after
}

// TestAPortSpelledWithALeadingZeroIsRefused covers the spelling this package
// refuses in a version component and accepted in a port.
//
// "00443" loaded as 443 through strconv.Atoi. isPlainNumber refuses a leading
// zero in a schema version and says why: a number with one is a different
// spelling of the same value, and accepting both means two contracts that are
// not byte-identical declare the same thing -- which a digest over the
// declaration cannot see. A port is the same question.
func TestAPortSpelledWithALeadingZeroIsRefused(t *testing.T) {
	for _, declared := range []string{"00443", "0443", "08000-08100", "443-00444"} {
		t.Run(declared, func(t *testing.T) {
			if _, err := loadWithPorts(t, declared); err == nil {
				t.Fatalf("%q loaded, so two spellings of one declaration are both valid", declared)
			}
		})
	}

	// Zero itself is a port number and is written with one digit.
	if _, err := loadWithPorts(t, "0"); err != nil {
		t.Fatalf("port 0 was refused: %v", err)
	}
}

// TestADeclarationThatRepeatsItselfIsRefused covers what a contract says twice.
//
// A declaration of 443 four times, or of two overlapping ranges, is a
// declaration whose rendered Expected fact reads "443, 443, 443, 443". The
// contract is the author's statement of intent and a repeated entry is a mistake
// in it, not a statement -- and this package already refuses a repeated family
// and a repeated cloud for the same reason.
func TestADeclarationThatRepeatsItselfIsRefused(t *testing.T) {
	for name, declared := range map[string][]string{
		"the same port twice":        {"443", "443"},
		"the same port with a space": {"443", " 443"},
		"a port inside a range":      {"8000-8100", "8050"},
		"two overlapping ranges":     {"80-100", "90-200"},
		"two touching ranges":        {"80-100", "101-200"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadWithPortList(t, declared); err == nil {
				t.Fatalf("%v loaded, so the contract declares the same port more than once", declared)
			}
		})
	}

	// Distinct ports and ranges that do not meet are the ordinary case and must
	// keep loading.
	for name, declared := range map[string][]string{
		"two ports":             {"80", "443"},
		"two separated ranges":  {"80-100", "200-300"},
		"a port beside a range": {"22", "8000-8100"},
		"the whole port space":  {"0-65535"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadWithPortList(t, declared); err != nil {
				t.Fatalf("%v was refused: %v", declared, err)
			}
		})
	}
}

// TestAnEarlierVersionCarryingALaterFieldIsLoaded records a decision that was
// taken by omission.
//
// A 1.0 contract declaring public_ports loads, and the field changes the verdict:
// public_ports: ["22"] in a document claiming to predate the field turns a WARN
// into a PASS. Nothing refused it and nothing said it was meant to be accepted.
//
// Accepting it is right. The field is an explicit statement by an author, the
// schema version says which fields a reader may expect rather than which ones are
// forbidden, and refusing a declaration somebody wrote on purpose would be
// refusing intent on a technicality -- while silently dropping it would be worse
// still, because the contract would then permit less than its author wrote with
// nothing said about it.
//
// The compatibility rule this follows is the one the Evidence Bundle already
// has: a reader accepts a document of its own major version and ignores nothing
// it understands.
func TestAnEarlierVersionCarryingALaterFieldIsLoaded(t *testing.T) {
	contract, err := contractWith(t, `{
  "schema_version": "1.0",
  "change_id": "c",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "network", "public_ports": ["443"]}]
}`)
	if err != nil {
		t.Fatalf("a 1.0 contract declaring public_ports was refused: %v", err)
	}

	ports, declared := contract.PublicPortsOf(intent.FamilyNetwork)
	if !declared {
		t.Fatal("the declaration was dropped, so the contract permits less than its author wrote")
	}
	if len(ports) != 1 || ports[0] != (model.PortRange{From: 443, To: 443}) {
		t.Fatalf("ports = %v, want 443", ports)
	}
}

// TestALaterMinorVersionCarryingTheSameFieldIsLoaded is the forward direction of
// the same rule, which the compatibility note already covered: a reader of 1.1
// accepts 1.9 and reads the fields it knows.
func TestALaterMinorVersionCarryingTheSameFieldIsLoaded(t *testing.T) {
	contract, err := contractWith(t, `{
  "schema_version": "1.9",
  "change_id": "c",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "network", "public_ports": ["443"]}]
}`)
	if err != nil {
		t.Fatalf("a 1.9 contract was refused: %v", err)
	}
	if _, declared := contract.PublicPortsOf(intent.FamilyNetwork); !declared {
		t.Fatal("the declaration was dropped")
	}
}
