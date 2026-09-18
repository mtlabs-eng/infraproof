package intent_test

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mtlabs-eng/infraproof/internal/intent"
)

const valid = `{
  "schema_version": "1.0",
  "change_id": "add-private-staging-assets",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage", "exposure": "private", "purpose": "application-assets"}]
}`

// trailingComma matches the comma left behind when the test removes the last
// field of the object.
var trailingComma = regexp.MustCompile(`,\s*\n\s*}`)

func load(t *testing.T, raw string) intent.Contract {
	t.Helper()
	contract, err := intent.Parse([]byte(raw), "intent.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return contract
}

func TestParseReadsEveryField(t *testing.T) {
	contract := load(t, valid)

	if contract.SchemaVersion != "1.0" {
		t.Errorf("schema version = %q", contract.SchemaVersion)
	}
	if contract.ChangeID != "add-private-staging-assets" {
		t.Errorf("change id = %q", contract.ChangeID)
	}
	if contract.Environment != "staging" {
		t.Errorf("environment = %q", contract.Environment)
	}
	if len(contract.AllowedClouds) != 1 || contract.AllowedClouds[0] != "aws" {
		t.Errorf("allowed clouds = %v", contract.AllowedClouds)
	}
	if contract.DestructiveChanges != intent.DestructiveForbidden {
		t.Errorf("destructive changes = %q", contract.DestructiveChanges)
	}
	exposure, declared := contract.ExposureOf(intent.FamilyObjectStorage)
	if !declared || exposure != intent.ExposurePrivate {
		t.Errorf("exposure = %q declared=%v", exposure, declared)
	}
	if contract.Source != "intent.json" {
		t.Errorf("source = %q", contract.Source)
	}
}

// TestDigestIsOverTheExactBytes keeps the contract identifiable without copying
// it into output. Two contracts that differ only in whitespace are different
// files, and a report that claims to have compared against one must not be
// satisfiable by the other.
func TestDigestIsOverTheExactBytes(t *testing.T) {
	first := load(t, valid)
	if !strings.HasPrefix(first.Digest, "sha256:") {
		t.Fatalf("digest = %q, want a sha256 prefix", first.Digest)
	}

	spaced := load(t, valid+"\n")
	if spaced.Digest == first.Digest {
		t.Fatal("two different files produced one digest")
	}

	again := load(t, valid)
	if again.Digest != first.Digest {
		t.Fatal("the same bytes produced two digests")
	}
}

// TestAnOmittedRequiredFieldIsInvalid is the contract's own form of the rule
// the mappers obey: absence is not a default. A contract that did not say what
// it permits must not be read as permitting anything.
func TestAnOmittedRequiredFieldIsInvalid(t *testing.T) {
	required := map[string]string{
		"schema_version":      `"schema_version": "1.0",`,
		"change_id":           `"change_id": "add-private-staging-assets",`,
		"environment":         `"environment": "staging",`,
		"allowed_clouds":      `"allowed_clouds": ["aws"],`,
		"destructive_changes": `"destructive_changes": "forbidden",`,
		"resources":           `"resources": [{"family": "object_storage", "exposure": "private", "purpose": "application-assets"}]`,
	}

	for field, line := range required {
		t.Run(field, func(t *testing.T) {
			raw := strings.Replace(valid, line, "", 1)
			if raw == valid {
				t.Fatalf("the test did not remove %s", field)
			}
			// Removing the last field leaves a trailing comma, which would
			// fail as a syntax error and prove nothing about the field.
			raw = trailingComma.ReplaceAllString(raw, "\n}")

			_, err := intent.Parse([]byte(raw), "intent.json")
			if err == nil {
				t.Fatalf("a contract without %s was accepted", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("the error does not name the missing field: %v", err)
			}
		})
	}
}

// TestAnEmptyExposureIsNotUnspecified separates two different things a contract
// can say. "unspecified" is a decision the author made; an omitted exposure is
// a contract that never addressed the question, and reading one as the other
// would silence a rule on the author's behalf.
func TestAnEmptyExposureIsNotUnspecified(t *testing.T) {
	raw := strings.Replace(valid, `"exposure": "private", `, "", 1)

	_, err := intent.Parse([]byte(raw), "intent.json")
	if err == nil {
		t.Fatal("a resource without an exposure was accepted")
	}
	if !strings.Contains(err.Error(), "exposure") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

func TestInvalidValuesAreRejected(t *testing.T) {
	cases := map[string]string{
		"an unknown destructive policy": strings.Replace(valid, `"forbidden"`, `"whenever"`, 1),
		"an unknown exposure":           strings.Replace(valid, `"private"`, `"semi-public"`, 1),
		"an unknown family":             strings.Replace(valid, `"object_storage"`, `"databases"`, 1),
		"an unknown cloud":              strings.Replace(valid, `["aws"]`, `["oracle"]`, 1),
		"an empty cloud set":            strings.Replace(valid, `["aws"]`, `[]`, 1),
		"no resources":                  strings.Replace(valid, `"resources": [{"family": "object_storage", "exposure": "private", "purpose": "application-assets"}]`, `"resources": []`, 1),
		"a blank environment":           strings.Replace(valid, `"staging"`, `"   "`, 1),
		"a duplicate family":            strings.Replace(valid, `"resources": [{"family": "object_storage", "exposure": "private", "purpose": "application-assets"}]`, `"resources": [{"family": "object_storage", "exposure": "private"}, {"family": "object_storage", "exposure": "public"}]`, 1),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == valid {
				t.Fatal("the test did not change the contract")
			}
			if _, err := intent.Parse([]byte(raw), "intent.json"); err == nil {
				t.Fatal("an invalid contract was accepted")
			}
		})
	}
}

// TestAnUnrecognizedFieldIsRejected refuses to read a contract partially. A
// field this build does not know may be the one carrying the restriction the
// author cared about, and ignoring it would report a PASS the contract never
// licensed.
func TestAnUnrecognizedFieldIsRejected(t *testing.T) {
	raw := strings.Replace(valid, `"environment": "staging",`,
		`"environment": "staging", "max_cost": 100,`, 1)

	_, err := intent.Parse([]byte(raw), "intent.json")
	if err == nil {
		t.Fatal("a contract with an unrecognized field was accepted")
	}
	if !strings.Contains(err.Error(), "max_cost") {
		t.Errorf("the error does not name the field: %v", err)
	}
}

// TestALaterMajorVersionIsRejected keeps the compatibility boundary at the
// major version. A later minor version may add fields this build ignores
// safely; a later major version may redefine one it thinks it understands.
func TestSchemaVersionCompatibility(t *testing.T) {
	cases := map[string]bool{
		"1.0": true,
		"1.4": true,
		"2.0": false,
		"0.9": false,
		"1":   false,
		"":    false,
		"one": false,
	}

	for version, accepted := range cases {
		t.Run(version, func(t *testing.T) {
			raw := strings.Replace(valid, `"schema_version": "1.0"`,
				`"schema_version": "`+version+`"`, 1)
			_, err := intent.Parse([]byte(raw), "intent.json")
			if accepted && err != nil {
				t.Fatalf("version %q was rejected: %v", version, err)
			}
			if !accepted && err == nil {
				t.Fatalf("version %q was accepted", version)
			}
		})
	}
}

// TestYAMLIsRefusedClearly keeps a deferred format from failing as a puzzle.
// This build has no YAML reader, and a YAML file handed to a JSON decoder
// produces a syntax error that tells the reader nothing about why.
func TestYAMLIsRefusedClearly(t *testing.T) {
	raw := `schema_version: "1.0"
change_id: add-private-staging-assets
environment: staging
`
	// The source is deliberately not named "intent.yaml": the path appears in
	// every error, so naming it there would make the assertion true whatever
	// the code did. An earlier form of this test did exactly that, and
	// disabling the detection outright left it green.
	_, err := intent.Parse([]byte(raw), "contract.txt")
	if err == nil {
		t.Fatal("a YAML contract was accepted")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "yaml") {
		t.Errorf("the error does not say the format is the problem: %v", err)
	}
}

// TestYAMLIsRecognizedInTheFormsItIsWritten covers what a user actually hands
// over. The document marker is the case that matters most: it is conventional,
// it begins with "-", and a detector that treats "-" as a JSON number opener
// lets it through to fail as "invalid character '-' in numeric literal" — the
// exact puzzle the refusal exists to prevent.
func TestYAMLIsRecognizedInTheFormsItIsWritten(t *testing.T) {
	cases := map[string]string{
		"a plain mapping":      "schema_version: \"1.0\"\nchange_id: c\n",
		"a document marker":    "---\nschema_version: \"1.0\"\nchange_id: c\n",
		"a marker with spaces": "  ---  \nschema_version: \"1.0\"\n",
		"a leading comment":    "# the contract\nschema_version: \"1.0\"\n",
		"a directive":          "%YAML 1.2\n---\nschema_version: \"1.0\"\n",
		"a top-level list":     "- schema_version: \"1.0\"\n",
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := intent.Parse([]byte(raw), "contract.txt")
			if err == nil {
				t.Fatal("a YAML contract was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "yaml") {
				t.Errorf("the error does not say the format is the problem: %v", err)
			}
		})
	}
}

// TestJSONIsNotMistakenForYAML keeps the refusal from costing the format this
// build does read. A detector that is too eager turns a valid contract into a
// lecture about a format the user never used.
func TestJSONIsNotMistakenForYAML(t *testing.T) {
	cases := map[string]string{
		"as written":             valid,
		"with leading space":     "   " + valid,
		"with a leading newline": "\n" + valid,
		"with a byte order mark": "\ufeff" + valid,
		"compact":                `{"schema_version":"1.0","change_id":"c","environment":"e","allowed_clouds":["aws"],"destructive_changes":"forbidden","resources":[{"family":"object_storage","exposure":"private"}]}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := intent.Parse([]byte(raw), "contract.txt"); err != nil {
				t.Fatalf("valid JSON was rejected: %v", err)
			}
		})
	}
}

// TestADuplicateKeyIsRejected refuses a contract that says two things in one
// field. encoding/json takes the last occurrence silently, so a contract
// declaring private exposure and then public is read as declaring public, which
// downgrades a proven public bucket from a block to a warning.
//
// Validation already refuses two resources entries for one family, on the
// reasoning that they either agree, and one is noise, or disagree, and neither
// can be applied. A duplicate key is the same hazard one level down.
func TestADuplicateKeyIsRejected(t *testing.T) {
	cases := map[string]string{
		"a repeated scalar": strings.Replace(valid, `"environment": "staging",`,
			`"environment": "staging", "environment": "production",`, 1),
		"a repeated array": strings.Replace(valid, `"allowed_clouds": ["aws"],`,
			`"allowed_clouds": ["aws"], "allowed_clouds": ["gcp"],`, 1),
		"a repeated object member": strings.Replace(valid,
			`{"family": "object_storage", "exposure": "private", "purpose": "application-assets"}`,
			`{"family": "object_storage", "exposure": "private", "exposure": "public"}`, 1),
		"agreeing duplicates": strings.Replace(valid, `"environment": "staging",`,
			`"environment": "staging", "environment": "staging",`, 1),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == valid {
				t.Fatal("the test did not change the contract")
			}
			_, err := intent.Parse([]byte(raw), "contract.json")
			if err == nil {
				t.Fatal("a contract with a duplicate key was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "more than once") {
				t.Errorf("the error does not name the problem: %v", err)
			}
		})
	}
}

// TestTrailingContentIsRejected mirrors the plan parser. A file holding a
// contract followed by anything else is not a contract, and reading the first
// document and discarding the rest would silently ignore whatever came after.
func TestTrailingContentIsRejected(t *testing.T) {
	if _, err := intent.Parse([]byte(valid+" {}"), "intent.json"); err == nil {
		t.Fatal("trailing content was accepted")
	}
}

// TestConstraintsAreLoadedButReportedAsUnevaluated is the product-level form of
// the rule the mappers obey. A restriction written in the contract and checked
// by nothing must not sit silently beside a PASS.
func TestConstraintsAreLoadedButReportedAsUnevaluated(t *testing.T) {
	raw := strings.Replace(valid, `"destructive_changes": "forbidden",`,
		`"destructive_changes": "forbidden",
		 "constraints": {"allowed_regions": ["eu-west-1"], "required_tags": {"owner": "checkout"}},`, 1)

	contract := load(t, raw)
	if contract.Constraints == nil {
		t.Fatal("constraints were not loaded")
	}

	unevaluated := contract.Unevaluated()
	if len(unevaluated) != 2 {
		t.Fatalf("unevaluated = %v, want both constraints reported", unevaluated)
	}
	for _, want := range []string{"constraints.allowed_regions", "constraints.required_tags"} {
		var found bool
		for _, got := range unevaluated {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was loaded but not reported as unevaluated", want)
		}
	}

	// A contract asking for nothing this build cannot check reports nothing.
	if got := load(t, valid).Unevaluated(); len(got) != 0 {
		t.Errorf("unevaluated = %v, want none", got)
	}
}

// TestParseDoesNotPanicOnHostileInput keeps a malformed contract an input error
// rather than a crash. A contract is a file a human edits, and the most likely
// malformed one is a typo, not an attack.
func TestParseDoesNotPanicOnHostileInput(t *testing.T) {
	cases := []string{
		"", " ", "null", "[]", `""`, "0", "{", `{"resources": null}`,
		`{"resources": [null]}`, `{"allowed_clouds": [null]}`,
		`{"schema_version": 1.0}`, `{"constraints": {"required_tags": {"a": null}}}`,
		"\x00", strings.Repeat("[", 5000),
	}

	for _, raw := range cases {
		t.Run(strings.ToValidUTF8(raw[:min(len(raw), 20)], ""), func(t *testing.T) {
			if _, err := intent.Parse([]byte(raw), "intent.json"); err == nil {
				t.Fatalf("hostile input was accepted: %q", raw)
			}
		})
	}
}

func TestParseRejectsAnUnreadableFile(t *testing.T) {
	if _, err := intent.Load("testdata/does-not-exist.json"); err == nil {
		t.Fatal("a missing file was accepted")
	}
}

// TestAnInvalidContractIsRejectedTheSameWayTwice keeps diagnostics
// deterministic. Go iterates a map in a random order, and a tool whose selling
// point is that its output is a function of its input must not describe one
// contract two ways.
func TestAnInvalidContractIsRejectedTheSameWayTwice(t *testing.T) {
	raw := strings.Replace(valid, `"destructive_changes": "forbidden",`,
		`"destructive_changes": "forbidden",
		 "constraints": {"required_tags": {"a": "", "b": "", "c": "", "d": "", "e": "", "f": ""}},`, 1)

	_, first := intent.Parse([]byte(raw), "contract.json")
	if first == nil {
		t.Fatal("a contract with blank required tags was accepted")
	}
	for range 50 {
		_, again := intent.Parse([]byte(raw), "contract.json")
		if again == nil || again.Error() != first.Error() {
			t.Fatalf("one contract produced two diagnostics:\n %v\n %v", first, again)
		}
	}
}

// TestParseTerminatesOnEveryInput is the regression for a hang the fuzz target
// found within ten seconds of first being run.
//
// The duplicate-key walk skipped a token it had failed to read and carried on.
// A json.Decoder in an error state answers More with true indefinitely, so an
// unterminated string inside an array spun forever — the worst failure mode
// available to a command a pipeline waits on, because it never reports
// anything at all.
func TestParseTerminatesOnEveryInput(t *testing.T) {
	cases := map[string]string{
		"an unterminated string in an array": `{"resources": [{"family": "object_storage", "exposure": "priva_st}]}`,
		"an unterminated string at the top":  `{"change_id": "abc`,
		"an unclosed array":                  `{"allowed_clouds": ["aws"`,
		"an unclosed nested object":          `{"constraints": {"required_tags": {"a": "b"`,
		"a truncated array of objects":       `{"resources": [{`,
		"an array of unterminated strings":   `{"allowed_clouds": ["a`,
		"a deeply nested truncation":         `{"a": [[[[[[[[[[`,
		"garbage after a well-formed prefix": `{"change_id": "c"} \x00`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				if _, err := intent.Parse([]byte(raw), "contract.json"); err == nil {
					t.Error("malformed input was accepted")
				}
			}()

			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("Parse did not terminate")
			}
		})
	}
}
