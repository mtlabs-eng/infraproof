package intent_test

import (
	"encoding/json"
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

// TestADeeplyNestedContractIsRefusedCheaply is the regression for a defect the
// duplicate-key check introduced.
//
// json.Decoder.Token does not apply the nesting limit that Decode does, so the
// hand-written walk descended where the standard library refuses — and it
// descended expensively. A 600 KB file of nothing but brackets took gigabytes
// and tens of seconds, and the process died abnormally rather than exiting 10.
// The walk runs before the decode, so it removed the standard library's guard
// from the path that runs first.
//
// A contract is a document a human writes. Nothing legitimate is deeper than a
// handful of levels, so the limit costs nothing real and turns an exhaustion
// into an input error.
func TestADeeplyNestedContractIsRefusedCheaply(t *testing.T) {
	cases := map[string]string{
		"nested arrays":       strings.Repeat("[", 300000) + strings.Repeat("]", 300000),
		"nested objects":      strings.Repeat(`{"a":`, 300000) + "1" + strings.Repeat("}", 300000),
		"unbalanced":          strings.Repeat("[", 300000),
		"mixed":               strings.Repeat(`{"a":[`, 200000),
		"just past the limit": strings.Repeat("[", 66) + strings.Repeat("]", 66),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				_, err := intent.Parse([]byte(raw), "contract.json")
				done <- err
			}()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a contract deeper than any real one was accepted")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Parse did not terminate")
			}
		})
	}
}

// TestAContractOfOrdinaryShapeIsNotRefusedForDepth keeps the limit from costing
// anything a user would write. The documented contract nests three levels.
func TestAContractOfOrdinaryShapeIsNotRefusedForDepth(t *testing.T) {
	raw := strings.Replace(valid, `"destructive_changes": "forbidden",`,
		`"destructive_changes": "forbidden",
		 "constraints": {"allowed_regions": ["eu-west-1"], "required_tags": {"owner": "checkout"}},`, 1)

	if _, err := intent.Parse([]byte(raw), "contract.json"); err != nil {
		t.Fatalf("an ordinary contract was rejected: %v", err)
	}
}

// TestKeysThatFoldTogetherAreRejected closes a contract that says two things in
// one field and is read as saying the second.
//
// encoding/json matches a struct tag case-insensitively, so "Exposure" fills
// the field "exposure" names. DisallowUnknownFields does not fire, because a
// field was matched. The duplicate walk compared exact bytes and saw two
// different keys. A contract declaring private exposure and then public was
// therefore read as declaring public, which downgrades a proven public bucket
// from a block to a warning.
//
// The walk now refuses any two keys the decoder would fold together, which is
// the same rule it already applied to keys spelled identically, for the same
// reason: they either agree and one is noise, or disagree and neither can be
// applied.
func TestKeysThatFoldTogetherAreRejected(t *testing.T) {
	cases := map[string]string{
		"a folded exposure": strings.Replace(valid,
			`"exposure": "private"`, `"exposure": "private", "Exposure": "public"`, 1),
		"a folded envelope field": strings.Replace(valid,
			`"environment": "staging",`, `"environment": "staging", "Environment": "production",`, 1),
		"a folded destructive policy": strings.Replace(valid,
			`"destructive_changes": "forbidden",`,
			`"destructive_changes": "forbidden", "DESTRUCTIVE_CHANGES": "allowed_with_warning",`, 1),
		"a folded schema version": strings.Replace(valid,
			`"schema_version": "1.0",`, `"schema_version": "1.0", "Schema_Version": "9.0",`, 1),
		// Not a matter of case. encoding/json folds with unicode.SimpleFold,
		// under which the long s folds with s; strings.ToLower does not. A
		// rule that restates the decoder's relation rather than calling it
		// gets one that is almost the same, and the gap is permissive.
		"a fold that is not a case change": strings.Replace(valid,
			`"exposure": "private"`,
			`"exposure": "private", "expo`+"\u017F"+`ure": "public"`, 1),
		"a fold in an envelope field": strings.Replace(valid,
			`"destructive_changes": "forbidden",`,
			`"destructive_changes": "forbidden", "de`+"\u017F"+`tructive_changes": "allowed_with_warning",`, 1),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == valid {
				t.Fatal("the test did not change the contract")
			}
			_, err := intent.Parse([]byte(raw), "contract.json")
			if err == nil {
				t.Fatal("a contract naming one field twice was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "more than once") {
				t.Errorf("the error does not name the problem: %v", err)
			}
		})
	}
}

// TestTagsDifferingOnlyInCaseAreTwoTags keeps the folding rule off the one
// place a contract carries names rather than fields. Cloud tag keys are
// case-sensitive, so "Owner" and "owner" are two tags, and refusing them would
// reject a contract that says something perfectly ordinary.
func TestTagsDifferingOnlyInCaseAreTwoTags(t *testing.T) {
	raw := strings.Replace(valid, `"destructive_changes": "forbidden",`,
		`"destructive_changes": "forbidden",
		 "constraints": {"required_tags": {"Owner": "checkout", "owner": "payments"}},`, 1)

	contract, err := intent.Parse([]byte(raw), "contract.json")
	if err != nil {
		t.Fatalf("two tags differing in case were rejected: %v", err)
	}
	if contract.Constraints.RequiredTags == nil || len(*contract.Constraints.RequiredTags) != 2 {
		t.Fatalf("required tags = %v, want both", contract.Constraints.RequiredTags)
	}
}

// TestSchemaVersionMatchesTheBundlesRule keeps the contract's version check as
// strict as the one the Evidence Bundle applies to its own. strconv.Atoi
// accepts a sign and leading zeros; a version is digits.
func TestSchemaVersionMatchesTheBundlesRule(t *testing.T) {
	for version, accepted := range map[string]bool{
		"1.0":   true,
		"1.12":  true,
		"+1.0":  false,
		"001.0": false,
		"1.x.y": false,
		// Surrounding space is trimmed at load, as it is for every other
		// field a contract carries; a version with a stray space is a typo
		// rather than a different version.
		" 1.0": true,
		"1.0 ": true,
	} {
		t.Run(version, func(t *testing.T) {
			raw := strings.Replace(valid, `"schema_version": "1.0"`,
				`"schema_version": "`+version+`"`, 1)
			_, err := intent.Parse([]byte(raw), "contract.json")
			if accepted && err != nil {
				t.Fatalf("version %q was rejected: %v", version, err)
			}
			if !accepted && err == nil {
				t.Fatalf("version %q was accepted", version)
			}
		})
	}
}

// TestAYAMLNameIsRefusedWhateverIsInside keeps the refusal matching what the
// documentation promises. A flow-style YAML document begins with "{" and
// reaches the JSON decoder, where it fails as a syntax error — which is the
// puzzle the refusal exists to prevent.
func TestAYAMLNameIsRefusedWhateverIsInside(t *testing.T) {
	for _, name := range []string{"intent.yaml", "intent.yml", "INTENT.YAML", "a/b/c.yaml"} {
		t.Run(name, func(t *testing.T) {
			// Flow style: valid YAML, and valid-looking JSON openers.
			raw := `{schema_version: "1.0", change_id: c}`

			_, err := intent.Parse([]byte(raw), name)
			if err == nil {
				t.Fatal("a YAML file was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "yaml") {
				t.Errorf("the error does not say the format is the problem: %v", err)
			}
		})
	}
}

// TestEveryJSONDocumentReachesTheDecoder holds the boundary between "not JSON"
// and "not a contract" where the decoder puts it.
//
// An earlier form classified the document from its first byte, which restated
// the decoder's grammar. This project has been caught three times by the gap in
// an "almost", so the question is asked of the thing that defines the answer.
func TestEveryJSONDocumentReachesTheDecoder(t *testing.T) {
	// Valid JSON that is not a contract must be refused as a contract, with
	// the decoder's own complaint, never as a format problem.
	for name, raw := range map[string]string{
		"a bare number":        `42`,
		"a bare string":        `"hello"`,
		"a bare true":          `true`,
		"a bare null":          `null`,
		"an array":             `[1, 2, 3]`,
		"a negative number":    `-1`,
		"an empty object":      `{}`,
		"an object of nothing": `{"schema_version": "1.0"}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := intent.Parse([]byte(raw), "contract.json")
			if err == nil {
				t.Fatal("a JSON document that is not a contract was accepted")
			}
			if strings.Contains(strings.ToLower(err.Error()), "yaml") {
				t.Errorf("valid JSON was reported as a format problem: %v", err)
			}
		})
	}

	// A document that does not begin as JSON is refused as a format problem.
	// One that opens with "{" is indistinguishable from JSON at its first
	// token — flow-style YAML and a single-quoted object both do — so those
	// get the decoder's message and its byte offset, which is the only
	// actionable thing to say about a typo. The filename is the other gate.
	for name, raw := range map[string]string{
		"a plain mapping":   "schema_version: \"1.0\"\n",
		"a document marker": "---\nschema_version: \"1.0\"\n",
		"a top-level list":  "- schema_version: \"1.0\"\n",
		"a directive":       "%YAML 1.2\n---\na: b\n",
		"a comment":         "# a contract\na: b\n",
		"an unquoted word":  "hello",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := intent.Parse([]byte(raw), "contract.txt")
			if err == nil {
				t.Fatal("a document that is not JSON was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "json") {
				t.Errorf("the error does not say the format is the problem: %v", err)
			}
		})
	}
}

// TestAMergedFieldIsNamedTwiceToo covers the half of the decoder's relation the
// reversal oracle cannot see.
//
// Reversal detects a field the decoder overwrites: the last spelling wins, so
// swapping the order swaps the answer. It detects nothing where the decoder
// merges — an array element, a pointer already followed, a map already made —
// because two spellings writing to different leaves give the same result in
// either order.
//
// A contract naming "resources" twice was therefore accepted as the union of
// both, including one that was invalid written once: the exposure the first
// spelling omitted arrived from the second, and a bucket with a public ACL
// came back PASS.
func TestAMergedFieldIsNamedTwiceToo(t *testing.T) {
	cases := map[string]string{
		"a slice merged by element": `{
		  "schema_version": "1.0", "change_id": "c", "environment": "staging",
		  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
		  "resources": [{"family": "object_storage", "purpose": "assets"}],
		  "Resources": [{"exposure": "public"}]}`,

		"a pointer already followed": `{
		  "schema_version": "1.0", "change_id": "c", "environment": "staging",
		  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
		  "resources": [{"family": "object_storage", "exposure": "private"}],
		  "constraints": {"allowed_regions": ["eu-west-1"]},
		  "Constraints": {"required_tags": {"owner": "checkout"}}}`,

		"a map already made": `{
		  "schema_version": "1.0", "change_id": "c", "environment": "staging",
		  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
		  "resources": [{"family": "object_storage", "exposure": "private"}],
		  "constraints": {"required_tags": {"a": "1"}, "Required_Tags": {"b": "2"}}}`,

		"a slice of clouds": `{
		  "schema_version": "1.0", "change_id": "c", "environment": "staging",
		  "allowed_clouds": ["aws"], "Allowed_Clouds": ["gcp"],
		  "destructive_changes": "forbidden",
		  "resources": [{"family": "object_storage", "exposure": "private"}]}`,

		"a fold that is not a case change": `{
		  "schema_version": "1.0", "change_id": "c", "environment": "staging",
		  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
		  "resources": [{"family": "object_storage", "purpose": "assets"}],
		  "re` + "ſ" + `ources": [{"exposure": "public"}]}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := intent.Parse([]byte(raw), "contract.json")
			if err == nil {
				t.Fatal("a contract naming one field twice was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), "more than once") {
				t.Errorf("the error does not name the problem: %v", err)
			}
		})
	}
}

// TestAMistypedContractKeepsTheDecodersMessage separates a format question
// from a typo.
//
// A document that does not begin as JSON is a format problem, and saying so
// beats a byte offset. A document that begins as JSON and then goes wrong is a
// typo, and there the offset is the only actionable thing in the message. An
// earlier form reported the four commonest ways to mistype JSON as "this is
// not JSON; YAML is not supported", which sends the author to a question they
// do not have.
func TestAMistypedContractKeepsTheDecodersMessage(t *testing.T) {
	for name, raw := range map[string]string{
		"a trailing comma":     `{"schema_version": "1.0",}`,
		"a truncated document": `{"schema_version": "1.0"`,
		"a missing comma":      `{"schema_version": "1.0" "change_id": "c"}`,
		"a stray character":    `{"schema_version": "1.0"} x`,
		"flow-style YAML":      `{schema_version: "1.0", change_id: c}`,
		"single quotes":        `{'schema_version': '1.0'}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := intent.Parse([]byte(raw), "contract.json")
			if err == nil {
				t.Fatal("a malformed document was accepted")
			}
			if strings.Contains(strings.ToLower(err.Error()), "yaml") {
				t.Errorf("a mistyped JSON contract was reported as a format problem: %v", err)
			}
		})
	}
}

// TestADocumentNestedTooDeepSaysSo keeps the bound that protects the rewrite
// from being one that tells nobody. Swallowing it left the reader with whatever
// the decoder said next, which was an internal Go type name.
func TestADocumentNestedTooDeepSaysSo(t *testing.T) {
	for name, raw := range map[string]string{
		"nested arrays":  strings.Repeat("[", 5000) + strings.Repeat("]", 5000),
		"nested objects": `{"a":` + strings.Repeat(`{"a":`, 200) + "1" + strings.Repeat("}", 201),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := intent.Parse([]byte(raw), "contract.json")
			if err == nil {
				t.Fatal("a document deeper than any real one was accepted")
			}
			if !strings.Contains(err.Error(), "levels deep") {
				t.Errorf("the error does not say what is wrong: %v", err)
			}
			if strings.Contains(err.Error(), "wireContract") {
				t.Errorf("an internal type name reached the user: %v", err)
			}
		})
	}
}

// TestManyFoldedTagNamesCostLittle keeps a valid contract from paying for the
// check that clears it.
//
// Cloud tag keys are case-sensitive, so a contract may carry many that fold
// together, and docs/INTENT-CONTRACT.md says so. Confirming each collision
// separately rewrote and decoded the whole document again, which made such a
// contract quadratic in its own size: 86 KB took nine seconds. Whether a
// position matches fields or holds names is a property of the position, so one
// probe answers for every collision in it.
func TestManyFoldedTagNamesCostLittle(t *testing.T) {
	tags := make(map[string]string, 4000)
	for i := range 4000 {
		key := []byte("environmenttagx")
		for bit := range 15 {
			if i&(1<<bit) != 0 {
				key[bit] -= 'a' - 'A'
			}
		}
		tags[string(key)] = "v"
	}
	encoded, err := json.Marshal(map[string]any{
		"schema_version":      "1.0",
		"change_id":           "c",
		"environment":         "staging",
		"allowed_clouds":      []string{"aws"},
		"destructive_changes": "forbidden",
		"resources":           []map[string]string{{"family": "object_storage", "exposure": "private"}},
		"constraints":         map[string]any{"required_tags": tags},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := intent.Parse(encoded, "contract.json")
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("a valid contract of many case-spelled tag names was rejected: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("Parse did not finish in five seconds on %d bytes", len(encoded))
	}
}

// TestAnInternalTypeNameNeverReachesTheUser keeps a Go implementation detail
// out of a message a person has to act on. A document that is JSON and is not
// an object was reported as failing to unmarshal into intent.wireContract.
func TestAnInternalTypeNameNeverReachesTheUser(t *testing.T) {
	for _, raw := range []string{`[1,2]`, `"x"`, `42`, `true`, `null`, `{"schema_version": 1}`,
		strings.Repeat("[", 200) + strings.Repeat("]", 200)} {
		t.Run(raw[:min(len(raw), 12)], func(t *testing.T) {
			_, err := intent.Parse([]byte(raw), "contract.json")
			if err == nil {
				t.Fatal("a document that is not a contract was accepted")
			}
			if strings.Contains(err.Error(), "wireContract") {
				t.Errorf("an internal type name reached the user: %v", err)
			}
		})
	}
}

// TestAnEmptyConstraintIsStillAConstraint holds the sentence in
// docs/INTENT-CONTRACT.md: a restriction the contract states and nothing
// enforces cannot sit silently beside a PASS.
//
// An empty allow-list is the most restrictive thing the field can say — no
// region is permitted — and reading presence off the length reported it as
// absent. Every other field in the contract distinguishes omitted from empty
// through a pointer; these two lost the distinction exactly where the document
// depends on it.
func TestAnEmptyConstraintIsStillAConstraint(t *testing.T) {
	cases := map[string]struct {
		document string
		want     string
	}{
		"an empty allow-list":  {`{"allowed_regions": []}`, "constraints.allowed_regions"},
		"an empty tag map":     {`{"required_tags": {}}`, "constraints.required_tags"},
		"a stated allow-list":  {`{"allowed_regions": ["eu-west-1"]}`, "constraints.allowed_regions"},
		"a stated tag map":     {`{"required_tags": {"owner": "checkout"}}`, "constraints.required_tags"},
		"no constraints block": {``, ""},
		"an empty block":       {`{}`, ""},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body := `{"schema_version": "1.0", "change_id": "c", "environment": "staging",
			          "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
			          "resources": [{"family": "object_storage", "exposure": "private"}]`
			if tc.document != "" {
				body += `, "constraints": ` + tc.document
			}
			body += "}"

			contract, err := intent.Parse([]byte(body), "c.json")
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}

			stated := contract.Unevaluated()
			switch {
			case tc.want == "" && len(stated) != 0:
				t.Fatalf("unevaluated = %v; the contract stated no constraint", stated)
			case tc.want == "":
			case len(stated) != 1 || stated[0] != tc.want:
				t.Fatalf("unevaluated = %v, want [%s]", stated, tc.want)
			}
		})
	}
}

// TestSurroundingSpaceIsNotPartOfAValue keeps one rule for every string the
// contract carries.
//
// derefString trims, so schema_version, environment and family all accept
// surrounding space. allowed_clouds is a list and went through no such thing,
// so a contract this build would otherwise accept was refused for a space —
// and a reader was told their cloud is unrecognized when the name was right.
func TestSurroundingSpaceIsNotPartOfAValue(t *testing.T) {
	contract, err := intent.Parse([]byte(`{
	  "schema_version": " 1.0 ", "change_id": " c ", "environment": " staging ",
	  "allowed_clouds": [" aws "], "destructive_changes": " forbidden ",
	  "resources": [{"family": " object_storage ", "exposure": " private "}]
	}`), "c.json")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if len(contract.AllowedClouds) != 1 || contract.AllowedClouds[0] != "aws" {
		t.Errorf("allowed clouds = %q, want [aws]", contract.AllowedClouds)
	}
}

// TestAnErrorQuotesAValueWithoutReprintingTheFile keeps a validation message
// readable.
//
// Naming the offending value is what makes a message actionable, and the
// values are the reader's own contract rather than plan data. The length is
// theirs too: a single entry may be a megabyte, and a message is written to a
// terminal.
func TestAnErrorQuotesAValueWithoutReprintingTheFile(t *testing.T) {
	huge := strings.Repeat("a", 100000)
	_, err := intent.Parse([]byte(`{
	  "schema_version": "1.0", "change_id": "c", "environment": "staging",
	  "allowed_clouds": ["`+huge+`"], "destructive_changes": "forbidden",
	  "resources": [{"family": "object_storage", "exposure": "private"}]
	}`), "c.json")
	if err == nil {
		t.Fatal("a cloud nobody supports was accepted")
	}

	if len(err.Error()) > 1000 {
		t.Errorf("the message is %d bytes; it reprints the contract rather than quoting it",
			len(err.Error()))
	}
	if !strings.Contains(err.Error(), "aaa") {
		t.Errorf("the message does not say which value is wrong: %q", err.Error())
	}
}
