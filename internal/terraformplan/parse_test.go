package terraformplan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEveryValidFixtureParses walks the fixture directory so that adding a
// fixture cannot silently go untested.
func TestEveryValidFixtureParses(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}

	// These fixtures exist to be rejected.
	rejected := map[string]bool{"malformed": true, "unsupported-version": true}

	seen := 0
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || rejected[name] {
			continue
		}
		seen++
		t.Run(name, func(t *testing.T) {
			plan, err := Parse(fixtureBytes(t, name))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if plan.FormatVersion == "" {
				t.Fatal("format version was not captured")
			}
			if !strings.HasPrefix(plan.Digest, "sha256:") {
				t.Fatalf("digest %q is not prefixed with sha256:", plan.Digest)
			}
			for i, change := range plan.ResourceChanges {
				if change.Address == "" {
					t.Fatalf("resource change %d has no address", i)
				}
				if len(change.Actions) == 0 {
					t.Fatalf("resource change %d has no actions", i)
				}
			}
		})
	}
	if seen == 0 {
		t.Fatal("no fixtures were exercised")
	}
}

func TestCreateChangeFields(t *testing.T) {
	change := onlyChange(t, "create")

	if change.Address != "aws_s3_bucket.assets" {
		t.Fatalf("address = %q", change.Address)
	}
	if change.Mode != ModeManaged {
		t.Fatalf("mode = %q, want %q", change.Mode, ModeManaged)
	}
	if change.Type != "aws_s3_bucket" || change.Name != "assets" {
		t.Fatalf("type/name = %q/%q", change.Type, change.Name)
	}
	if change.ProviderName != "registry.terraform.io/hashicorp/aws" {
		t.Fatalf("provider = %q", change.ProviderName)
	}
	if change.Before.State() != StateKnown || change.Before.Kind() != KindNull {
		t.Fatalf("before of a create should be a known null, got state %q kind %q",
			change.Before.State(), change.Before.Kind())
	}
	if got := change.After.Field("bucket").Text(); got != "example-assets" {
		t.Fatalf("after.bucket = %q", got)
	}
}

func TestDataSourceModeIsPreserved(t *testing.T) {
	change := onlyChange(t, "data-source-read")

	if change.Mode != ModeData {
		t.Fatalf("mode = %q, want %q", change.Mode, ModeData)
	}
	if change.ActionReason != "read_because_config_unknown" {
		t.Fatalf("action reason = %q", change.ActionReason)
	}
}

func TestDeposedKeyIsPreserved(t *testing.T) {
	if got := onlyChange(t, "deposed").Deposed; got != "deadbeef" {
		t.Fatalf("deposed = %q, want %q", got, "deadbeef")
	}
}

// TestUnrecognizedResourceIsRetained is the acceptance criterion that an
// unsupported resource stays in the plan as an opaque change. The parser has no
// type registry at all, so this asserts that none was smuggled in.
func TestUnrecognizedResourceIsRetained(t *testing.T) {
	change := onlyChange(t, "opaque-resource")

	if change.Type != "acme_widget" {
		t.Fatalf("type = %q", change.Type)
	}
	if got := change.After.Field("shape").Text(); got != "hexagon" {
		t.Fatalf("an unrecognized resource lost its values: shape = %q", got)
	}
}

func TestOpenTofuPlanParses(t *testing.T) {
	change := onlyChange(t, "opentofu-minimal")

	if !strings.HasPrefix(change.ProviderName, "registry.opentofu.org/") {
		t.Fatalf("provider = %q, want an opentofu registry address", change.ProviderName)
	}
	if got := change.After.Field("length").Number().String(); got != "2" {
		t.Fatalf("after.length = %q", got)
	}
}

func TestReplacePathsArePreserved(t *testing.T) {
	change := onlyChange(t, "replace-delete-create")

	if len(change.ReplacePaths) != 1 || len(change.ReplacePaths[0]) != 1 || change.ReplacePaths[0][0] != "bucket" {
		t.Fatalf("replace paths = %v, want [[bucket]]", change.ReplacePaths)
	}
}

func TestFixtureDirectoryIsSanitized(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("reading testdata: %v", err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join("testdata", entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		for _, forbidden := range []string{"AKIA", "arn:aws:iam::", "-----BEGIN"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("fixture %s contains what looks like a real credential (%q)", entry.Name(), forbidden)
			}
		}
	}
}

// TestImportIDIsPreserved covers the one field the milestone's extraction list
// does not name. Terraform records an adopted object's import ID on the change,
// and a verifier that dropped it could not tell a resource being adopted from
// one being created.
func TestImportIDIsPreserved(t *testing.T) {
	change := onlyChange(t, "importing")

	if change.ImportID != "already-existing-assets" {
		t.Fatalf("import ID = %q", change.ImportID)
	}
	if len(change.Actions) != 1 || change.Actions[0] != ActionNoOp {
		t.Fatalf("actions = %v, want [no-op]", change.Actions)
	}
}

func TestChangeWithoutImportingHasNoImportID(t *testing.T) {
	if got := onlyChange(t, "create").ImportID; got != "" {
		t.Fatalf("import ID = %q, want empty", got)
	}
}

func TestMalformedImportingIsReported(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets",
	      "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	      "provider_name": "p",
	      "change": {"actions": ["create"], "before": null, "after": {}, "importing": 7}
	    }
	  ]
	}`)

	_, err := Parse(raw)
	if err == nil {
		t.Fatal("an importing block that is not an object should be rejected")
	}
	if !strings.Contains(err.Error(), "importing") {
		t.Fatalf("error %q does not locate the importing block", err.Error())
	}
}

// TestAChangeWithoutAProviderIsInvalidInput keeps a plan's own fault from being
// reported as this program's.
//
// provider_name identifies which provider manages a resource, and the Evidence
// Bundle requires it in every finding that names one. Reading it as absent and
// carrying the gap forward meant a plan missing it reached a bundle invariant
// and exited 11 — "internal failure", which the CLI contract reserves for a
// program that broke its own rules. A malformed plan is invalid input, and
// invalid input is refused at the boundary where it arrives.
func TestAChangeWithoutAProviderIsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"omitted":    `"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b"`,
		"empty":      `"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": ""`,
		"whitespace": `"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": "   "`,
		"null":       `"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b", "provider_name": null`,
	}

	for name, fields := range cases {
		t.Run(name, func(t *testing.T) {
			raw := `{"format_version": "1.2", "resource_changes": [{` + fields +
				`, "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}}]}`

			_, err := Parse([]byte(raw))
			if err == nil {
				t.Fatal("a change without a provider was accepted")
			}
			if !strings.Contains(err.Error(), "provider_name") {
				t.Errorf("the error does not name the field: %v", err)
			}
		})
	}
}

// TestTwoChangesAtOneAddressAreInvalid keeps the address usable as an identity.
//
// Terraform emits one change per address, and everything downstream relies on
// that: correlation joins by address, and coverage records which addresses were
// judged. A plan carrying two changes at one address makes one resource's
// verdict answer for another's — a public bucket covered by a private one that
// happens to share its name.
//
// A deposed object is the one case Terraform writes twice, and it is
// distinguished by its deposed key, so it is admitted.
//
// The diagnostic names the path and a bounded token, never the address: an
// address is a plan value, and a ParseError has no field capable of holding
// one.
func TestTwoChangesAtOneAddressAreInvalid(t *testing.T) {
	const change = `"change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}`

	duplicate := `{"format_version": "1.2", "resource_changes": [
	  {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	   "provider_name": "p", ` + change + `},
	  {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket_policy", "name": "b",
	   "provider_name": "p", ` + change + `}
	]}`

	_, err := Parse([]byte(duplicate))
	if err == nil {
		t.Fatal("two changes at one address were accepted")
	}
	// The address is a plan value, so the diagnostic reports the path and a
	// bounded token rather than the address itself.
	if !strings.Contains(err.Error(), "resource_changes[1].address") {
		t.Errorf("the error does not locate the duplicate: %v", err)
	}

	deposed := `{"format_version": "1.2", "resource_changes": [
	  {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	   "provider_name": "p", ` + change + `},
	  {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	   "provider_name": "p", "deposed": "abc123", ` + change + `}
	]}`

	if _, err := Parse([]byte(deposed)); err != nil {
		t.Fatalf("a deposed object beside its current one was rejected: %v", err)
	}
}

// TestADuplicateAddressDiagnosticCarriesNoPlanValue keeps the last plan-derived
// string out of a diagnostic. Every other one goes through safeToken; this was
// the only bypass, and an address is as much a plan value as any other.
func TestADuplicateAddressDiagnosticCarriesNoPlanValue(t *testing.T) {
	const secret = "aws_s3_bucket.hunter2-the-secret-name-and-more-besides"
	const change = `"change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}`

	raw := `{"format_version": "1.2", "resource_changes": [
	  {"address": "` + secret + `", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	   "provider_name": "p", ` + change + `},
	  {"address": "` + secret + `", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	   "provider_name": "p", ` + change + `}
	]}`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("two changes at one address were accepted")
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("the diagnostic carries a plan value: %v", err)
	}
	if len(err.Error()) > 300 {
		t.Errorf("the diagnostic is %d bytes; it is not bounded", len(err.Error()))
	}
}

// TestAnUnrecognizedActionIsCarriedAndFlagged keeps an unfamiliar verb from
// reading as harmless, without discarding the rest of a plan over it.
//
// Milestone 02 decided the parser carries what it does not understand and the
// policy layer refuses to conclude, and Action.Valid's doc comment says so.
// Nothing called it: IsDestructive asks whether "delete" is among the actions,
// so "Delete", "destroy" and any invented verb read as a change that destroys
// nothing, and a contract forbidding destruction passed them.
func TestAnUnrecognizedActionIsCarriedAndFlagged(t *testing.T) {
	plan := func(actions string) []byte {
		return []byte(`{"format_version": "1.2", "resource_changes": [
		  {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
		   "provider_name": "p",
		   "change": {"actions": ` + actions + `, "before": {"bucket": "b"}, "after": null}}
		]}`)
	}

	for name, actions := range map[string]string{
		"a miscased delete": `["Delete"]`,
		"another word":      `["destroy"]`,
		"an invented verb":  `["evaporate"]`,
		"empty":             `[""]`,
		"one of a pair":     `["delete", "recreate"]`,
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := Parse(plan(actions))
			if err != nil {
				t.Fatalf("an unrecognized action must not fail the parse: %v", err)
			}
			if !parsed.ResourceChanges[0].HasUnrecognizedAction() {
				t.Fatalf("%s was not flagged as unrecognized", actions)
			}
		})
	}

	for name, actions := range map[string]string{
		"a delete":              `["delete"]`,
		"a replace":             `["delete", "create"]`,
		"the other replace":     `["create", "delete"]`,
		"a no-op":               `["no-op"]`,
		"a read":                `["read"]`,
		"an update":             `["update"]`,
		"a forgotten resource":  `["forget"]`,
		"a forgotten and taken": `["create", "forget"]`,
	} {
		t.Run(name, func(t *testing.T) {
			parsed, err := Parse(plan(actions))
			if err != nil {
				t.Fatalf("a plan Terraform emits was rejected: %v", err)
			}
			if parsed.ResourceChanges[0].HasUnrecognizedAction() {
				t.Fatalf("%s is an action Terraform emits and was flagged", actions)
			}
		})
	}
}

// TestForgettingAnObjectIsNotDestroyingIt keeps the new verb's meaning
// straight. A removed block drops a resource from state and leaves the object
// alone, so it destroys nothing — but it is understood rather than ignored.
func TestForgettingAnObjectIsNotDestroyingIt(t *testing.T) {
	raw := []byte(`{"format_version": "1.2", "resource_changes": [
	  {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	   "provider_name": "p",
	   "change": {"actions": ["forget"], "before": {"bucket": "b"}, "after": null}}
	]}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if plan.ResourceChanges[0].IsDestructive() {
		t.Error("forgetting an object was read as destroying it")
	}
}

// TestAnUnrecognizedModeIsRefused keeps the field that decides admissibility
// from being believed without being checked.
//
// Mode says whether a plan entry is something the configuration manages or
// something it only reads, and IsRead keys on it exactly — so any other
// spelling is silently treated as managed, which is the permissive side. The
// actions have carried a closed set and a guard since milestone 02; this had
// neither, and it became load-bearing when admissibility began depending on it.
func TestAnUnrecognizedModeIsRefused(t *testing.T) {
	plan := func(mode string) []byte {
		return []byte(`{"format_version": "1.2", "resource_changes": [
		  {"address": "aws_s3_bucket.b", "mode": ` + mode + `, "type": "aws_s3_bucket", "name": "b",
		   "provider_name": "p",
		   "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}}
		]}`)
	}

	for name, mode := range map[string]string{
		"a miscased data":  `"Data"`,
		"an invented mode": `"observed"`,
		"empty":            `""`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(plan(mode)); err == nil {
				t.Fatalf("an unrecognized mode was accepted: %s", mode)
			}
		})
	}

	for name, mode := range map[string]string{
		"managed": `"managed"`,
		"data":    `"data"`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(plan(mode)); err != nil {
				t.Fatalf("a mode Terraform emits was rejected: %v", err)
			}
		})
	}
}

// TestAPlanNamingOneKeyTwiceIsRefused closes the last place a stated identity
// was read as the one written last.
//
// resource_changes and the configuration walk each refuse two entries at one
// address, because an address identifies one resource. A repeated JSON key is
// the same claim made one level down, and it never reached either check:
// encoding/json collapses repeated members into the last one while decoding, so
// a second "one" under module_calls discarded that module's whole configuration
// before anything could look. Measured on a plan whose ACL is public-read, the
// verdict went from BLOCK to UNKNOWN with no diagnostic.
func TestAPlanNamingOneKeyTwiceIsRefused(t *testing.T) {
	cases := map[string]string{
		"a module call": `{
		  "format_version": "1.2",
		  "configuration": {"root_module": {"module_calls": {
		    "one": {"module": {"resources": []}},
		    "one": {"module": {"resources": []}}
		  }}}
		}`,
		"a provider instance": `{
		  "format_version": "1.2",
		  "configuration": {"provider_config": {
		    "aws": {"name": "aws"},
		    "aws": {"name": "aws"}
		  }}
		}`,
		"an attribute of a change": `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
		     "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"acl": "private", "acl": "public-read"}}}
		  ]
		}`,
		"the format version itself": `{"format_version": "1.2", "format_version": "9.0"}`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(raw))
			if err == nil {
				t.Fatal("a document naming one key twice was accepted, and one of the two was discarded")
			}
			if !strings.Contains(err.Error(), "more than once") {
				t.Errorf("the error does not say what is wrong: %v", err)
			}
		})
	}
}

// TestARepeatedKeyIsFoundPastEveryArrayInFrontOfIt covers the walk rather than
// the rule.
//
// The cases above are minimal, and a token stream re-synchronises by accident
// on a minimal document: a scan that never descended into arrays still found
// their repeated keys, because the array's own closing token happened to leave
// the reader where the next key was. A plan is not minimal. Its resource
// changes are an array of objects holding arrays, and the configuration comes
// after all of them -- so a scan that skips an array skips the rest of the
// document, and the repeated module call this commit exists to refuse is
// accepted with nothing said.
func TestARepeatedKeyIsFoundPastEveryArrayInFrontOfIt(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "b", "tags": [{"k": "v"}, {"k": "v"}]}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {
	    "one": {"module": {"resources": []}},
	    "one": {"module": {"resources": []}}
	  }}}
	}`)

	_, err := Parse(raw)
	if err == nil {
		t.Fatal("a repeated module call behind an array of changes was accepted")
	}
	if !strings.Contains(err.Error(), "configuration.root_module.module_calls.one") {
		t.Errorf("the error does not locate the repeated key: %v", err)
	}
}

// TestADiagnosticLocatesTheRepeatedKey holds the other half of a diagnostic:
// saying something is wrong, and saying where. Evidence that names the wrong
// place is not evidence.
func TestADiagnosticLocatesTheRepeatedKey(t *testing.T) {
	cases := map[string]struct{ raw, path string }{
		"inside a change": {`{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
		     "provider_name": "p",
		     "change": {"actions": ["create"], "before": null,
		                "after": {"acl": "private", "acl": "public-read"}}}
		  ]
		}`, "resource_changes[0].change.after.acl"},
		"a provider instance": {`{
		  "format_version": "1.2",
		  "configuration": {"provider_config": {
		    "aws": {"name": "aws"}, "aws": {"name": "aws"}}}
		}`, "configuration.provider_config.aws"},
		"a long field name": {
			`{"format_version": "1.2", "terraform_version": "1.14.0", "terraform_version": "1.0.0"}`,
			"terraform_version"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.raw))
			if err == nil {
				t.Fatal("the document was accepted")
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Errorf("the error locates the wrong place.\n want it to contain %q\n  got %v",
					tc.path, err)
			}
		})
	}
}

// TestADocumentTooDeepToScanIsRefusedRatherThanSkipped covers the bound.
//
// Past it the scan cannot keep looking, and there are two ways to stop: refuse
// the document, or accept it with everything below unscanned. Only the first is
// safe to be wrong about, and nothing held the code to it.
func TestADocumentTooDeepToScanIsRefusedRatherThanSkipped(t *testing.T) {
	deep := func(levels int, tail string) []byte {
		return []byte(`{"format_version": "1.2", "a": ` +
			strings.Repeat(`{"b": `, levels) + tail + strings.Repeat(`}`, levels) + `}`)
	}

	// Well inside the bound, and holding a repeated key at the bottom: read and
	// refused for the repetition, not for the depth.
	if _, err := Parse(deep(100, `{"c": 1, "c": 2}`)); err == nil ||
		!strings.Contains(err.Error(), "more than once") {
		t.Errorf("a repeated key a hundred levels down was not found: %v", err)
	}

	// Past the bound: refused for the depth, whatever is below.
	_, err := Parse(deep(600, `null`))
	if err == nil {
		t.Fatal("a document too deep to scan was accepted, and everything below the bound went unread")
	}
	if !strings.Contains(err.Error(), "nested") {
		t.Errorf("the error does not say the document is too deep: %v", err)
	}
}

// TestRepeatedKeysAreRefusedOnlyWithinOneObject keeps the rule from refusing
// the ordinary case. The same name in two different objects is two different
// keys, which is most of a plan.
func TestRepeatedKeysAreRefusedOnlyWithinOneObject(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.a", "mode": "managed", "type": "aws_s3_bucket", "name": "a",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket.b", "mode": "managed", "type": "aws_s3_bucket", "name": "b",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "b"}}}
	  ],
	  "configuration": {"root_module": {"module_calls": {
	    "one": {"module": {"resources": [
	      {"address": "aws_s3_bucket.a", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "a", "expressions": {}}]}},
	    "two": {"module": {"resources": [
	      {"address": "aws_s3_bucket.a", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "a", "expressions": {}}]}}
	  }}}
	}`)

	if _, err := Parse(raw); err != nil {
		t.Fatalf("an ordinary plan was refused: %v", err)
	}
}
