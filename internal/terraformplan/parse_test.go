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
