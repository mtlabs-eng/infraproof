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
