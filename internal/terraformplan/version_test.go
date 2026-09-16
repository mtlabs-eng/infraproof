package terraformplan

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func planWithFormatVersion(version string) []byte {
	return []byte(fmt.Sprintf(`{"format_version": %q, "resource_changes": []}`, version))
}

func TestSupportedFormatVersions(t *testing.T) {
	for _, version := range []string{"1.0", "1.1", "1.2", "1.9", "1.12"} {
		t.Run(version, func(t *testing.T) {
			plan, err := Parse(planWithFormatVersion(version))
			if err != nil {
				t.Fatalf("format version %q should be accepted: %v", version, err)
			}
			if plan.FormatVersion != version {
				t.Fatalf("format version = %q, want %q", plan.FormatVersion, version)
			}
		})
	}
}

func TestUnsupportedFormatVersions(t *testing.T) {
	for _, version := range []string{"", "0.1", "0.2", "2.0", "10.0", "one", "1", "1.x"} {
		t.Run(version, func(t *testing.T) {
			_, err := Parse(planWithFormatVersion(version))
			if err == nil {
				t.Fatalf("format version %q should be rejected", version)
			}
			if !errors.Is(err, ErrUnsupportedFormatVersion) {
				t.Fatalf("error %v should match ErrUnsupportedFormatVersion", err)
			}
			if !strings.Contains(err.Error(), "format_version") {
				t.Fatalf("error %q does not name the offending field", err.Error())
			}
		})
	}
}

func TestUnsupportedVersionFixtureIsRejected(t *testing.T) {
	_, err := Parse(fixtureBytes(t, "unsupported-version"))
	if err == nil {
		t.Fatal("the unsupported-version fixture should be rejected")
	}
	if !errors.Is(err, ErrUnsupportedFormatVersion) {
		t.Fatalf("error %v should match ErrUnsupportedFormatVersion", err)
	}
}

func TestTerraformVersionIsCaptured(t *testing.T) {
	if got := parseFixture(t, "create").TerraformVersion; got != "1.12.0" {
		t.Fatalf("terraform version = %q, want 1.12.0", got)
	}
}
