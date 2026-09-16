package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

// planFixture reaches into the parser's fixtures rather than duplicating them.
// The coupling is test-only: no production file names a fixture.
func planFixture(name string) string {
	return filepath.Join("..", "..", "internal", "terraformplan", "testdata", name+".json")
}

func runInspectFixture(t *testing.T, name string) (string, string, int) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run([]string{"inspect", "--plan", planFixture(name)}, &stdout, &stderr)
	return stdout.String(), stderr.String(), code
}

func TestInspectReportsAPlan(t *testing.T) {
	stdout, stderr, code := runInspectFixture(t, "replace-delete-create")

	if code != evidence.ExitPass {
		t.Fatalf("exit code = %d, want %d (stderr: %s)", code, evidence.ExitPass, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}

	var report struct {
		FormatVersion   string `json:"format_version"`
		PlanDigest      string `json:"plan_digest"`
		ResourceChanges []struct {
			Address     string   `json:"address"`
			Actions     []string `json:"actions"`
			Replace     bool     `json:"replace"`
			Destructive bool     `json:"destructive"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, stdout)
	}

	if report.FormatVersion != "1.2" {
		t.Fatalf("format version = %q", report.FormatVersion)
	}
	if !strings.HasPrefix(report.PlanDigest, "sha256:") || len(report.PlanDigest) != len("sha256:")+64 {
		t.Fatalf("plan digest = %q", report.PlanDigest)
	}
	if len(report.ResourceChanges) != 1 {
		t.Fatalf("resource changes = %d, want 1", len(report.ResourceChanges))
	}
	change := report.ResourceChanges[0]
	if strings.Join(change.Actions, ",") != "delete,create" {
		t.Fatalf("actions = %v, want [delete create]", change.Actions)
	}
	if !change.Replace || !change.Destructive {
		t.Fatalf("replace = %v destructive = %v, want both true", change.Replace, change.Destructive)
	}
}

// TestInspectNeverPrintsASensitiveValue is the acceptance criterion applied to
// the one surface that actually shows a user plan data.
func TestInspectNeverPrintsASensitiveValue(t *testing.T) {
	const canary = "CANARY-SENSITIVE-VALUE-DO-NOT-LEAK"

	raw, err := os.ReadFile(planFixture("nested-sensitive"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	if !strings.Contains(string(raw), canary) {
		t.Fatal("the fixture no longer contains the canary; this test would pass vacuously")
	}

	stdout, stderr, code := runInspectFixture(t, "nested-sensitive")
	if code != evidence.ExitPass {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	if strings.Contains(stdout, canary) || strings.Contains(stderr, canary) {
		t.Fatalf("a sensitive value reached the output:\n%s%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "after.tags.secret") {
		t.Fatalf("the redacted path was not reported:\n%s", stdout)
	}
	if !strings.Contains(stdout, "before.previous_token") {
		t.Fatalf("a redacted path on the before side was not reported:\n%s", stdout)
	}
}

func TestInspectReportsUnknownPaths(t *testing.T) {
	stdout, _, code := runInspectFixture(t, "unknown-after")
	if code != evidence.ExitPass {
		t.Fatalf("exit code = %d", code)
	}
	for _, want := range []string{"after.arn", "after.nested.pending", "after.rules[0]", "after.rules[1].inner"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("unknown path %q missing from:\n%s", want, stdout)
		}
	}
}

func TestInspectIsDeterministic(t *testing.T) {
	first, _, _ := runInspectFixture(t, "nested-sensitive")
	for i := 0; i < 10; i++ {
		again, _, _ := runInspectFixture(t, "nested-sensitive")
		if again != first {
			t.Fatal("inspect output differs between runs")
		}
	}
}

func TestInspectReportsProviderAlias(t *testing.T) {
	stdout, _, code := runInspectFixture(t, "provider-aliases")
	if code != evidence.ExitPass {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout, `"provider_alias": "west"`) {
		t.Fatalf("provider alias missing from:\n%s", stdout)
	}
}

func TestInspectInputErrors(t *testing.T) {
	cases := map[string][]string{
		"missing --plan":      {"inspect"},
		"empty --plan":        {"inspect", "--plan", ""},
		"unreadable file":     {"inspect", "--plan", filepath.Join("testdata", "does-not-exist.json")},
		"unknown flag":        {"inspect", "--intent", "intent.yaml"},
		"malformed json":      {"inspect", "--plan", planFixture("malformed")},
		"unsupported version": {"inspect", "--plan", planFixture("unsupported-version")},
		"positional argument": {"inspect", "plan.json"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			code := run(args, &stdout, &stderr)

			if code != evidence.ExitInvalidInput {
				t.Fatalf("exit code = %d, want %d", code, evidence.ExitInvalidInput)
			}
			if stderr.String() == "" {
				t.Fatal("an input error must explain itself on stderr")
			}
			if stdout.String() != "" {
				t.Fatalf("stdout = %q, want empty on an input error", stdout.String())
			}
		})
	}
}

func TestHelpMentionsInspect(t *testing.T) {
	var stdout, stderr strings.Builder

	if code := run([]string{"--help"}, &stdout, &stderr); code != evidence.ExitPass {
		t.Fatalf("exit code = %d", code)
	}
	if !strings.Contains(stdout.String(), "inspect") {
		t.Fatalf("help does not mention inspect:\n%s", stdout.String())
	}
}
