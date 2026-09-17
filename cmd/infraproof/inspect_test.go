package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
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

// TestInspectMatchesItsGolden pins the report format. Determinism alone does
// not: comparing runs to each other proves the output is stable, not that it is
// the output anyone reviewed.
func TestInspectMatchesItsGolden(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "inspect-nested-modules.golden.json"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}

	stdout, stderr, code := runInspectFixture(t, "nested-modules")
	if code != evidence.ExitPass {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr)
	}
	if stdout != string(want) {
		t.Fatalf("inspect output does not match its golden\n--- got ---\n%s\n--- want ---\n%s", stdout, want)
	}
}

// TestInspectSortsByAddress checks the ordering rule against input that is
// deliberately out of order, which the golden fixture cannot do because
// Terraform already emits its changes in address order.
func TestInspectSortsByAddress(t *testing.T) {
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "zzz_last.resource", "mode": "managed", "type": "zzz_last", "name": "resource",
	     "provider_name": "p", "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "mmm_middle.resource", "mode": "managed", "type": "mmm_middle", "name": "resource",
	     "provider_name": "p", "change": {"actions": ["create"], "before": null, "after": {}}},
	    {"address": "aaa_first.resource", "mode": "managed", "type": "aaa_first", "name": "resource",
	     "provider_name": "p", "change": {"actions": ["create"], "before": null, "after": {}}}
	  ]
	}`

	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(plan), 0o600); err != nil {
		t.Fatalf("writing plan: %v", err)
	}

	var stdout, stderr strings.Builder
	if code := run([]string{"inspect", "--plan", path}, &stdout, &stderr); code != evidence.ExitPass {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	out := stdout.String()
	first := strings.Index(out, "aaa_first")
	middle := strings.Index(out, "mmm_middle")
	last := strings.Index(out, "zzz_last")
	if first < 0 || middle < 0 || last < 0 {
		t.Fatalf("all three resources should be reported:\n%s", out)
	}
	if !(first < middle && middle < last) {
		t.Fatalf("resources are not sorted by address:\n%s", out)
	}
}

// TestInspectSortsPathLists covers the same rule one level down.
func TestInspectSortsPathLists(t *testing.T) {
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "a.b", "mode": "managed", "type": "a", "name": "b", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {},
	                "after_unknown": {"zebra": true, "apple": true, "mango": true}}}
	  ]
	}`

	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, []byte(plan), 0o600); err != nil {
		t.Fatalf("writing plan: %v", err)
	}

	var stdout, stderr strings.Builder
	if code := run([]string{"inspect", "--plan", path}, &stdout, &stderr); code != evidence.ExitPass {
		t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
	}

	var report struct {
		ResourceChanges []struct {
			UnknownPaths []string `json:"unknown_paths"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	got := report.ResourceChanges[0].UnknownPaths
	want := []string{"after.apple", "after.mango", "after.zebra"}
	if len(got) != len(want) {
		t.Fatalf("unknown paths = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unknown paths = %v, want %v", got, want)
		}
	}
}

// TestInspectSortsPathsAcrossBothSides is why the path lists are sorted after
// collection rather than relying on the parser's already-sorted field order:
// the before side is walked first, and "before." sorts after "after.".
func TestInspectSortsPathsAcrossBothSides(t *testing.T) {
	stdout, _, code := runInspectFixture(t, "nested-sensitive")
	if code != evidence.ExitPass {
		t.Fatalf("exit code = %d", code)
	}

	var report struct {
		ResourceChanges []struct {
			RedactedPaths []string `json:"redacted_paths"`
		} `json:"resource_changes"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	paths := report.ResourceChanges[0].RedactedPaths
	if len(paths) < 2 {
		t.Fatalf("this test needs paths on both sides, got %v", paths)
	}
	if !slices.IsSorted(paths) {
		t.Fatalf("redacted paths are not sorted: %v", paths)
	}
	if paths[0][:6] != "after." || paths[len(paths)-1][:7] != "before." {
		t.Fatalf("this test is only meaningful with paths from both sides, got %v", paths)
	}
}

// TestInspectReportsWhatTheMappersUnderstood makes the normalization visible to
// a human without inspect reaching a verdict. It reports the state of the
// determination and the attributes it rested on; whether that is acceptable is
// the check command's question, and this build has none.
func TestInspectReportsWhatTheMappersUnderstood(t *testing.T) {
	cases := map[string]struct {
		fixture, address, state string
		grants                  bool
		unresolved              string
	}{
		"aws public": {
			filepath.Join("..", "..", "internal", "providers", "aws", "testdata", "public-acl.json"),
			"aws_s3_bucket.assets", "KNOWN", true, "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK",
		},
		"gcp undetermined": {
			filepath.Join("..", "..", "internal", "providers", "gcp", "testdata", "unknown-inherited-no-grant.json"),
			"google_storage_bucket.assets", "UNKNOWN", false, "GCP_ORGANIZATION_PUBLIC_ACCESS_POLICY",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if code := run([]string{"inspect", "--plan", c.fixture}, &stdout, &stderr); code != evidence.ExitPass {
				t.Fatalf("exit code = %d (stderr: %s)", code, stderr.String())
			}

			var report struct {
				ResourceChanges []struct {
					Address       string `json:"address"`
					ObjectStorage *struct {
						PublicAccess       string   `json:"public_access"`
						GrantsPublicAccess bool     `json:"grants_public_access"`
						DeterminedFrom     []string `json:"determined_from"`
						Unresolved         []string `json:"unresolved_controls"`
					} `json:"object_storage"`
				} `json:"resource_changes"`
			}
			if err := json.Unmarshal([]byte(stdout.String()), &report); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}

			var found bool
			for _, change := range report.ResourceChanges {
				if change.Address != c.address {
					if change.ObjectStorage != nil && change.ObjectStorage.PublicAccess != "" {
						continue
					}
					continue
				}
				found = true
				if change.ObjectStorage == nil {
					t.Fatalf("%s reported no normalized capabilities:\n%s", c.address, stdout.String())
				}
				if change.ObjectStorage.PublicAccess != c.state {
					t.Fatalf("public access = %q, want %q", change.ObjectStorage.PublicAccess, c.state)
				}
				if change.ObjectStorage.GrantsPublicAccess != c.grants {
					t.Fatalf("grants = %v, want %v", change.ObjectStorage.GrantsPublicAccess, c.grants)
				}
				if len(change.ObjectStorage.DeterminedFrom) == 0 {
					t.Fatal("the determination names no provider attribute")
				}
				if len(change.ObjectStorage.Unresolved) != 1 || change.ObjectStorage.Unresolved[0] != c.unresolved {
					t.Fatalf("unresolved = %v, want %q", change.ObjectStorage.Unresolved, c.unresolved)
				}
			}
			if !found {
				t.Fatalf("%s is missing from the report:\n%s", c.address, stdout.String())
			}
		})
	}
}

// TestInspectStillReachesNoVerdict keeps the command's promise intact now that
// it shows normalized capabilities. The check is on the report's structure
// rather than on substrings: a check identifier such as
// AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK legitimately contains the word BLOCK.
func TestInspectStillReachesNoVerdict(t *testing.T) {
	stdout, _, code := runInspectFixture(t, "nested-sensitive")
	if code != evidence.ExitPass {
		t.Fatalf("exit code = %d", code)
	}

	var report map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{"decision", "findings", "verdict", "summary"} {
		if _, present := report[key]; present {
			t.Fatalf("inspect reported %q, which is a verdict this build cannot reach", key)
		}
	}

	var changes struct {
		ResourceChanges []map[string]json.RawMessage `json:"resource_changes"`
	}
	if err := json.Unmarshal([]byte(stdout), &changes); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, change := range changes.ResourceChanges {
		for _, key := range []string{"severity", "disposition", "decision", "claim"} {
			if _, present := change[key]; present {
				t.Fatalf("a resource entry reported %q, which belongs to a finding", key)
			}
		}
	}
}
