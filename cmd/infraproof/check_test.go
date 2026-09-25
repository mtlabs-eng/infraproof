package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
)

// write puts a file in a temporary directory and returns its path. Every input
// this command reads is a local file, and none of these tests reach a network
// or a cloud.
func write(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

const privateIntent = `{
  "schema_version": "1.0",
  "change_id": "add-private-staging-assets",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage", "exposure": "private"}]
}`

// blockedPlan grants public access through an ACL with nothing preventing it.
const blockedPlan = `{
  "format_version": "1.2",
  "terraform_version": "1.14.0",
  "resource_changes": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
     "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "a", "tags": {"environment": "staging"}}}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}}
  ],
  "configuration": {"root_module": {"resources": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
     "expressions": {}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets",
     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
  ]}}
}`

// passingPlan blocks every route to the public.
const passingPlan = `{
  "format_version": "1.2",
  "terraform_version": "1.14.0",
  "resource_changes": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
     "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "a", "tags": {"environment": "staging"}}}},
    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
     "type": "aws_s3_bucket_public_access_block", "name": "assets",
     "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"block_public_acls": true, "block_public_policy": true,
                          "ignore_public_acls": true, "restrict_public_buckets": true}}}
  ],
  "configuration": {"root_module": {"resources": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
     "expressions": {}},
    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
     "type": "aws_s3_bucket_public_access_block", "name": "assets",
     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
  ]}}
}`

// undeterminedPlan has a bucket and nothing that settles its exposure.
const undeterminedPlan = `{
  "format_version": "1.2",
  "terraform_version": "1.14.0",
  "resource_changes": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
     "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "a", "tags": {"environment": "staging"}}}}
  ]
}`

func check(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr strings.Builder
	code := run(append([]string{"check"}, args...), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// TestCheckExitCodesMatchTheContract is the acceptance criterion made
// mechanical. The exit code is the part of this program a pipeline reads, and
// it is the part most easily broken without anyone noticing.
func TestCheckExitCodesMatchTheContract(t *testing.T) {
	cases := map[string]struct {
		plan string
		want int
	}{
		"a violation blocks":                {blockedPlan, evidence.ExitBlock},
		"a proven prevention passes":        {passingPlan, evidence.ExitPass},
		"an undetermined answer is unknown": {undeterminedPlan, evidence.ExitUnknown},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := check(t,
				"--intent", write(t, "intent.json", privateIntent),
				"--plan", write(t, "plan.json", tc.plan))

			if code != tc.want {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tc.want, stdout, stderr)
			}
			if stderr != "" {
				t.Errorf("stderr = %q; a decision is not an operational error", stderr)
			}
		})
	}
}

// TestCheckEmitsAValidBundle keeps the JSON output conformant. A bundle the
// contract refuses is one no consumer can rely on.
func TestCheckEmitsAValidBundle(t *testing.T) {
	_, stdout, _ := check(t,
		"--intent", write(t, "intent.json", privateIntent),
		"--plan", write(t, "plan.json", blockedPlan))

	var bundle evidence.Bundle
	if err := json.Unmarshal([]byte(stdout), &bundle); err != nil {
		t.Fatalf("the output is not an Evidence Bundle: %v\n%s", err, stdout)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("the output does not satisfy the contract: %v", err)
	}
	if bundle.SchemaVersion != evidence.SchemaVersion {
		t.Errorf("schema version = %q, want %q", bundle.SchemaVersion, evidence.SchemaVersion)
	}
	if bundle.Decision != evidence.DecisionBlock {
		t.Errorf("decision = %q, want BLOCK", bundle.Decision)
	}
	if bundle.Subject.PlanDigest == "" || bundle.Subject.IntentSource == "" {
		t.Errorf("the subject does not identify both inputs: %+v", bundle.Subject)
	}
}

// TestMarkdownCarriesTheSameDecision keeps the two renderings from disagreeing.
// A reader who sees the report and a pipeline that reads the JSON must not be
// told different things.
func TestMarkdownCarriesTheSameDecision(t *testing.T) {
	intentPath := write(t, "intent.json", privateIntent)
	planPath := write(t, "plan.json", blockedPlan)

	jsonCode, jsonOut, _ := check(t, "--intent", intentPath, "--plan", planPath, "--format", "json")
	mdCode, mdOut, _ := check(t, "--intent", intentPath, "--plan", planPath, "--format", "markdown")

	if jsonCode != mdCode {
		t.Fatalf("exit codes differ by format: json=%d markdown=%d", jsonCode, mdCode)
	}
	if !strings.Contains(mdOut, "BLOCK") {
		t.Errorf("the Markdown report does not state the decision:\n%s", mdOut)
	}
	if !strings.Contains(jsonOut, "STORAGE_PUBLIC") || !strings.Contains(mdOut, "STORAGE_PUBLIC") {
		t.Error("the two renderings do not report the same finding")
	}
}

// TestCheckIsDeterministic keeps the output a function of the input alone.
func TestCheckIsDeterministic(t *testing.T) {
	intentPath := write(t, "intent.json", privateIntent)
	planPath := write(t, "plan.json", blockedPlan)

	_, first, _ := check(t, "--intent", intentPath, "--plan", planPath)
	_, second, _ := check(t, "--intent", intentPath, "--plan", planPath)

	if first != second {
		t.Fatal("two runs over one pair of inputs produced different bytes")
	}
}

// TestOperationalErrorsAreNotDecisions keeps a broken input from reading as a
// verdict. A missing file is not a PASS, and it is not a BLOCK either.
func TestOperationalErrorsAreNotDecisions(t *testing.T) {
	good := write(t, "intent.json", privateIntent)
	goodPlan := write(t, "plan.json", passingPlan)

	cases := map[string][]string{
		"no arguments":          {},
		"no plan":               {"--intent", good},
		"no intent":             {"--plan", goodPlan},
		"a missing intent file": {"--intent", filepath.Join(t.TempDir(), "absent.json"), "--plan", goodPlan},
		"a missing plan file":   {"--intent", good, "--plan", filepath.Join(t.TempDir(), "absent.json")},
		"an invalid contract":   {"--intent", write(t, "bad.json", `{"schema_version": "1.0"}`), "--plan", goodPlan},
		"an invalid plan":       {"--intent", good, "--plan", write(t, "bad.json", `{"format_version": "9.0"}`)},
		"an unknown format":     {"--intent", good, "--plan", goodPlan, "--format", "xml"},
		"a positional argument": {"--intent", good, "--plan", goodPlan, "extra"},
	}

	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, stdout, stderr := check(t, args...)
			if code != evidence.ExitInvalidInput {
				t.Fatalf("exit = %d, want %d\nstdout: %s", code, evidence.ExitInvalidInput, stdout)
			}
			if stderr == "" {
				t.Error("an operational failure must say what went wrong")
			}
			if stdout != "" {
				t.Errorf("stdout = %q; a failed run must not emit a report", stdout)
			}
		})
	}
}

// TestAYAMLContractIsRefusedByName keeps a deferred format from failing as a
// puzzle. This build has no YAML reader, and a reader handed a JSON syntax
// error learns nothing about why.
func TestAYAMLContractIsRefusedByName(t *testing.T) {
	yaml := "schema_version: \"1.0\"\nchange_id: c\nenvironment: staging\n"

	// The file is deliberately not named .yaml: the path appears in every
	// error, so naming it there would make the assertion true whatever the
	// code did. internal/intent/load_test.go warns about exactly this.
	code, _, stderr := check(t,
		"--intent", write(t, "contract.txt", yaml),
		"--plan", write(t, "plan.json", passingPlan))

	if code != evidence.ExitInvalidInput {
		t.Fatalf("exit = %d, want %d", code, evidence.ExitInvalidInput)
	}
	if !strings.Contains(strings.ToLower(stderr), "yaml") {
		t.Errorf("the error does not name the format: %q", stderr)
	}
}

// TestCheckNeverPrintsASensitiveValue is the safety rule at the boundary where
// it is easiest to break: the place values become text a human reads.
func TestCheckNeverPrintsASensitiveValue(t *testing.T) {
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "provider_name": "registry.terraform.io/hashicorp/aws",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "hunter2-the-bucket", "tags": {"environment": "hunter2-the-env"}},
	                "after_sensitive": {"bucket": true, "tags": true}}}
	  ]
	}`

	for _, format := range []string{"json", "markdown"} {
		t.Run(format, func(t *testing.T) {
			_, stdout, stderr := check(t,
				"--intent", write(t, "intent.json", privateIntent),
				"--plan", write(t, "plan.json", plan),
				"--format", format)

			for _, secret := range []string{"hunter2-the-bucket", "hunter2-the-env"} {
				if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
					t.Fatalf("a sensitive value reached the output: %s", secret)
				}
			}
		})
	}
}

// TestAnUninterpretedResourceDoesNotPass is this milestone's form of the defect
// the M03 rounds kept finding. A plan full of resources no mapper understands
// has not been checked, and reporting a PASS would say it had.
func TestAnUninterpretedResourceDoesNotPass(t *testing.T) {
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "vendor_bucket.assets", "mode": "managed", "type": "vendor_bucket", "name": "assets",
	     "provider_name": "registry.example.com/vendor/vendor",
	     "change": {"actions": ["create"], "before": null, "after": {"name": "a"}}}
	  ]
	}`

	code, stdout, _ := check(t,
		"--intent", write(t, "intent.json", privateIntent),
		"--plan", write(t, "plan.json", plan))

	if code == evidence.ExitPass {
		t.Fatalf("a plan this build cannot read reported a pass:\n%s", stdout)
	}
	if code != evidence.ExitUnknown {
		t.Fatalf("exit = %d, want %d", code, evidence.ExitUnknown)
	}
}

// TestTheDocumentedFlowWorks runs the command the README shows, with the
// arguments it shows, against the files it ships.
//
// An earlier form substituted a real plan path because the README named a file
// that did not exist — which meant the test passed while the documented flow
// exited 10 for anyone who copied it. Documentation that drifts from the
// program is worse than none: a reader who copies it and gets an error learns
// to distrust the rest of it.
func TestTheDocumentedFlowWorks(t *testing.T) {
	arguments := documentedArguments(t)

	code, stdout, stderr := check(t, arguments...)

	if code != evidence.ExitPass {
		t.Fatalf("exit = %d, want %d\nstderr: %s", code, evidence.ExitPass, stderr)
	}
	if !strings.Contains(stdout, "PASS") {
		t.Errorf("the report does not state the decision:\n%s", stdout)
	}
}

// documentedArguments reads the check invocation out of the README, so the test
// exercises what a reader would actually type rather than a copy of it that can
// drift.
func documentedArguments(t *testing.T) []string {
	t.Helper()

	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("reading the README: %v", err)
	}

	_, block, found := strings.Cut(string(readme), "go run ./cmd/infraproof check")
	if !found {
		t.Fatal("the README no longer documents the check command")
	}
	block, _, found = strings.Cut(block, "```")
	if !found {
		t.Fatal("the documented command is not in a fenced block")
	}

	var arguments []string
	for _, field := range strings.Fields(block) {
		if field == "\\" {
			continue
		}
		arguments = append(arguments, field)
	}
	if len(arguments) == 0 {
		t.Fatal("the documented command takes no arguments")
	}

	// The README paths are relative to the repository root.
	for i, argument := range arguments {
		if strings.HasPrefix(argument, "examples/") {
			arguments[i] = filepath.Join("..", "..", argument)
		}
	}
	return arguments
}

// TestTheShippedContractIsValid keeps the example honest. A contract the
// program refuses is a worked example of how to fail.
func TestTheShippedContractIsValid(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "examples", "intent.json"))
	if err != nil {
		t.Fatalf("reading the shipped contract: %v", err)
	}
	if _, err := intent.Parse(raw, "examples/intent.json"); err != nil {
		t.Fatalf("the shipped example contract does not load: %v", err)
	}
}

// TestNoNetworkOrCloudCredentialIsReachable holds the safety claim the README
// makes, at the level the build can check it: nothing in this program's
// transitive dependencies is a cloud SDK, an HTTP client used to call one, or
// an LLM client. The module declares no external dependency at all, which is
// asserted separately; this covers the standard library packages that would be
// the first sign of a change in direction.
func TestNoNetworkOrCloudCredentialIsReachable(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps",
		"github.com/mtlabs-eng/infraproof/cmd/infraproof").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}

	forbidden := []string{"net/http", "net/smtp", "os/exec", "net/rpc"}
	for _, dependency := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		for _, banned := range forbidden {
			if dependency == banned {
				t.Errorf("the command depends on %s", banned)
			}
		}
	}
}

// TestCheckHelpExitsSuccessfully keeps the exit contract whole. The README
// defines 10 as invalid input or usage, and asking a command to describe itself
// is neither. The top-level --help exits 0; this one went through the flag
// package's own error path and exited 10.
func TestCheckHelpExitsSuccessfully(t *testing.T) {
	for _, flag := range []string{"--help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			var stdout, stderr strings.Builder
			code := run([]string{"check", flag}, &stdout, &stderr)

			if code != evidence.ExitPass {
				t.Fatalf("exit = %d, want %d", code, evidence.ExitPass)
			}
			if !strings.Contains(stdout.String(), "--intent") {
				t.Errorf("help does not describe the command:\n%s", stdout.String())
			}
		})
	}
}

// TestCheckHelpSaysOneThing keeps the command from describing itself twice.
//
// The flag package prints its own generated usage on any parse failure, --help
// included, so asking for help produced the hand-written text on stdout and a
// differently worded one on stderr. The comment beside checkUsage said the two
// places a reader can ask say the same thing; they did not.
func TestCheckHelpSaysOneThing(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run([]string{"check", "--help"}, &stdout, &stderr); code != evidence.ExitPass {
		t.Fatalf("exit = %d, want %d", code, evidence.ExitPass)
	}
	if stderr.String() != "" {
		t.Fatalf("a second usage was written to stderr:\n%s", stderr.String())
	}

	// And what it prints describes the command, rather than being an empty
	// constant nobody would notice.
	for _, part := range []string{"--intent", "--plan", "--format", "Exit codes:"} {
		if !strings.Contains(stdout.String(), part) {
			t.Errorf("help does not mention %q:\n%s", part, stdout.String())
		}
	}
}

// TestADataSourceIsReportedAsReadThroughTheWholeFlow covers the skips through
// the normalizer rather than around it.
//
// The skips were pinned by a test that built a NormalizedResource by hand and
// set ReadOnly itself, so nothing exercised the code that decides a resource is
// a read. Three of the four skips could be removed with the suite still green.
func TestADataSourceIsReportedAsReadThroughTheWholeFlow(t *testing.T) {
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "a", "tags": {"environment": "staging"},
	                          "block_public_acls": true}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "provider_name": "registry.terraform.io/hashicorp/aws",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"block_public_acls": true, "block_public_policy": true,
	                          "ignore_public_acls": true, "restrict_public_buckets": true}}},
	    {"address": "data.google_storage_bucket.existing", "mode": "data",
	     "type": "google_storage_bucket", "name": "existing",
	     "provider_name": "registry.terraform.io/hashicorp/google",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"name": "prod", "labels": {"environment": "production"}}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	    {"address": "data.google_storage_bucket.existing", "mode": "data",
	     "type": "google_storage_bucket", "name": "existing", "expressions": {}}
	  ]}}
	}`

	// The contract allows AWS only, and the read is of a GCP bucket tagged
	// production. Neither its cloud nor its environment is about the change.
	code, stdout, stderr := check(t,
		"--intent", write(t, "intent.json", privateIntent),
		"--plan", write(t, "plan.json", plan))

	if code != evidence.ExitPass {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s",
			code, evidence.ExitPass, stdout, stderr)
	}

	var bundle evidence.Bundle
	if err := json.Unmarshal([]byte(stdout), &bundle); err != nil {
		t.Fatalf("the output is not an Evidence Bundle: %v", err)
	}
	for _, finding := range bundle.Findings {
		if finding.Resource != nil &&
			strings.Contains(finding.Resource.Address, "data.google_storage_bucket") {
			t.Errorf("a read produced %s", finding.RuleID)
		}
	}
	// A read produces no record of its own at all. Checking only that it
	// raises nothing required would leave every skip but one removable with
	// the suite still green: the rules would emit non-required rows about a
	// resource that is not part of the change, and the decision would not
	// move.
	for _, unknown := range bundle.Unknowns {
		if unknown.ResourceAddress != nil &&
			strings.Contains(*unknown.ResourceAddress, "data.google_storage_bucket") {
			t.Errorf("a read was reported as %s; a verdict is about a change", unknown.CheckID)
		}
	}
}

// TestAnUnreadableVerbDoesNotHideADestruction joins the parser and the policy,
// which nothing did.
//
// The parser test proved an unrecognized verb is carried and flagged. The
// policy test proved the flag raises a required unknown. Neither put a
// destruction beside the unreadable verb, so the branch that replaced the
// finding with the doubt — turning BLOCK into UNKNOWN on a plan that states
// delete — was reachable only from the command, and the command had no test
// for it.
func TestAnUnreadableVerbDoesNotHideADestruction(t *testing.T) {
	plan := func(actions string) string {
		return `{
		  "format_version": "1.2",
		  "resource_changes": [
		    {"address": "aws_s3_bucket.gone", "mode": "managed", "type": "aws_s3_bucket",
		     "name": "gone", "provider_name": "registry.terraform.io/hashicorp/aws",
		     "change": {"actions": ` + actions + `, "before": {"bucket": "b"}, "after": null}}
		  ]
		}`
	}

	intentPath := write(t, "intent.json", privateIntent)

	plain, _, _ := check(t, "--intent", intentPath, "--plan", write(t, "a.json", plan(`["delete"]`)))
	if plain != evidence.ExitBlock {
		t.Fatalf("a plain delete exits %d, want %d", plain, evidence.ExitBlock)
	}

	withVerb, stdout, _ := check(t,
		"--intent", intentPath, "--plan", write(t, "b.json", plan(`["delete", "quiesce"]`)))
	if withVerb != evidence.ExitBlock {
		t.Fatalf("a delete beside an unreadable verb exits %d, want %d\n%s",
			withVerb, evidence.ExitBlock, stdout)
	}

	var bundle evidence.Bundle
	if err := json.Unmarshal([]byte(stdout), &bundle); err != nil {
		t.Fatalf("the output is not an Evidence Bundle: %v", err)
	}

	var destruction, doubt bool
	for _, finding := range bundle.Findings {
		if finding.RuleID == "DESTRUCTIVE_CHANGE" {
			destruction = true
		}
	}
	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID == "CHANGE_ACTION_RECOGNIZED" {
			doubt = true
		}
	}
	if !destruction {
		t.Error("the plan states delete and the destruction was not reported")
	}
	if !doubt {
		t.Error("the unreadable verb was not reported")
	}
}

// TestAWithheldSourceReachesTheReport covers the admissibility boundary at the
// layer where it is observable.
//
// It had tests only in the normalizer, both asserting on a fact and both in
// the prevention direction, so the two defects it introduced — an ambiguity
// resolved by deleting a candidate, and a grant discarded without a record —
// were invisible to the suite and to every committed fixture.
func TestAWithheldSourceReachesTheReport(t *testing.T) {
	// A container naming two accounts, one managed and one read, which is what
	// Terraform writes for a conditional.
	conditional := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.locked", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "locked",
	     "provider_name": "registry.terraform.io/hashicorp/azurerm",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "l", "allow_nested_items_to_be_public": false}}},
	    {"address": "data.azurerm_storage_account.legacy", "mode": "data",
	     "type": "azurerm_storage_account", "name": "legacy",
	     "provider_name": "registry.terraform.io/hashicorp/azurerm",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"name": "g", "allow_nested_items_to_be_public": true}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "provider_name": "registry.terraform.io/hashicorp/azurerm",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.locked", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "locked", "expressions": {}},
	    {"address": "data.azurerm_storage_account.legacy", "mode": "data",
	     "type": "azurerm_storage_account", "name": "legacy", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "data.azurerm_storage_account.legacy.id", "data.azurerm_storage_account.legacy",
	       "azurerm_storage_account.locked.id", "azurerm_storage_account.locked"]}}}
	  ]}}
	}`

	everyCloud := strings.Replace(privateIntent, `["aws"]`, `["aws", "azure", "gcp"]`, 1)

	code, stdout, stderr := check(t,
		"--intent", write(t, "intent.json", everyCloud),
		"--plan", write(t, "plan.json", conditional))

	if code != evidence.ExitUnknown {
		t.Fatalf("exit = %d, want %d; a candidate was withheld and the question is open\n%s\n%s",
			code, evidence.ExitUnknown, stdout, stderr)
	}
	if !strings.Contains(stdout, "data.azurerm_storage_account.legacy") {
		t.Fatalf("the report does not say what was withheld:\n%s", stdout)
	}

	var bundle evidence.Bundle
	if err := json.Unmarshal([]byte(stdout), &bundle); err != nil {
		t.Fatalf("the output is not an Evidence Bundle: %v", err)
	}
	var withheld bool
	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID == "SOURCE_WITHHELD" {
			withheld = true
		}
	}
	if !withheld {
		t.Errorf("no record names the withheld source: %v", bundle.Unknowns)
	}
}

// TestAPlanValueInARecordDoesNotCostAVerdict keeps an operational failure from
// replacing an answer the tool could give.
//
// Every plan-derived string in the bundle is carried on one line, because the
// contract forbids a break in anything rendered as inline text. A record about
// a withheld source interpolates a resource address, and a for_each key holding
// a newline is legal Terraform — so a plan the tool could judge produced exit
// 11 and no verdict instead.
func TestAPlanValueInARecordDoesNotCostAVerdict(t *testing.T) {
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.gate", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "gate",
	     "provider_name": "registry.terraform.io/hashicorp/azurerm",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "g", "allow_nested_items_to_be_public": false}}},
	    {"address": "data.azurerm_storage_account.legacy[\"x\ny\"]", "mode": "data",
	     "type": "azurerm_storage_account", "name": "legacy", "index": "x\ny",
	     "provider_name": "registry.terraform.io/hashicorp/azurerm",
	     "change": {"actions": ["read"], "before": null,
	                "after": {"name": "l", "allow_nested_items_to_be_public": true}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "provider_name": "registry.terraform.io/hashicorp/azurerm",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.gate", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "gate", "expressions": {}},
	    {"address": "data.azurerm_storage_account.legacy", "mode": "data",
	     "type": "azurerm_storage_account", "name": "legacy",
	     "for_each_expression": {"constant_value": ["x\ny"]}, "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "data.azurerm_storage_account.legacy[\"x\ny\"].id",
	       "data.azurerm_storage_account.legacy[\"x\ny\"]",
	       "azurerm_storage_account.gate.id", "azurerm_storage_account.gate"]}}}
	  ]}}
	}`

	everyCloud := strings.Replace(privateIntent, `["aws"]`, `["aws", "azure", "gcp"]`, 1)
	code, stdout, stderr := check(t,
		"--intent", write(t, "intent.json", everyCloud),
		"--plan", write(t, "plan.json", plan))

	if code == evidence.ExitInternal {
		t.Fatalf("a plan the tool could judge produced an internal error:\n%s", stderr)
	}
	if stdout == "" {
		t.Fatalf("no report was produced (exit %d):\n%s", code, stderr)
	}

	var bundle evidence.Bundle
	if err := json.Unmarshal([]byte(stdout), &bundle); err != nil {
		t.Fatalf("the output is not an Evidence Bundle: %v", err)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("the bundle does not satisfy its own contract: %v", err)
	}

	// And the record that carries the address is actually there, or the test
	// would pass without reaching the path it exists for.
	var named bool
	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID == "SOURCE_WITHHELD" {
			named = true
			if strings.ContainsAny(unknown.Reason, "\r\n") {
				t.Errorf("the record carries a line break: %q", unknown.Reason)
			}
		}
	}
	if !named {
		t.Fatalf("the withheld read was not recorded, so this test did not reach its path:\n%s",
			stdout)
	}
}

// TestTwoContractsAtOnePathAreTellableApart makes the sentence in
// docs/INTENT-CONTRACT.md true: InfraProof records the contract's digest.
//
// The digest was computed at load and reached no output, so a bundle recorded
// only the path a contract was read from. Two different contracts at one path
// — a file edited between runs, a path that is a symlink, a checkout on another
// branch — produced byte-identical evidence, and the plan was identifiable
// while the thing it was compared against was not.
func TestTwoContractsAtOnePathAreTellableApart(t *testing.T) {
	dir := t.TempDir()
	contract := filepath.Join(dir, "intent.json")
	plan := write(t, "plan.json", passingPlan)

	render := func(body string) string {
		t.Helper()
		if err := os.WriteFile(contract, []byte(body), 0o600); err != nil {
			t.Fatalf("writing the contract: %v", err)
		}
		code, stdout, stderr := check(t, "--intent", contract, "--plan", plan)
		if code != evidence.ExitPass {
			t.Fatalf("exit = %d: %s", code, stderr)
		}
		return stdout
	}

	first := render(privateIntent)
	second := render(strings.Replace(privateIntent,
		`"change_id": "add-private-staging-assets"`, `"change_id": "add-private-staging-buckets"`, 1))

	if first == second {
		t.Fatal("two different contracts at one path produced identical evidence")
	}

	var bundle evidence.Bundle
	if err := json.Unmarshal([]byte(first), &bundle); err != nil {
		t.Fatalf("the bundle does not parse: %v", err)
	}
	if !strings.HasPrefix(bundle.Subject.IntentDigest, "sha256:") {
		t.Errorf("intent digest = %q, want a sha256 digest", bundle.Subject.IntentDigest)
	}
}
