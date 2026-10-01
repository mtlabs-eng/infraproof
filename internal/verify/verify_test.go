package verify_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/verify"
)

const contract = `{
  "schema_version": "1.0",
  "change_id": "add-private-staging-assets",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage", "exposure": "private"}]
}`

const publicPlan = `{
  "format_version": "1.2",
  "resource_changes": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "tags": {"environment": "staging"}}}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "acl": "public-read"}}}
  ],
  "configuration": {"root_module": {"resources": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "expressions": {}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "expressions": {"bucket": {"references": [
       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
  ]}}
}`

func write(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// TestOneVerificationForEveryCaller is what makes "the adapter returns what the
// command returns" a property rather than a coincidence.
//
// The command used to wire the five steps itself. A second caller wiring them
// again would agree until one of them was changed, and the milestone's
// criterion — that MCP results are semantically identical to CLI results for
// the same files — would then be false in a way no test could see.
func TestOneVerificationForEveryCaller(t *testing.T) {
	bundle, err := verify.FromFiles(
		write(t, "intent.json", contract),
		write(t, "plan.json", publicPlan),
		verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}

	if bundle.Decision != evidence.DecisionBlock {
		t.Errorf("decision = %q, want BLOCK for a public-read bucket under a private contract",
			bundle.Decision)
	}
	if err := bundle.Validate(); err != nil {
		t.Errorf("the bundle does not satisfy its own contract: %v", err)
	}
	if bundle.Subject.PlanDigest == "" || bundle.Subject.IntentDigest == "" {
		t.Error("the bundle does not identify the bytes it was reached from")
	}
}

// TestUnreadableInputIsAnErrorAndNotAVerdict keeps the two apart at the new
// boundary, as the command already kept them apart at its own: a report reached
// from inputs that could not be read would be a verdict about nothing.
func TestUnreadableInputIsAnErrorAndNotAVerdict(t *testing.T) {
	good := write(t, "intent.json", contract)
	plan := write(t, "plan.json", publicPlan)

	cases := map[string][2]string{
		"no such contract":           {filepath.Join(t.TempDir(), "absent.json"), plan},
		"no such plan":               {good, filepath.Join(t.TempDir(), "absent.json")},
		"contract is not a contract": {write(t, "bad.json", `{"schema_version": "1.0"}`), plan},
		"plan is not a plan":         {good, write(t, "bad.json", `{"format_version": "9.0"}`)},
		"plan is not JSON":           {good, write(t, "bad.json", `schema_version: "1.0"`)},
	}

	for name, paths := range cases {
		t.Run(name, func(t *testing.T) {
			bundle, err := verify.FromFiles(paths[0], paths[1], verify.Options{})
			if err == nil {
				t.Fatalf("unreadable input produced a verdict: %q", bundle.Decision)
			}
			if bundle.Decision != "" {
				t.Errorf("a failed verification returned a decision as well as an error: %q",
					bundle.Decision)
			}
		})
	}
}

// configuredPlan is the plan the shipped aws configuration matches, by address.
const configuredPlan = `{
  "format_version": "1.2",
  "resource_changes": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "tags": {"environment": "staging"}}}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "acl": "public-read"}}}
  ],
  "configuration": {"root_module": {"resources": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "expressions": {}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "expressions": {"bucket": {"references": [
       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
  ]}}
}`

// awsConfiguration is the configuration directory internal/tfconfig ships for
// exactly these addresses.
func awsConfiguration() string {
	return filepath.Join("..", "tfconfig", "testdata", "aws")
}

// TestNoConfigurationDirectoryChangesNothing covers the milestone's
// compatibility criterion. Without the directory the verification is the one it
// was before this milestone, byte for byte.
func TestNoConfigurationDirectoryChangesNothing(t *testing.T) {
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", publicPlan)

	bundle, err := verify.FromFiles(intent, plan, verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(raw), "location") {
		t.Fatalf("a verification with no configuration directory carried a location: %s", raw)
	}
}

// TestAConfigurationDirectoryAddsOnlyLocations covers the other half of the same
// rule: locations are additional and never load-bearing. The two bundles are
// compared field by field with the locations stripped out, so anything else that
// moved would show here.
func TestAConfigurationDirectoryAddsOnlyLocations(t *testing.T) {
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", configuredPlan)

	plain, err := verify.FromFiles(intent, plan, verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	located, err := verify.FromFiles(intent, plan, verify.Options{ConfigRoot: awsConfiguration()})
	if err != nil {
		t.Fatalf("FromFiles with a configuration directory: %v", err)
	}

	if evidence.ExitCode(plain.Decision) != evidence.ExitCode(located.Decision) {
		t.Fatalf("exit code changed: %d then %d",
			evidence.ExitCode(plain.Decision), evidence.ExitCode(located.Decision))
	}

	// Something must have been located, or this test would pass by locating
	// nothing at all.
	if located.Findings[0].Resource.Location == nil {
		t.Fatal("nothing was located, so this test proves nothing")
	}

	stripped := located
	stripped.Findings = slices.Clone(located.Findings)
	for i := range stripped.Findings {
		finding := &stripped.Findings[i]
		if finding.Resource != nil {
			resource := *finding.Resource
			resource.Location = nil
			finding.Resource = &resource
		}
		finding.Evidence = slices.Clone(finding.Evidence)
		for j := range finding.Evidence {
			finding.Evidence[j].Location = nil
		}
	}
	stripped.Unknowns = slices.Clone(located.Unknowns)
	for i := range stripped.Unknowns {
		stripped.Unknowns[i].Evidence = slices.Clone(stripped.Unknowns[i].Evidence)
		for j := range stripped.Unknowns[i].Evidence {
			stripped.Unknowns[i].Evidence[j].Location = nil
		}
	}

	want, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	got, err := json.Marshal(stripped)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("locating changed more than the locations\n--- with locations stripped ---\n%s\n--- without ---\n%s", got, want)
	}
}

// TestAConfigurationDirectoryThatCannotBeReadIsAnError keeps the distinction the
// rest of this package keeps. A directory that cannot be opened was the caller's
// mistake, not a fact about the change, and reporting a verdict from it would
// hide the mistake.
func TestAConfigurationDirectoryThatCannotBeReadIsAnError(t *testing.T) {
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", publicPlan)

	bundle, err := verify.FromFiles(intent, plan,
		verify.Options{ConfigRoot: filepath.Join(t.TempDir(), "nowhere")})
	if err == nil {
		t.Fatalf("a configuration directory that is not there produced a verdict: %q", bundle.Decision)
	}
	if bundle.Decision != "" {
		t.Errorf("a failed verification returned a decision as well as an error: %q", bundle.Decision)
	}
}

// TestALocatedBundleStillSatisfiesItsContract covers the obligation every
// producer in this build has: what it emits validates.
func TestALocatedBundleStillSatisfiesItsContract(t *testing.T) {
	bundle, err := verify.FromFiles(
		write(t, "intent.json", contract),
		write(t, "plan.json", configuredPlan),
		verify.Options{ConfigRoot: awsConfiguration()})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("a located bundle does not satisfy its own contract: %v", err)
	}
}

// TestNoConfigurationDirectoryReadsNoFile covers what "no flag, no file read"
// means, which the test beside it could not see.
//
// Independent review removed the guard on an empty ConfigRoot and the whole suite
// still passed: filepath.Abs("") resolves to the process working directory, so a
// plain run from inside a Terraform directory read its .tf files and reported
// positions from them. The test that claimed to cover this passed only because
// the test binary's working directory happened to hold no .tf file. This one puts
// one there.
func TestNoConfigurationDirectoryReadsNoFile(t *testing.T) {
	// Resolved before the working directory changes, or they name nothing.
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", configuredPlan)

	elsewhere := t.TempDir()
	configuration, err := os.ReadFile(filepath.Join(awsConfiguration(), "main.tf"))
	if err != nil {
		t.Fatalf("reading the shipped configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "main.tf"), configuration, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Chdir(elsewhere)

	bundle, err := verify.FromFiles(intent, plan, verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(raw), "location") {
		t.Fatalf("a run with no configuration directory read the working directory:\n%s", raw)
	}
}
