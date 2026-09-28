package verify_test

import (
	"os"
	"path/filepath"
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
		write(t, "plan.json", publicPlan))
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
			bundle, err := verify.FromFiles(paths[0], paths[1])
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
