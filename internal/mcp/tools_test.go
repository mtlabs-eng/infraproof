package mcp_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/mcp"
	"github.com/mtlabs-eng/infraproof/internal/render"
	"github.com/mtlabs-eng/infraproof/internal/verify"
)

const privateIntent = `{
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

// root builds a directory holding an intent and a plan, and a server over it.
func root(t *testing.T, contract, plan string) (*mcp.Server, string, string) {
	t.Helper()

	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	planPath := filepath.Join(dir, "plan.json")
	for path, body := range map[string]string{intentPath: contract, planPath: plan} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}

	server, err := mcp.New(mcp.Options{Roots: []string{dir}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server, intentPath, planPath
}

// toolCall sends one tools/call and returns the text content and whether the
// tool reported a failure.
func toolCall(t *testing.T, server *mcp.Server, name string, arguments map[string]any) (string, bool) {
	t.Helper()

	request, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": arguments},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	response, answered := call(t, server, string(request))
	if !answered {
		t.Fatal("a tools/call went unanswered")
	}
	if failure, ok := response["error"].(map[string]any); ok {
		t.Fatalf("the request was refused as a request: %v", failure)
	}
	result, ok := response["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", response)
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("the tool returned no content: %v", result)
	}
	block, _ := content[0].(map[string]any)
	text, _ := block["text"].(string)
	failed, _ := result["isError"].(bool)
	return text, failed
}

// TestTheAdapterReturnsWhatTheVerifierReturns is the milestone's criterion, and
// it is asked of the bytes rather than of the decision: a tool that agreed on
// the verdict and differed on the evidence would still be telling an agent
// something the command does not.
//
// Nothing is set aside. The report names the file the caller named, so the two
// interfaces produce one document. An earlier form recorded the path after
// resolving its links, which is more of the filesystem than the caller handed
// over -- and everything here may be repeated by a model into a commit message.
func TestTheAdapterReturnsWhatTheVerifierReturns(t *testing.T) {
	server, intentPath, planPath := root(t, privateIntent, publicPlan)

	text, failed := toolCall(t, server, "analyze_change", map[string]any{
		"intent_path": intentPath, "plan_path": planPath,
	})
	if failed {
		t.Fatalf("the tool reported a failure: %s", text)
	}

	bundle, err := verify.FromFiles(intentPath, planPath)
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	want, err := render.JSON(bundle)
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	if text != string(want) {
		t.Errorf("the adapter and the verifier disagree.\n--- adapter ---\n%s\n--- verifier ---\n%s",
			text, want)
	}

	var returned evidence.Bundle
	if err := json.Unmarshal([]byte(text), &returned); err != nil {
		t.Fatalf("the tool returned something that is not a bundle: %v", err)
	}
	if returned.Decision != evidence.DecisionBlock {
		t.Errorf("decision = %q, want BLOCK", returned.Decision)
	}
	if returned.Subject.IntentSource != intentPath {
		t.Errorf("the report names a path the caller did not supply.\n want %q\n  got %q",
			intentPath, returned.Subject.IntentSource)
	}
}

// TestTheReportNamesNoMoreOfTheFilesystemThanWasGiven is the disclosure half of
// the same decision. A caller that names a file relative to a root, or through
// a link, learns nothing further about where that root is.
func TestTheReportNamesNoMoreOfTheFilesystemThanWasGiven(t *testing.T) {
	_, intentPath, planPath := root(t, privateIntent, publicPlan)

	dir := filepath.Dir(intentPath)
	link := filepath.Join(t.TempDir(), "through-a-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Skipf("this platform will not make a symlink: %v", err)
	}
	server, err := mcp.New(mcp.Options{Roots: []string{dir, link}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	spelled := filepath.Join(link, filepath.Base(intentPath))
	text, failed := toolCall(t, server, "analyze_change", map[string]any{
		"intent_path": spelled, "plan_path": planPath,
	})
	if failed {
		t.Fatalf("the tool reported a failure: %s", text)
	}

	var returned evidence.Bundle
	if err := json.Unmarshal([]byte(text), &returned); err != nil {
		t.Fatalf("the tool returned something that is not a bundle: %v", err)
	}
	if returned.Subject.IntentSource != spelled {
		t.Errorf("the report resolved the caller's path into another one.\n want %q\n  got %q",
			spelled, returned.Subject.IntentSource)
	}
}

// TestNoToolReadsOutsideItsRoots is the confinement seen from the outside. The
// guard is tested on its own; this is the assertion that the tools use it.
func TestNoToolReadsOutsideItsRoots(t *testing.T) {
	server, intentPath, planPath := root(t, privateIntent, publicPlan)

	outside := t.TempDir()
	elsewhere := filepath.Join(outside, "plan.json")
	if err := os.WriteFile(elsewhere, []byte(publicPlan), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	for name, args := range map[string]map[string]any{
		"the plan is elsewhere":     {"intent_path": intentPath, "plan_path": elsewhere},
		"the contract is elsewhere": {"intent_path": filepath.Join(outside, "intent.json"), "plan_path": planPath},
		"climbing out":              {"intent_path": intentPath, "plan_path": filepath.Join(filepath.Dir(planPath), "..", filepath.Base(outside), "plan.json")},
		"an absolute escape":        {"intent_path": intentPath, "plan_path": "/etc/hosts"},
	} {
		t.Run(name, func(t *testing.T) {
			for _, tool := range []string{"analyze_change", "explain_finding"} {
				arguments := map[string]any{}
				for k, v := range args {
					arguments[k] = v
				}
				if tool == "explain_finding" {
					arguments["rule_id"] = "STORAGE_PUBLIC"
				}

				text, failed := toolCall(t, server, tool, arguments)
				if !failed {
					t.Errorf("%s read outside its roots: %s", tool, text)
				}
				if strings.Contains(text, "localhost") || strings.Contains(text, "bucket") {
					t.Errorf("%s returned content from outside its roots: %s", tool, text)
				}
			}
		})
	}
}

// TestATooLargeFileIsRefusedRatherThanRead covers the bound. Half a plan parses
// into a different change, so the file is refused and not truncated.
func TestATooLargeFileIsRefusedRatherThanRead(t *testing.T) {
	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(intentPath, []byte(privateIntent), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Sparse: the bound is on what is read, and writing sixty-four megabytes of
	// content to make the point would make this the slowest test here. A sparse
	// file reads as zeroes, which is more than the bound and not a plan either.
	file, err := os.Create(planPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := file.Truncate(mcp.MaxInputBytes + 1); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	server, err := mcp.New(mcp.Options{Roots: []string{dir}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	text, failed := toolCall(t, server, "analyze_change", map[string]any{
		"intent_path": intentPath, "plan_path": planPath,
	})
	if !failed {
		t.Fatalf("a file past the bound was read: %s", text)
	}
	if !strings.Contains(text, "longer than") {
		t.Errorf("the refusal does not say there is a bound: %s", text)
	}
}

// TestNoSensitiveValueReachesAToolResult is the safety rule at the boundary
// where it is easiest to break: the place a value becomes text an agent reads,
// and then repeats.
func TestNoSensitiveValueReachesAToolResult(t *testing.T) {
	const secret = "SUPER-SECRET-POLICY-DOCUMENT"
	plan := `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "assets", "tags": {"environment": "staging"}}}},
	    {"address": "aws_s3_bucket_policy.assets", "mode": "managed",
	     "type": "aws_s3_bucket_policy", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"bucket": "assets", "policy": "` + secret + `"},
	                "after_sensitive": {"policy": true}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_policy.assets", "mode": "managed",
	     "type": "aws_s3_bucket_policy", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`

	server, intentPath, planPath := root(t, privateIntent, plan)
	for _, tool := range []string{"analyze_change", "explain_finding"} {
		arguments := map[string]any{"intent_path": intentPath, "plan_path": planPath}
		if tool == "explain_finding" {
			arguments["rule_id"] = "STORAGE_PUBLIC"
		}
		text, _ := toolCall(t, server, tool, arguments)
		if strings.Contains(text, secret) {
			t.Errorf("%s returned a value the plan marked sensitive: %s", tool, text)
		}
	}
}

// TestExplainFindingAnswersFromThePlanAsItIsNow is the consequence of holding
// no state: the tool re-runs the verification, so a plan edited between calls
// is described as it is rather than as it was.
func TestExplainFindingAnswersFromThePlanAsItIsNow(t *testing.T) {
	server, intentPath, planPath := root(t, privateIntent, publicPlan)

	text, failed := toolCall(t, server, "explain_finding", map[string]any{
		"intent_path": intentPath, "plan_path": planPath, "rule_id": "STORAGE_PUBLIC",
	})
	if failed {
		t.Fatalf("the tool reported a failure: %s", text)
	}
	if !strings.Contains(text, "STORAGE_PUBLIC") || !strings.Contains(text, "aws_s3_bucket.assets") {
		t.Fatalf("the finding was not explained: %s", text)
	}

	// The same call, after the grant is removed from the plan.
	fixed := strings.Replace(publicPlan, `"acl": "public-read"`, `"acl": "private"`, 1)
	if err := os.WriteFile(planPath, []byte(fixed), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	after, failed := toolCall(t, server, "explain_finding", map[string]any{
		"intent_path": intentPath, "plan_path": planPath, "rule_id": "STORAGE_PUBLIC",
	})
	if failed {
		t.Fatalf("the tool reported a failure: %s", after)
	}
	if strings.Contains(after, `"claim"`) {
		t.Errorf("the tool answered from a plan that no longer exists: %s", after)
	}
	if !strings.Contains(after, "no finding under that rule") {
		t.Errorf("the tool does not say that the rule reported nothing: %s", after)
	}
}

// TestOnlyARegularFileIsRead closes the gap a size check leaves open. A device
// or a named pipe reports a size that says nothing about how much reading it
// will produce, and /dev/zero linked into a root would be read until something
// else stopped it.
func TestOnlyARegularFileIsRead(t *testing.T) {
	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	if err := os.WriteFile(intentPath, []byte(privateIntent), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	pipe := filepath.Join(dir, "plan.json")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Skipf("this platform will not make a named pipe: %v", err)
	}

	server, err := mcp.New(mcp.Options{Roots: []string{dir}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		text, failed := toolCall(t, server, "analyze_change", map[string]any{
			"intent_path": intentPath, "plan_path": pipe,
		})
		if !failed {
			t.Errorf("a named pipe was read as a plan: %s", text)
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reading a named pipe did not return; the server is waiting on a writer that " +
			"will never come")
	}
}

// TestAVerificationThatWillNotFinishIsAbandoned is the other half of the
// milestone's bound. Input size bounds the bytes and not the work: normalization
// grows faster than the plan does, so a file well inside the size limit can ask
// for more time than a caller has.
//
// The answer is an answer, not a hang: the caller is told the verification was
// abandoned, and gets to decide what to do about it.
func TestAVerificationThatWillNotFinishIsAbandoned(t *testing.T) {
	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(intentPath, []byte(privateIntent), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if err := os.WriteFile(planPath, []byte(wideplan(2000)), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	server, err := mcp.New(mcp.Options{Roots: []string{dir}, Timeout: time.Nanosecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	text, failed := toolCall(t, server, "analyze_change", map[string]any{
		"intent_path": intentPath, "plan_path": planPath,
	})
	if !failed {
		t.Fatalf("a verification past its deadline returned a verdict: %.200s", text)
	}
	if !strings.Contains(text, "longer than") {
		t.Errorf("the refusal does not say what happened: %s", text)
	}
}

// wideplan builds a plan of n buckets, which is enough work to outlast a
// deadline measured in nanoseconds without being slow to run.
func wideplan(buckets int) string {
	var changes, resources []string
	for i := range buckets {
		address := fmt.Sprintf("aws_s3_bucket.b%d", i)
		changes = append(changes, fmt.Sprintf(`{"address": %q, "mode": "managed",
		  "type": "aws_s3_bucket", "name": "b%d", "provider_name": "p",
		  "change": {"actions": ["create"], "before": null, "after": {"bucket": "b%d"}}}`,
			address, i, i))
		resources = append(resources, fmt.Sprintf(`{"address": %q, "mode": "managed",
		  "type": "aws_s3_bucket", "name": "b%d", "expressions": {}}`, address, i))
	}
	return `{"format_version": "1.2", "resource_changes": [` + strings.Join(changes, ",") +
		`], "configuration": {"root_module": {"resources": [` + strings.Join(resources, ",") + `]}}}`
}
