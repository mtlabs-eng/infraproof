package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

// TestTheServerWillNotStartWithoutARoot is the permission decision at the only
// place an operator makes it. A server told nowhere to read from would
// otherwise be told everywhere.
func TestTheServerWillNotStartWithoutARoot(t *testing.T) {
	for name, args := range map[string][]string{
		"no flags at all":       {"mcp"},
		"an absent root":        {"mcp", "--root", filepath.Join(t.TempDir(), "nowhere")},
		"a root that is a file": {"mcp", "--root", write(t, "plan.json", "{}")},
		"a positional argument": {"mcp", "--root", t.TempDir(), "extra"},
	} {
		t.Run(name, func(t *testing.T) {
			var stdout, stderr strings.Builder
			if code := run(args, &stdout, &stderr); code != evidence.ExitInvalidInput {
				t.Errorf("exit = %d, want %d", code, evidence.ExitInvalidInput)
			}
			if stdout.String() != "" {
				t.Errorf("stdout = %q; the protocol stream must carry nothing else", stdout.String())
			}
			if stderr.String() == "" {
				t.Error("a refusal to start must explain itself")
			}
		})
	}
}

// TestTheCommandAndTheToolReachOneVerdict is the milestone's criterion at the
// level a user meets it: the same two files, through the command and through
// the adapter, and one answer.
func TestTheCommandAndTheToolReachOneVerdict(t *testing.T) {
	dir := t.TempDir()
	intentPath := filepath.Join(dir, "intent.json")
	planPath := filepath.Join(dir, "plan.json")
	for path, body := range map[string]string{intentPath: privateIntent, planPath: blockedPlan} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("writing: %v", err)
		}
	}

	var cliOut, cliErr strings.Builder
	code := run([]string{"check", "--intent", intentPath, "--plan", planPath}, &cliOut, &cliErr)
	if code != evidence.ExitBlock {
		t.Fatalf("check exit = %d, want %d: %s", code, evidence.ExitBlock, cliErr.String())
	}

	request, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      "analyze_change",
			"arguments": map[string]any{"intent_path": intentPath, "plan_path": planPath},
		},
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	stdin, stdout := os.Stdin, strings.Builder{}
	replaceStdin(t, string(request)+"\n")
	defer func() { os.Stdin = stdin }()

	if code := run([]string{"mcp", "--root", dir}, &stdout, &strings.Builder{}); code != evidence.ExitPass {
		t.Fatalf("mcp exit = %d", code)
	}

	var response struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(stdout.String())), &response); err != nil {
		t.Fatalf("the server wrote something unreadable: %v\n%s", err, stdout.String())
	}
	if response.Result.IsError || len(response.Result.Content) == 0 {
		t.Fatalf("the tool failed: %s", stdout.String())
	}

	var throughTool, throughCommand evidence.Bundle
	if err := json.Unmarshal([]byte(response.Result.Content[0].Text), &throughTool); err != nil {
		t.Fatalf("the tool returned no bundle: %v", err)
	}
	if err := json.Unmarshal([]byte(cliOut.String()), &throughCommand); err != nil {
		t.Fatalf("the command returned no bundle: %v", err)
	}

	if throughTool.Decision != throughCommand.Decision {
		t.Errorf("two interfaces, two decisions: %q through the tool, %q through the command",
			throughTool.Decision, throughCommand.Decision)
	}
	if len(throughTool.Findings) != len(throughCommand.Findings) {
		t.Errorf("the tool reported %d findings and the command %d",
			len(throughTool.Findings), len(throughCommand.Findings))
	}
	if throughTool.Subject.PlanDigest != throughCommand.Subject.PlanDigest {
		t.Error("the two interfaces disagree about which plan they read")
	}
}

// replaceStdin points os.Stdin at a pipe holding the given text.
func replaceStdin(t *testing.T, text string) {
	t.Helper()

	read, write, err := os.Pipe()
	if err != nil {
		t.Fatalf("Pipe: %v", err)
	}
	go func() {
		defer write.Close()
		_, _ = write.WriteString(text)
	}()
	os.Stdin = read
	t.Cleanup(func() { read.Close() })
}
