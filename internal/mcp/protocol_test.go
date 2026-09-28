package mcp_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/mcp"
)

// call sends one line to the server and returns the one line it writes back,
// decoded. A request that produces no response returns false.
func call(t *testing.T, server *mcp.Server, request string) (map[string]any, bool) {
	t.Helper()

	var out strings.Builder
	if err := server.Serve(strings.NewReader(request+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	line := strings.TrimSpace(out.String())
	if line == "" {
		return nil, false
	}
	if strings.Contains(line, "\n") {
		t.Fatalf("one request produced more than one response: %q", line)
	}

	var response map[string]any
	if err := json.Unmarshal([]byte(line), &response); err != nil {
		t.Fatalf("the server wrote something that is not JSON: %q", line)
	}
	return response, true
}

func testServer(t *testing.T) *mcp.Server {
	t.Helper()
	server, err := mcp.New(mcp.Options{Roots: []string{t.TempDir()}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return server
}

// TestAMalformedRequestIsAnsweredAndNotObeyed is the whole of this boundary's
// job. Everything arriving here was written by something else, and the two
// failures that matter are answering the wrong thing and not answering at all.
func TestAMalformedRequestIsAnsweredAndNotObeyed(t *testing.T) {
	cases := map[string]string{
		"not JSON":                      `{"jsonrpc":`,
		"not an object":                 `[1, 2, 3]`,
		"no method":                     `{"jsonrpc": "2.0", "id": 1}`,
		"method is not a string":        `{"jsonrpc": "2.0", "id": 1, "method": 7}`,
		"unknown method":                `{"jsonrpc": "2.0", "id": 1, "method": "nonesuch"}`,
		"wrong protocol":                `{"jsonrpc": "1.0", "id": 1, "method": "tools/list"}`,
		"params of the wrong kind":      `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": 7}`,
		"no tool name":                  `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}}`,
		"unknown tool":                  `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "rm_rf", "arguments": {}}}`,
		"arguments of the wrong kind":   `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "analyze_change", "arguments": 7}}`,
		"a missing argument":            `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "analyze_change", "arguments": {"plan_path": "p"}}}`,
		"an argument of the wrong kind": `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "analyze_change", "arguments": {"intent_path": 7, "plan_path": "p"}}}`,
		"an unknown argument":           `{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "analyze_change", "arguments": {"intent_path": "i", "plan_path": "p", "shell": "sh"}}}`,
	}

	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			response, answered := call(t, testServer(t), request)
			if !answered {
				t.Fatal("a malformed request went unanswered")
			}
			if response["jsonrpc"] != "2.0" {
				t.Errorf("the response does not speak the protocol: %v", response["jsonrpc"])
			}
			failure, ok := response["error"].(map[string]any)
			if !ok {
				t.Fatalf("a malformed request produced a result: %v", response)
			}
			if _, ok := failure["code"].(float64); !ok {
				t.Errorf("the error carries no code: %v", failure)
			}
			message, ok := failure["message"].(string)
			if !ok || strings.TrimSpace(message) == "" {
				t.Errorf("the error says nothing: %v", failure)
			}
			if len(message) > 500 {
				t.Errorf("the error is %d bytes; it repeats its input rather than describing it",
					len(message))
			}
		})
	}
}

// TestANotificationIsNotAnswered holds the one case where silence is the
// protocol. A request without an id expects no reply, and answering it puts a
// response on the stream the client is not reading for.
func TestANotificationIsNotAnswered(t *testing.T) {
	if _, answered := call(t, testServer(t),
		`{"jsonrpc": "2.0", "method": "notifications/initialized"}`); answered {
		t.Error("a notification was answered")
	}
}

// TestTheServerDescribesItselfBeforeItIsUsed covers the handshake and the
// catalogue, which is how a client learns what may be asked.
func TestTheServerDescribesItselfBeforeItIsUsed(t *testing.T) {
	server := testServer(t)

	initialize, _ := call(t, server, `{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t"}}}`)
	result, ok := initialize["result"].(map[string]any)
	if !ok {
		t.Fatalf("initialize did not produce a result: %v", initialize)
	}
	if _, ok := result["protocolVersion"].(string); !ok {
		t.Errorf("the server names no protocol version: %v", result)
	}
	if _, ok := result["capabilities"].(map[string]any); !ok {
		t.Errorf("the server declares no capabilities: %v", result)
	}

	listed, _ := call(t, server, `{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}`)
	catalogue, ok := listed["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/list did not produce a result: %v", listed)
	}
	tools, ok := catalogue["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("the server offers no tools: %v", catalogue)
	}

	names := map[string]bool{}
	for _, entry := range tools {
		tool, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("a tool is not an object: %v", entry)
		}
		name, _ := tool["name"].(string)
		names[name] = true
		if description, _ := tool["description"].(string); strings.TrimSpace(description) == "" {
			t.Errorf("%s describes itself to nobody", name)
		}
		// A client validates arguments against this before sending them, and a
		// tool without one is a tool whose input is whatever arrives.
		if _, ok := tool["inputSchema"].(map[string]any); !ok {
			t.Errorf("%s declares no input schema: %v", name, tool)
		}
	}
	for _, want := range []string{"analyze_change", "explain_finding"} {
		if !names[want] {
			t.Errorf("the milestone's tool %q is not offered; the server offers %v", want, names)
		}
	}
}

// TestEveryRequestIsAnsweredExactlyOnce keeps the stream usable. A second
// response to one id, or none at all, leaves a client waiting on a reply that
// will never come or reading one it cannot place.
func TestEveryRequestIsAnsweredExactlyOnce(t *testing.T) {
	requests := []string{
		`{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}`,
		`{"jsonrpc": "2.0", "method": "notifications/initialized"}`,
		`{"jsonrpc": "2.0", "id": "two", "method": "tools/list"}`,
		`{"jsonrpc": "2.0", "id": 3, "method": "nonesuch"}`,
		`not json at all`,
	}

	var out strings.Builder
	server := testServer(t)
	if err := server.Serve(strings.NewReader(strings.Join(requests, "\n")+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	var seen []any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var response map[string]any
		if err := json.Unmarshal([]byte(line), &response); err != nil {
			t.Fatalf("the server wrote something that is not JSON: %q", line)
		}
		seen = append(seen, response["id"])
	}
	if len(seen) != 4 {
		t.Fatalf("four requests expected an answer and %d were written: %v", len(seen), seen)
	}
}
