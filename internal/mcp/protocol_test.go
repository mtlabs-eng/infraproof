package mcp_test

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

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

// TestEveryValidJSONMessageIsAnswered covers the gap between "not JSON" and
// "not a request".
//
// A bare null parses into the zero request, which has no id, which reads as a
// notification -- so the server said nothing at all, to a client that was
// waiting. The specification separates the two: a parse error is for input that
// is not JSON, and everything that is JSON and is not a request object is an
// invalid request, answered with a null id.
func TestEveryValidJSONMessageIsAnswered(t *testing.T) {
	cases := map[string]struct {
		request string
		code    float64
	}{
		"a bare null":             {`null`, -32600},
		"a bare number":           {`42`, -32600},
		"a bare string":           {`"tools/list"`, -32600},
		"a bare boolean":          {`true`, -32600},
		"an empty array":          {`[]`, -32600},
		"a batch":                 {`[{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]`, -32600},
		"not JSON at all":         {`{"jsonrpc":`, -32700},
		"an id that is an object": {`{"jsonrpc": "2.0", "id": {"a": 1}, "method": "tools/list"}`, -32600},
		"an id that is an array":  {`{"jsonrpc": "2.0", "id": [1], "method": "tools/list"}`, -32600},
		"an id that is a boolean": {`{"jsonrpc": "2.0", "id": true, "method": "tools/list"}`, -32600},
		"a repeated member":       {`{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "method": "tools/call"}`, -32600},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			response, answered := call(t, testServer(t), tc.request)
			if !answered {
				t.Fatal("a message that is valid JSON went unanswered")
			}
			failure, ok := response["error"].(map[string]any)
			if !ok {
				t.Fatalf("the message was accepted: %v", response)
			}
			if code, _ := failure["code"].(float64); code != tc.code {
				t.Errorf("code = %v, want %v: %v", code, tc.code, failure["message"])
			}
		})
	}
}

// TestPingIsAnswered covers the one method a client may use to ask whether this
// server is still there. Answering it with "no such method" tells a client
// watching for liveness that the server is broken.
func TestPingIsAnswered(t *testing.T) {
	response, answered := call(t, testServer(t), `{"jsonrpc": "2.0", "id": 9, "method": "ping"}`)
	if !answered {
		t.Fatal("ping went unanswered")
	}
	if _, failed := response["error"]; failed {
		t.Errorf("ping was refused: %v", response["error"])
	}
	if _, ok := response["result"].(map[string]any); !ok {
		t.Errorf("ping produced no result: %v", response)
	}
}

// TestAToolErrorDoesNotGrowWithItsInput bounds what goes back to a model.
//
// A tool result is read into a context window and repeated from there. The
// contract loader reports one clause per repeated resource, so a contract the
// caller can write inside a root turns into an error of the same order as the
// file -- ten megabytes of it, through a server whose inbound messages are
// bounded at one.
func TestAToolErrorDoesNotGrowWithItsInput(t *testing.T) {
	// Two payloads, because the bound is on characters and a test that counts
	// bytes over ASCII cannot tell the two apart. The second repeats a
	// character that takes four bytes, so a bound counting bytes would cut it
	// four times shorter, and one counting characters produces four times the
	// bytes -- which is the number worth stating.
	for name, family := range map[string]string{
		"plain":                  "object_storage",
		"four bytes a character": strings.Repeat("\U0001F600", 8),
	} {
		t.Run(name, func(t *testing.T) {
			var resources []string
			for i := 0; i < 4000; i++ {
				resources = append(resources, `{"family": "`+family+`", "exposure": "private"}`)
			}
			contract := `{"schema_version": "1.0", "change_id": "c", "environment": "staging",
			  "allowed_clouds": ["aws"], "destructive_changes": "forbidden",
			  "resources": [` + strings.Join(resources, ",") + `]}`

			server, intentPath, planPath := root(t, contract, publicPlan)
			text, failed := toolCall(t, server, "analyze_change", map[string]any{
				"intent_path": intentPath, "plan_path": planPath,
			})
			if !failed {
				t.Fatal("a contract repeating one family four thousand times was accepted")
			}

			if characters := utf8.RuneCountInString(text); characters > 2100 {
				t.Errorf("the tool returned %d characters of error for a %d byte contract; "+
					"it repeats its input rather than describing it", characters, len(contract))
			}
			if !utf8.ValidString(text) {
				t.Error("the error was cut inside a character")
			}
		})
	}
}
