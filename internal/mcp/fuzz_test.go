package mcp_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/mcp"
)

// FuzzRequest holds the boundary's one guarantee over input nobody chose.
//
// Everything reaching this server was written by something else, and the plan
// parser is fuzzed for exactly the same reason. The property is not that a
// request is understood -- most of these are not -- but that every one is
// answered on the protocol's terms: one JSON-RPC message back per message in,
// never a panic, never a half-written line, and never silence on a request that
// carried an id.
func FuzzRequest(f *testing.F) {
	f.Add(`{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}`)
	f.Add(`{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}`)
	f.Add(`{"jsonrpc": "2.0", "method": "notifications/initialized"}`)
	f.Add(`{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "analyze_change", "arguments": {"intent_path": "i", "plan_path": "p"}}}`)
	f.Add(`{"jsonrpc": "2.0", "id": null, "method": "tools/call", "params": {"name": "explain_finding", "arguments": {}}}`)
	f.Add(`{"jsonrpc":`)
	f.Add(`[]`)
	// Valid JSON that is not a request object. Each of these decodes into the
	// zero request, which carries no id, which read as a notification -- so the
	// server answered a waiting client with silence. Seeds, because an oracle
	// nothing exercises is an oracle that proves nothing.
	f.Add(`null`)
	f.Add(`42`)
	f.Add(`"tools/list"`)
	f.Add(`true`)
	f.Add(`[{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]`)
	f.Add(`{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "method": "tools/call"}`)
	f.Add(`{"jsonrpc": "2.0", "id": {"deep": {"deeper": 1}}, "method": "tools/list"}`)
	f.Add(`{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "analyze_change", "arguments": {"intent_path": "../../../etc/passwd", "plan_path": "p"}}}`)

	server, err := mcp.New(mcp.Options{Roots: []string{f.TempDir()}})
	if err != nil {
		f.Fatalf("New: %v", err)
	}

	f.Fuzz(func(t *testing.T, line string) {
		// One message per line is the transport. A value carrying a break is
		// several messages, which the framing already answers one at a time.
		if strings.ContainsAny(line, "\r\n") {
			t.Skip()
		}

		var out strings.Builder
		if err := server.Serve(strings.NewReader(line+"\n"), &out); err != nil {
			t.Fatalf("serving %q: %v", line, err)
		}

		written := strings.TrimSpace(out.String())
		if written == "" {
			// Silence is the protocol for a blank line, which is framing and
			// not a message, and for a notification: an object that speaks the
			// protocol and carries no id. It is a defect anywhere else, because
			// a client is waiting.
			//
			// The object test is the part that matters. Decoding into a struct
			// accepts a bare null and leaves the id empty, so an oracle that
			// asked only about the id would call silence correct for exactly
			// the input that made this boundary silent in the first place.
			if strings.TrimSpace(line) == "" {
				return
			}
			var document any
			if err := json.Unmarshal([]byte(line), &document); err != nil {
				t.Fatalf("an unreadable request went unanswered: %q", line)
			}
			object, isObject := document.(map[string]any)
			if !isObject {
				t.Fatalf("a message that is valid JSON and not a request went unanswered: %q", line)
			}
			if _, carriesID := object["id"]; carriesID {
				t.Fatalf("a request carrying an id went unanswered: %q", line)
			}
			return
		}

		if strings.Contains(written, "\n") {
			t.Fatalf("one request produced more than one response: %q", written)
		}

		var response map[string]any
		if err := json.Unmarshal([]byte(written), &response); err != nil {
			t.Fatalf("the server wrote something that is not JSON: %q", written)
		}
		if response["jsonrpc"] != "2.0" {
			t.Errorf("the response does not speak the protocol: %q", written)
		}
		_, hasResult := response["result"]
		failure, hasError := response["error"]
		if hasResult == hasError {
			t.Errorf("a response must carry exactly one of result and error: %q", written)
		}
		if hasError {
			body, ok := failure.(map[string]any)
			if !ok {
				t.Fatalf("the error is not an object: %q", written)
			}
			if _, ok := body["code"].(float64); !ok {
				t.Errorf("the error carries no code: %q", written)
			}
			if message, _ := body["message"].(string); len(message) > 500 {
				t.Errorf("the error repeats its input rather than describing it: %d bytes",
					len(message))
			}
		}
	})
}
