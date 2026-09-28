// Package mcp serves the verifier to a coding agent over the Model Context
// Protocol, and serves nothing else.
//
// Everything arriving here was written by something other than this program, so
// the boundary is the same kind as the plan parser's: what a request says about
// itself is a claim, not a fact. Milestone 05 requires structured safe errors
// for invalid input, no command execution, no network, and no access outside
// allowed roots -- and the first of those is what keeps a client from hanging
// on a request this build declined to understand.
//
// The transport is stdio and there is no other. A JSON-RPC message per line,
// which is what the stdio transport specifies, so the framing needs no length
// header and a partial write cannot be read as a whole message.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/mtlabs-eng/infraproof/internal/pathguard"
)

// protocolVersion is the revision of the Model Context Protocol this build
// implements. A client asking for another is answered with this one, which the
// specification allows and a client may refuse.
const protocolVersion = "2025-06-18"

// JSON-RPC 2.0 error codes. The first four are the specification's; the last is
// this build's, for a request that was understood and refused.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
)

// maxMessage bounds one request line. A stdio peer can write without end, and a
// reader that grows to meet it has handed the peer this process's memory.
const maxMessage = 1 << 20

// maxMessageText bounds what an error message repeats back. A path or a tool
// name is the caller's, and an error is read in a log.
const maxMessageText = 200

// Options configures a server.
type Options struct {
	// Roots are the directories the server may read from. There is no default:
	// a server with no root is refused rather than built.
	Roots []string
	// Timeout bounds one verification. Zero means DefaultTimeout.
	//
	// Input size bounds the bytes and not the work: normalization grows faster
	// than the plan does, so a file well inside the size limit can ask for more
	// time than a caller has. Milestone 05 asks for bounded execution time and
	// this is it.
	Timeout time.Duration
}

// DefaultTimeout bounds one verification when none is configured.
//
// The slowest plan measured while building this took under a second. Thirty is
// far past any real one and short of a wait an agent would sit through without
// concluding the server is gone.
const DefaultTimeout = 30 * time.Second

// Server answers Model Context Protocol requests over one pair of streams.
//
// It holds no state between requests beyond what it was configured with. A tool
// that answered from a remembered result would need to say how fresh that
// result is, and the plan it was reached from is a file that may have changed
// since -- a contract milestone 05 defers rather than guesses at.
type Server struct {
	guard   *pathguard.Guard
	timeout time.Duration
}

// New builds a server.
func New(options Options) (*Server, error) {
	guard, err := pathguard.New(options.Roots)
	if err != nil {
		return nil, err
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Server{guard: guard, timeout: timeout}, nil
}

// request is one JSON-RPC message as it arrived.
//
// ID is kept as raw JSON because the specification allows a string or a number
// and requires the response to carry the same one back; decoding it into a Go
// type would answer "1" where the client said 1. Its absence is what makes a
// message a notification, and json.RawMessage distinguishes absent from null.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// response is one JSON-RPC reply. Exactly one of Result and Error is set.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads requests until the stream ends.
//
// A request that cannot be read at all is still answered, with a null id, which
// is what the specification says to do and what keeps a client from waiting on
// a reply that is never coming. A notification is answered with nothing, which
// is the one case where silence is the protocol rather than a failure to
// respond.
func (s *Server) Serve(in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, 4096)
	encoder := json.NewEncoder(out)

	for {
		line, err := readLine(reader)
		if len(line) > 0 {
			if reply, answer := s.handle(line); answer {
				if err := encoder.Encode(reply); err != nil {
					return fmt.Errorf("writing a response: %w", err)
				}
			}
		}
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		}
	}
}

// readLine returns one message, or an error. A line longer than maxMessage is
// not read into memory: the rest of it is discarded and the caller is told the
// message was refused, because a peer that writes without end must not be able
// to make this process grow to match.
func readLine(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, more, err := reader.ReadLine()
		if err != nil {
			return line, err
		}
		if len(line)+len(chunk) <= maxMessage {
			line = append(line, chunk...)
		} else {
			line = append(line[:0], oversized...)
		}
		if !more {
			return line, nil
		}
	}
}

// oversized is the message readLine substitutes for one too long to hold. It is
// not valid JSON, so it takes the parse-error path like any other unreadable
// input and the caller is answered rather than left waiting.
var oversized = []byte("!")

// handle answers one message, and reports whether there is anything to send.
func (s *Server) handle(line []byte) (response, bool) {
	var message request
	if err := json.Unmarshal(line, &message); err != nil {
		return failure(nil, codeParse, "the request is not a JSON-RPC message"), true
	}

	// A notification expects no reply, so a malformed one is discarded rather
	// than answered: a response to a message with no id has no id to carry, and
	// the client is not reading for one.
	notification := len(message.ID) == 0

	switch {
	case message.JSONRPC != "2.0":
		return failure(message.ID, codeInvalidRequest, "jsonrpc must be \"2.0\""), !notification
	case strings.TrimSpace(message.Method) == "":
		return failure(message.ID, codeInvalidRequest, "the request names no method"), !notification
	}

	if notification {
		return response{}, false
	}

	switch message.Method {
	case "initialize":
		return result(message.ID, s.initialize()), true
	case "tools/list":
		return result(message.ID, map[string]any{"tools": tools()}), true
	case "tools/call":
		return s.callTool(message.ID, message.Params), true
	default:
		return failure(message.ID, codeMethodNotFound,
			fmt.Sprintf("method %s is not one this server implements", quote(message.Method))), true
	}
}

// initialize describes this server to a client.
func (s *Server) initialize() map[string]any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		// Tools and nothing else. This server has no resources to offer and no
		// prompts, and saying otherwise would invite a request it would then
		// have to refuse.
		"capabilities": map[string]any{"tools": map[string]any{}},
		"serverInfo":   map[string]any{"name": "infraproof", "version": Version},
		"instructions": "Verifies a Terraform or OpenTofu plan against an intent contract, " +
			"offline. Both files are read from disk inside the allowed roots this server " +
			"was started with. Nothing is applied and no cloud is contacted.",
	}
}

func result(id json.RawMessage, payload any) response {
	return response{JSONRPC: "2.0", ID: id, Result: payload}
}

func failure(id json.RawMessage, code int, message string) response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return response{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: message}}
}

// quote bounds a caller's own text before an error repeats it. The value came
// from the client and goes back to the client, but it is read in a log on the
// way, and its length is the client's to choose.
func quote(text string) string {
	if len(text) > maxMessageText {
		text = text[:maxMessageText] + "… (truncated)"
	}
	return strconv.Quote(text)
}
