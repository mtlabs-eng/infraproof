package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/pathguard"
	"github.com/mtlabs-eng/infraproof/internal/render"
	"github.com/mtlabs-eng/infraproof/internal/verify"
)

// Version is the adapter's version, reported in the handshake.
const Version = "0.4.0"

// MaxInputBytes bounds each file a tool reads.
//
// The largest plan measured while building this was seventeen megabytes, and a
// plan is read entirely into memory to be parsed. Sixty-four is far past any
// real one and short of what an unbounded read costs, and the file is refused
// rather than truncated: half a plan parses into a different change.
const MaxInputBytes = 64 << 20

// tools is the catalogue, and the schema a client validates against before it
// sends anything. A tool without one is a tool whose input is whatever arrives.
func tools() []map[string]any {
	paths := map[string]any{
		"intent_path": map[string]any{
			"type":        "string",
			"description": "Path to a JSON intent contract, inside an allowed root.",
		},
		"plan_path": map[string]any{
			"type":        "string",
			"description": "Path to a Terraform or OpenTofu plan JSON file, inside an allowed root.",
		},
	}

	explain := map[string]any{}
	for name, schema := range paths {
		explain[name] = schema
	}
	explain["rule_id"] = map[string]any{
		"type":        "string",
		"description": "The rule_id of a finding this verification produced, such as STORAGE_PUBLIC.",
	}

	return []map[string]any{
		{
			"name": "analyze_change",
			"description": "Compare a Terraform or OpenTofu plan with an intent contract and return " +
				"the Evidence Bundle: a decision, findings with the plan data each rests on, and " +
				"the facts that could not be determined. Reads both files locally, applies nothing, " +
				"and contacts no cloud.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           paths,
				"required":             []string{"intent_path", "plan_path"},
				"additionalProperties": false,
			},
		},
		{
			"name": "explain_finding",
			"description": "Return one finding from the same verification, with the plan data it " +
				"rests on and its remediation. The verification is run again from the two files " +
				"rather than remembered, so the answer describes the plan as it is now.",
			"inputSchema": map[string]any{
				"type":                 "object",
				"properties":           explain,
				"required":             []string{"intent_path", "plan_path", "rule_id"},
				"additionalProperties": false,
			},
		},
	}
}

// callParams is the body of a tools/call request.
type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// callTool runs one tool and wraps what it returns.
//
// A tool that fails because of its input answers with a result carrying
// isError, not with a JSON-RPC error: the protocol's errors are for a request
// the server could not process, and "this plan could not be read" is something
// the model should see and act on rather than a transport failure. A request
// that is malformed as a request still takes the error path above.
func (s *Server) callTool(id json.RawMessage, raw json.RawMessage) response {
	var params callParams
	if len(raw) == 0 || json.Unmarshal(raw, &params) != nil {
		return failure(id, codeInvalidParams, "params must be an object naming a tool and its arguments")
	}
	if strings.TrimSpace(params.Name) == "" {
		return failure(id, codeInvalidParams, "params.name must name a tool")
	}

	run, known := map[string]func(json.RawMessage) (string, error){
		"analyze_change":  s.analyzeChange,
		"explain_finding": s.explainFinding,
	}[params.Name]
	if !known {
		return failure(id, codeInvalidParams,
			fmt.Sprintf("tool %s is not one this server offers", quote(params.Name)))
	}

	text, err := run(params.Arguments)
	if err != nil {
		var invalid *invalidArguments
		if errors.As(err, &invalid) {
			return failure(id, codeInvalidParams, invalid.Error())
		}
		// Bounded, like every other thing this server says back. A tool result
		// is read into a context window and repeated from there, and the
		// loaders report one clause per offending entry -- so a contract the
		// caller can write inside a root turns into an error of the same order
		// as the file, through a server whose inbound messages are bounded at a
		// megabyte.
		return result(id, toolText(bounded(err.Error()), true))
	}
	return result(id, toolText(text, false))
}

// maxToolError bounds what a failed tool says back. Long enough for the first
// few clauses of a validation failure, which is what a caller acts on, and
// short of a result that fills a context window.
const maxToolError = 2000

// bounded cuts a message on a character boundary and says where.
func bounded(text string) string {
	if len(text) <= maxToolError {
		return text
	}
	count := 0
	for at := range text {
		count++
		if count > maxToolError {
			return text[:at] + "… (truncated; the input reports more than this server will repeat)"
		}
	}
	return text
}

// toolText is a tool result in the shape the protocol expects.
func toolText(text string, failed bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": failed,
	}
}

// invalidArguments reports arguments that do not match a tool's declared
// schema. It is a request-level failure: the client sent something its own
// schema said it would not.
type invalidArguments struct{ message string }

func (e *invalidArguments) Error() string { return e.message }

// analyzeArgs and explainArgs are decoded strictly, so an argument this build
// does not know is refused rather than ignored. A client that sent one believes
// something about this server that is not true.
type analyzeArgs struct {
	IntentPath *string `json:"intent_path"`
	PlanPath   *string `json:"plan_path"`
}

type explainArgs struct {
	IntentPath *string `json:"intent_path"`
	PlanPath   *string `json:"plan_path"`
	RuleID     *string `json:"rule_id"`
}

func decodeArgs(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		return &invalidArguments{"arguments must be an object"}
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(into); err != nil {
		return &invalidArguments{"arguments do not match this tool's input schema"}
	}
	return nil
}

func required(name string, value *string) (string, error) {
	if value == nil || strings.TrimSpace(*value) == "" {
		return "", &invalidArguments{fmt.Sprintf("arguments.%s is required", name)}
	}
	return *value, nil
}

// analyzeChange verifies a plan against a contract and returns the bundle.
func (s *Server) analyzeChange(raw json.RawMessage) (string, error) {
	var args analyzeArgs
	if err := decodeArgs(raw, &args); err != nil {
		return "", err
	}
	bundle, err := s.bundle(args.IntentPath, args.PlanPath)
	if err != nil {
		return "", err
	}

	out, err := render.JSON(bundle)
	if err != nil {
		return "", fmt.Errorf("the verification produced a bundle that could not be rendered: %w", err)
	}
	return string(out), nil
}

// explainFinding returns one finding of the same verification.
//
// It re-runs the verification rather than remembering one, so what it describes
// is the plan as it is now. A remembered bundle would have to say how old it
// is, and the plan it came from is a file that may have changed since.
func (s *Server) explainFinding(raw json.RawMessage) (string, error) {
	var args explainArgs
	if err := decodeArgs(raw, &args); err != nil {
		return "", err
	}
	ruleID, err := required("rule_id", args.RuleID)
	if err != nil {
		return "", err
	}
	bundle, err := s.bundle(args.IntentPath, args.PlanPath)
	if err != nil {
		return "", err
	}

	canonical := evidence.Canonical(bundle)
	matching := make([]evidence.Finding, 0, len(canonical.Findings))
	for _, finding := range canonical.Findings {
		if finding.RuleID == ruleID {
			matching = append(matching, finding)
		}
	}
	if len(matching) == 0 {
		// Not an error: the verification succeeded and reported no such
		// finding, which is an answer. Saying which rules did report keeps the
		// caller from guessing at a spelling.
		return string(mustJSON(map[string]any{
			"rule_id":  ruleID,
			"findings": []evidence.Finding{},
			"reported": reportedRules(canonical),
			"note": "This verification reported no finding under that rule. The rules it did " +
				"report are listed, and a rule absent from both reported nothing to explain.",
		})), nil
	}

	return string(mustJSON(map[string]any{
		"rule_id":  ruleID,
		"findings": matching,
		"subject":  canonical.Subject,
	})), nil
}

// reportedRules names the rules this verification did report, in canonical
// order and without repeating one.
func reportedRules(bundle evidence.Bundle) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(bundle.Findings))
	for _, finding := range bundle.Findings {
		if !seen[finding.RuleID] {
			seen[finding.RuleID] = true
			out = append(out, finding.RuleID)
		}
	}
	return out
}

// bundle opens both files inside the allowed roots and runs the one
// verification every interface runs.
//
// The guard hands back open files rather than approved names. A name checked
// and then opened by someone else is a name that can be re-pointed in between,
// and independent review of this milestone did exactly that: a regular file
// became a symlink between the check and the read, and the read left the root.
//
// The paths recorded in the report are the ones the caller supplied. The
// resolved path is a different spelling, of more of the filesystem than the
// caller handed over, and everything this returns may be repeated by a model
// into a commit message or a comment.
func (s *Server) bundle(intentPath, planPath *string) (evidence.Bundle, error) {
	intentArg, err := required("intent_path", intentPath)
	if err != nil {
		return evidence.Bundle{}, err
	}
	planArg, err := required("plan_path", planPath)
	if err != nil {
		return evidence.Bundle{}, err
	}

	contract, err := s.open(intentArg)
	if err != nil {
		return evidence.Bundle{}, err
	}
	defer contract.Close()

	plan, err := s.open(planArg)
	if err != nil {
		return evidence.Bundle{}, err
	}
	defer plan.Close()

	return s.within(func() (evidence.Bundle, error) {
		return verify.FromReaders(intentArg, contract, planArg, plan, MaxInputBytes)
	})
}

// open returns a file inside the roots, refusing anything that is not a regular
// file.
//
// The kind is asked of the open file rather than of the path, for the same
// reason the path is never handed back: what a name referred to a moment ago is
// not what it refers to now. A device or a named pipe is refused because the
// size it reports says nothing about how much reading it will produce -- a pipe
// with no writer would hold the server for as long as anyone cared to leave it.
func (s *Server) open(path string) (*os.File, error) {
	file, err := s.guard.Open(path)
	if err != nil {
		// Which rule refused it, because a caller acts on them differently. A
		// path outside the roots needs a different root or a different file; a
		// path that names a parent directory needs only to be written
		// differently, and telling that caller it is outside the roots sends
		// them to widen the root instead.
		switch {
		case errors.Is(err, pathguard.ErrNamesAParent):
			return nil, fmt.Errorf("%s names a parent directory; give the path to the file "+
				"rather than a route to it", quote(path))
		case errors.Is(err, pathguard.ErrIsADirectory):
			return nil, fmt.Errorf("%s names a directory rather than a file", quote(path))
		case errors.Is(err, pathguard.ErrTooDeep):
			return nil, fmt.Errorf("%s names more directories than this server will walk",
				quote(path))
		case errors.Is(err, pathguard.ErrOutsideRoots):
			return nil, fmt.Errorf("%s is outside every directory this server was given access to",
				quote(path))
		}
		return nil, fmt.Errorf("%s could not be read", quote(path))
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%s could not be read", quote(path))
	}
	if info.IsDir() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is a directory", quote(path))
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", quote(path))
	}
	return file, nil
}

// within runs one verification under the server's deadline.
//
// A verification past its deadline is abandoned rather than waited for, and the
// caller is told. The goroutine is left to finish on its own: there is nothing
// to cancel, because the work is a computation over values already in memory
// rather than anything that takes a context, and stopping it half way would
// leave the question of what a half-normalized graph means. It holds no locks
// and touches nothing the next request reads, so what it costs is memory until
// it returns.
func (s *Server) within(work func() (evidence.Bundle, error)) (evidence.Bundle, error) {
	type outcome struct {
		bundle evidence.Bundle
		err    error
	}

	done := make(chan outcome, 1)
	go func() {
		bundle, err := work()
		done <- outcome{bundle, err}
	}()

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()

	select {
	case result := <-done:
		return result.bundle, result.err
	case <-timer.C:
		return evidence.Bundle{}, fmt.Errorf(
			"this verification took longer than %s and was abandoned; "+
				"the plan may be larger than this server will finish reading", s.timeout)
	}
}

func mustJSON(payload any) []byte {
	out, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		// Every value here came out of a bundle that already rendered, so this
		// cannot fire; it is not silently swallowed for the same reason the
		// parser's unreachable branches are errors.
		return []byte(`{"error": "the response could not be encoded"}`)
	}
	return out
}
