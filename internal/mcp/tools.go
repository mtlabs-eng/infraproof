package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/pathguard"
	"github.com/mtlabs-eng/infraproof/internal/render"
	"github.com/mtlabs-eng/infraproof/internal/verify"
)

// Version is the adapter's version, reported in the handshake.
const Version = "0.1.0"

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
		return result(id, toolText(err.Error(), true))
	}
	return result(id, toolText(text, false))
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

// bundle resolves both paths inside the allowed roots, checks their size, and
// runs the one verification every interface runs.
func (s *Server) bundle(intentPath, planPath *string) (evidence.Bundle, error) {
	intentArg, err := required("intent_path", intentPath)
	if err != nil {
		return evidence.Bundle{}, err
	}
	planArg, err := required("plan_path", planPath)
	if err != nil {
		return evidence.Bundle{}, err
	}

	intentReal, err := s.readable(intentArg)
	if err != nil {
		return evidence.Bundle{}, err
	}
	planReal, err := s.readable(planArg)
	if err != nil {
		return evidence.Bundle{}, err
	}

	return verify.FromFiles(intentReal, planReal)
}

// readable resolves a path inside the roots and refuses a file too large to
// read.
//
// The size is checked before the file is opened for reading, so a plan that
// would not fit costs a stat rather than the memory it asked for.
func (s *Server) readable(path string) (string, error) {
	real, err := s.guard.Resolve(path)
	if err != nil {
		if errors.Is(err, pathguard.ErrOutsideRoots) {
			return "", fmt.Errorf("%s is outside every directory this server was given access to",
				quote(path))
		}
		return "", err
	}

	info, err := os.Stat(real)
	if err != nil {
		return "", fmt.Errorf("%s could not be read", quote(path))
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory", quote(path))
	}
	if info.Size() > MaxInputBytes {
		return "", fmt.Errorf("%s is %d bytes, and this server reads at most %d",
			quote(path), info.Size(), MaxInputBytes)
	}
	return real, nil
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
