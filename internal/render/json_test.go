package render_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/render"
)

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return raw
}

// TestJSONMatchesReviewedContractExample anchors the renderer to the reviewed
// contract document rather than to whatever the implementation happens to emit.
// The file it compares against is the bundle docs/EVIDENCE-BUNDLE.md walks
// through, not the output of the command in the README. It used to sit in
// examples/ beside the contract and plan that command reads, where its name
// and location said otherwise.
func TestJSONMatchesReviewedContractExample(t *testing.T) {
	want := mustReadFile(t, filepath.Join("..", "..", "docs", "examples", "evidence-bundle.json"))

	got, err := render.JSON(contractBundle())
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("canonical JSON does not match docs/examples/evidence-bundle.json\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestJSONGoldens(t *testing.T) {
	cases := map[string]evidence.Bundle{
		"pass":     passBundle(),
		"redacted": redactedBundle(),
	}
	for name, bundle := range cases {
		t.Run(name, func(t *testing.T) {
			want := mustReadFile(t, filepath.Join("testdata", name+".golden.json"))
			got, err := render.JSON(bundle)
			if err != nil {
				t.Fatalf("render.JSON: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("JSON mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestJSONIsByteIdenticalOnRepeat(t *testing.T) {
	bundle := contractBundle()
	first, err := render.JSON(bundle)
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := render.JSON(bundle)
		if err != nil {
			t.Fatalf("render.JSON: %v", err)
		}
		if string(again) != string(first) {
			t.Fatal("repeated rendering produced different bytes")
		}
	}
}

// TestJSONTopLevelKeys guards canonical output against a future field that
// would make it nondeterministic, such as a timestamp, a generated run ID, or a
// local filesystem path.
func TestJSONTopLevelKeys(t *testing.T) {
	raw, err := render.JSON(contractBundle())
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decoding rendered JSON: %v", err)
	}

	got := make([]string, 0, len(decoded))
	for key := range decoded {
		got = append(got, key)
	}
	slices.Sort(got)

	want := []string{"decision", "findings", "schema_version", "subject", "summary", "unknowns", "verification"}
	if !slices.Equal(got, want) {
		t.Fatalf("top-level keys = %v, want %v", got, want)
	}
}

func TestJSONDoesNotEscapeHTML(t *testing.T) {
	bundle := contractBundle()
	bundle.Summary = `Public access <enabled> by "policy" & plan`

	raw, err := render.JSON(bundle)
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	if !strings.Contains(string(raw), "<enabled>") || !strings.Contains(string(raw), "&") {
		t.Fatalf("summary was HTML-escaped: %s", raw)
	}
}

func TestJSONRejectsInvalidBundle(t *testing.T) {
	bundle := contractBundle()
	bundle.Decision = evidence.DecisionPass

	if _, err := render.JSON(bundle); err == nil {
		t.Fatal("expected render.JSON to refuse an invalid bundle")
	}
}

func TestJSONDoesNotMutateInput(t *testing.T) {
	bundle := contractBundle()
	bundle.Findings = append(bundle.Findings, evidence.Finding{
		RuleID:      "AAA_RULE",
		Severity:    evidence.SeverityInfo,
		Disposition: evidence.DispositionInfo,
		Claim:       "An informational observation.",
		Remediation: "No remediation required.",
		Evidence:    []evidence.EvidenceRef{},
	})
	firstRuleID := bundle.Findings[0].RuleID

	if _, err := render.JSON(bundle); err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	if bundle.Findings[0].RuleID != firstRuleID {
		t.Fatal("render.JSON reordered the caller's findings")
	}
}

// TestJSONOrdersFindingsCanonically asserts that the canonical renderer sorts.
// Without it, removing the canonicalization step from render.JSON changes no
// test outcome, because every other JSON fixture is already in sorted order.
func TestJSONOrdersFindingsCanonically(t *testing.T) {
	bundle := contractBundle()
	bundle.Findings = append([]evidence.Finding{{
		RuleID:      "ZZZ_RULE",
		Severity:    evidence.SeverityInfo,
		Disposition: evidence.DispositionInfo,
		Claim:       "An informational observation.",
		Remediation: "No remediation required.",
		Evidence:    []evidence.EvidenceRef{},
	}}, bundle.Findings...)

	raw, err := render.JSON(bundle)
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}

	critical := strings.Index(string(raw), "STORAGE_PUBLIC")
	informational := strings.Index(string(raw), "ZZZ_RULE")
	if critical < 0 || informational < 0 {
		t.Fatalf("both findings should be rendered:\n%s", raw)
	}
	if critical > informational {
		t.Fatalf("CRITICAL finding must be rendered before the INFO finding:\n%s", raw)
	}
}

// TestJSONRendersEmptyCollectionsAsArrays keeps an absent collection and an
// empty collection indistinguishable in output, so a consumer never has to
// handle both null and [].
func TestJSONRendersEmptyCollectionsAsArrays(t *testing.T) {
	bundle := passBundle()
	bundle.Findings = nil
	bundle.Unknowns = nil

	raw, err := render.JSON(bundle)
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	out := string(raw)
	if !strings.Contains(out, `"findings": []`) || !strings.Contains(out, `"unknowns": []`) {
		t.Fatalf("nil collections must render as []:\n%s", out)
	}
	if strings.Contains(out, "null") {
		t.Fatalf("nil collections must not render as null:\n%s", out)
	}
}

// TestJSONRendersNilEvidenceAsArray covers the same guarantee one level down.
func TestJSONRendersNilEvidenceAsArray(t *testing.T) {
	bundle := passBundle()
	bundle.Findings = []evidence.Finding{{
		RuleID:      "INFO_RULE",
		Severity:    evidence.SeverityInfo,
		Disposition: evidence.DispositionInfo,
		Claim:       "An informational observation.",
		Remediation: "No remediation required.",
		Evidence:    nil,
	}}

	raw, err := render.JSON(bundle)
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	if !strings.Contains(string(raw), `"evidence": []`) {
		t.Fatalf("nil evidence must render as []:\n%s", raw)
	}
}
