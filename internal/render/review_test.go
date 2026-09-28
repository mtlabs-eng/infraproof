package render_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/render"
)

// TestAReviewSaysWhatTheBundleSays is the criterion, asked of content rather
// than of shape.
//
// A third rendering is a third chance for two outputs to disagree, and the one
// a reviewer reads is the one nobody diffs against the JSON. So every decision,
// every rule that produced a finding, and every check that could not conclude
// has to appear -- not in the same words, but the reader must not learn less
// from the short form than from the long one.
func TestAReviewSaysWhatTheBundleSays(t *testing.T) {
	for name, bundle := range map[string]evidence.Bundle{
		"a block":    contractBundle(),
		"a pass":     passBundle(),
		"a redacted": redactedBundle(),
	} {
		t.Run(name, func(t *testing.T) {
			out, err := render.Review(bundle)
			if err != nil {
				t.Fatalf("render.Review: %v", err)
			}
			text := string(out)

			if !strings.Contains(text, string(bundle.Decision)) {
				t.Errorf("the review does not say the decision %q", bundle.Decision)
			}
			for _, finding := range bundle.Findings {
				if !strings.Contains(text, finding.RuleID) {
					t.Errorf("the review omits the finding %q", finding.RuleID)
				}
				if finding.Resource != nil && !strings.Contains(text, finding.Resource.Address) {
					t.Errorf("the review omits the resource %q", finding.Resource.Address)
				}
			}
			for _, unknown := range bundle.Unknowns {
				if unknown.Required && !strings.Contains(text, unknown.CheckID) {
					t.Errorf("the review omits the required unknown %q", unknown.CheckID)
				}
			}
		})
	}
}

// TestAReviewIsTheSameBytesEveryTime keeps a comment from churning. A workflow
// updates one comment across pushes; a rendering that reorders itself makes
// every push look like a change.
func TestAReviewIsTheSameBytesEveryTime(t *testing.T) {
	bundle := contractBundle()
	first, err := render.Review(bundle)
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	for range 20 {
		again, err := render.Review(bundle)
		if err != nil {
			t.Fatalf("render.Review: %v", err)
		}
		if string(again) != string(first) {
			t.Fatal("the same bundle rendered two ways")
		}
	}
}

// TestAReviewCarriesAMarkerForOneSubject is what lets a workflow update a
// comment rather than append one per push.
//
// It identifies the inputs rather than the run: the same plan and contract
// produce the same marker, and a different plan produces a different one. A
// marker that carried a run number would make every push a new comment, which
// is the thing it exists to prevent.
func TestAReviewCarriesAMarkerForOneSubject(t *testing.T) {
	bundle := contractBundle()
	marker := render.Marker(bundle.Subject)

	if marker == "" {
		t.Fatal("there is no marker")
	}
	out, err := render.Review(bundle)
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	if !strings.Contains(string(out), marker) {
		t.Errorf("the review does not carry its marker:\n%s", out)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(out)), "<!--") {
		t.Error("the marker is not the first thing a workflow can look for")
	}

	same := contractBundle()
	same.Decision = evidence.DecisionWarn
	if render.Marker(same.Subject) != marker {
		t.Error("two verdicts about one plan carry different markers, so a workflow would " +
			"post a second comment rather than update the first")
	}

	other := contractBundle()
	other.Subject.PlanDigest = "sha256:" + strings.Repeat("1", 64)
	if render.Marker(other.Subject) == marker {
		t.Error("two different plans carry one marker, so a workflow would overwrite a comment " +
			"about a change it was not looking at")
	}
}

// TestALongReviewSaysWhatItLeftOut bounds the comment and refuses to do it
// quietly.
//
// A plan with a thousand findings produces a comment no platform will accept.
// Truncating in silence reads as "these are the findings", which is the
// sentence-level form of reporting an unchecked thing as checked.
func TestALongReviewSaysWhatItLeftOut(t *testing.T) {
	bundle := contractBundle()
	for i := range 500 {
		finding := bundle.Findings[0]
		finding.RuleID = "RULE_" + strings.Repeat("X", 3) + string(rune('A'+i%26))
		address := "aws_s3_bucket.b" + strings.Repeat("0", 3)
		finding.Resource = &evidence.Resource{
			Address: address, Cloud: evidence.CloudAWS, Provider: "p",
		}
		bundle.Findings = append(bundle.Findings, finding)
	}

	out, err := render.Review(bundle)
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	text := string(out)

	if len(text) > render.MaxReviewBytes {
		t.Errorf("the review is %d bytes, past the %d it bounds itself to",
			len(text), render.MaxReviewBytes)
	}
	if !strings.Contains(text, "not shown") {
		t.Errorf("the review truncates without saying so:\n%.500s", text)
	}
	if !strings.Contains(text, string(bundle.Decision)) {
		t.Error("the decision was cut; it is the one thing that must survive")
	}
}

// TestAReviewNeverCarriesAValueThePlanHeld is the safety rule at a third
// boundary. A comment on a pull request is read by everyone with access to the
// repository, which is more people than run the command.
func TestAReviewNeverCarriesAValueThePlanHeld(t *testing.T) {
	out, err := render.Review(redactedBundle())
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	var bundle evidence.Bundle
	raw, err := render.JSON(redactedBundle())
	if err != nil {
		t.Fatalf("render.JSON: %v", err)
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// The bundle cannot carry a value by construction; this asserts the review
	// does not add one back by rendering a field the bundle keeps out of reach.
	for _, finding := range bundle.Findings {
		for _, ref := range finding.Evidence {
			if ref.Redacted && strings.Contains(string(out), ref.Path+" =") {
				t.Errorf("the review prints a value at a location the bundle marked unreadable: %s",
					ref.Path)
			}
		}
	}
}

// TestAReviewRefusesABundleTheContractRefuses keeps the three renderings
// answering alike. A bundle that JSON will not write is not one a comment
// should carry.
func TestAReviewRefusesABundleTheContractRefuses(t *testing.T) {
	broken := contractBundle()
	broken.Decision = "MAYBE"

	if _, err := render.Review(broken); err == nil {
		t.Error("the review rendered a bundle the contract refuses")
	}
}
