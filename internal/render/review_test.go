package render_test

import (
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

// TestAPassSaysWhatItCouldNotCheck is the milestone's criterion read as
// written: the review carries the same decision, findings and unknowns as the
// bundle.
//
// The implementation narrowed that to required unknowns, and the test was
// written to the narrowed version. So a bundle with a dozen checks that could
// not conclude rendered as "PASS" and a summary and nothing else -- twelve
// unstated facts as silence, and silence reads as coverage. That is this
// project's own rule inverted at the last boundary before a human.
func TestAPassSaysWhatItCouldNotCheck(t *testing.T) {
	bundle := passBundle()
	for i := range 12 {
		bundle.Unknowns = append(bundle.Unknowns, evidence.Unknown{
			CheckID:  "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK",
			Required: false,
			Reason:   "The account-level block is not part of this plan.",
			Evidence: []evidence.EvidenceRef{},
		})
		_ = i
	}

	out, err := render.Review(bundle)
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	text := string(out)

	if !strings.Contains(text, "12") {
		t.Errorf("a pass over twelve checks that could not conclude says nothing about them:\n%s",
			text)
	}
	if !strings.Contains(text, "could not") {
		t.Errorf("the review does not say what the twelve are:\n%s", text)
	}
}

// TestTruncationKeepsTheWorstFindings covers what a reviewer loses first.
//
// The row loop skipped a row that did not fit and kept looking, so a short
// low-severity finding could be printed while a long critical one was counted
// as omitted. Canonical order puts the severe first; the rendering has to stop
// at the first row that does not fit rather than step over it.
func TestTruncationKeepsTheWorstFindings(t *testing.T) {
	bundle := contractBundle()
	critical := bundle.Findings[0]
	critical.Claim = strings.Repeat("This claim is long enough to crowd out what follows. ", 20)

	bundle.Findings = nil
	for range 400 {
		bundle.Findings = append(bundle.Findings, critical)
	}
	low := critical
	low.Severity = evidence.SeverityLow
	low.RuleID = "TINY_LOW_FINDING"
	low.Claim = "Short."
	low.Resource = &evidence.Resource{Address: "a.b", Cloud: evidence.CloudAWS, Provider: "p"}
	bundle.Findings = append(bundle.Findings, low)

	out, err := render.Review(bundle)
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	if strings.Contains(string(out), "TINY_LOW_FINDING") {
		t.Error("a low finding was printed while critical ones were counted as omitted; " +
			"the reader sees the least of what was found")
	}
}

// TestTheReviewIsBoundedByWhateverItIsGiven keeps the bound a bound.
//
// The closing line prints the contract's path, and the bundle contract puts no
// length on it -- so a long one carried the rendering past the limit it says it
// keeps, and a comment no platform accepts fails the step that posts it.
func TestTheReviewIsBoundedByWhateverItIsGiven(t *testing.T) {
	for name, source := range map[string]string{
		"a long path":       "/" + strings.Repeat("directory/", 400) + "intent.json",
		"expanding escapes": strings.Repeat("&", 4000) + ".json",
	} {
		t.Run(name, func(t *testing.T) {
			bundle := contractBundle()
			bundle.Subject.IntentSource = source

			out, err := render.Review(bundle)
			if err != nil {
				t.Fatalf("render.Review: %v", err)
			}
			if len(out) > render.MaxReviewBytes {
				t.Errorf("the review is %d bytes, past the %d it bounds itself to",
					len(out), render.MaxReviewBytes)
			}
			if !strings.Contains(string(out), string(bundle.Decision)) {
				t.Error("the decision was lost")
			}
		})
	}
}

// TestTheReviewPrintsNoEvidenceLocation replaces an assertion that could not
// fail. The previous one looked for a path followed by " =", which the review
// never writes in any form, so it passed for a renderer that printed anything
// at all.
func TestTheReviewPrintsNoEvidenceLocation(t *testing.T) {
	bundle := redactedBundle()

	out, err := render.Review(bundle)
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	text := string(out)

	var located int
	for _, finding := range evidence.Canonical(bundle).Findings {
		for _, ref := range finding.Evidence {
			located++
			if ref.Path != "" && strings.Contains(text, ref.Path) {
				t.Errorf("the review prints the location of a value rather than the finding: %q",
					ref.Path)
			}
		}
	}
	if located == 0 {
		t.Fatal("the bundle carries no evidence reference, so this test asserts nothing")
	}
}
