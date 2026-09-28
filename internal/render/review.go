package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

// MaxReviewBytes bounds one review.
//
// A comment on a pull request is read in a diff view, and platforms refuse one
// past a limit of their own -- GitHub's is sixty-five thousand characters. This
// is well inside that and still far longer than anything worth reading in a
// review, and what does not fit is counted rather than dropped in silence.
const MaxReviewBytes = 16000

// Review renders a bundle for a pull request.
//
// It is short on purpose. The Markdown report answers "what did the tool find",
// at whatever length that takes; this answers "should I merge this", to someone
// who has thirty seconds and a diff open. Everything the report carries is
// still in the bundle, which the workflow can attach.
//
// It carries the same decision, the same findings and the same required
// unknowns as the JSON, because a reader must not learn less from the short
// form -- and a test asserts that rather than a reader comparing them.
func Review(b evidence.Bundle) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	c := evidence.Canonical(b)

	var out bytes.Buffer
	// First, so a workflow can find it by reading the start of a comment.
	fmt.Fprintf(&out, "<!-- %s -->\n\n", Marker(c.Subject))
	// The summary is prose the contract bounds only to one line, so it is cut
	// here: a bound that holds for every field but one is not a bound, and the
	// one it does not hold for is the field printed before anything else.
	fmt.Fprintf(&out, "### InfraProof: %s\n\n%s\n", c.Decision, prose(cut(c.Summary, maxSummaryInReview)))

	if len(c.Findings) > 0 {
		out.WriteString("\n| | Rule | Resource | Claim |\n| --- | --- | --- | --- |\n")
	}
	// Bounded as it is built. Rendering everything and cutting the result would
	// cut a row in half, and half a row is a claim about a resource that is not
	// there.
	//
	// It stops at the first row that does not fit rather than stepping over it.
	// Canonical order puts the severe first, and skipping onwards printed a
	// short low finding while a long critical one was counted as omitted --
	// which shows a reader the least of what was found.
	var omitted int
	for i, finding := range c.Findings {
		row := reviewRow(finding)
		if out.Len()+len(row)+tailFor(c) > MaxReviewBytes {
			omitted = len(c.Findings) - i
			break
		}
		out.WriteString(row)
	}

	required := requiredUnknowns(c.Unknowns)
	for i, unknown := range required {
		line := fmt.Sprintf("- %s: %s\n", code(unknown.CheckID), prose(unknown.Reason))
		heading := ""
		if i == 0 {
			heading = "\n**Not determined, and required:**\n\n"
		}
		if out.Len()+len(heading)+len(line)+tailFor(c) > MaxReviewBytes {
			omitted += len(required) - i
			break
		}
		out.WriteString(heading)
		out.WriteString(line)
	}

	if omitted > 0 {
		fmt.Fprintf(&out, "\n_%d further %s not shown here; the attached Evidence Bundle "+
			"carries all of them._\n", omitted, plural(omitted, "entry is", "entries are"))
	}

	// What could not be concluded but did not prevent a pass. The long report
	// lists these; a reviewer with a diff open needs to know there are some,
	// because a verdict with a dozen unanswered checks behind it is not the
	// same as one with none, and printing neither reads as coverage.
	if bounding := len(c.Unknowns) - len(required); bounding > 0 {
		fmt.Fprintf(&out, "\n_%d further %s could not be determined; %s not prevent a pass, "+
			"and the Evidence Bundle names %s._\n",
			bounding, plural(bounding, "check", "checks"), plural(bounding, "it does", "they do"),
			plural(bounding, "it", "them"))
	}

	out.WriteString(closing(c))
	return out.Bytes(), nil
}

// closing is the last line: which plan was read, and what it was compared
// against. The contract puts no length on the source, and inlineText expands
// some characters fivefold, so the one field a caller controls is cut here
// rather than allowed to carry the comment past its bound.
func closing(c evidence.Bundle) string {
	// Bounded first, on a character boundary, and set in code afterwards.
	//
	// Escaping it as prose was wrong twice over: a code span does no entity or
	// backslash processing, so "a&b[1]" was shown as "a&amp;b\[1]" -- a path
	// that does not exist, and one the long report spells correctly. And the
	// bound was measured over the escaped text, so the cut landed in a
	// different place than it reads, and on a byte rather than a character: a
	// three-byte rune split across it left the comment invalid UTF-8.
	return fmt.Sprintf("\nPlan %s, verified offline against %s.\n",
		code(short(c.Subject.PlanDigest)), code(cut(c.Subject.IntentSource, maxSourceInReview)))
}

// cut shortens a value to at most n characters, on a character boundary, and
// says that it did.
func cut(text string, n int) string {
	count := 0
	for at := range text {
		count++
		if count > n {
			return text[:at] + "…"
		}
	}
	return text
}

// tailFor is the room the rest of the rendering needs, measured rather than
// guessed. A fixed reserve was wrong in the one direction that matters: the
// closing line grows with a field nobody bounds.
func tailFor(c evidence.Bundle) int {
	return len(closing(c)) + maxNoticeBytes
}

const (
	// maxSourceInReview bounds the contract path the closing line prints, and
	// maxSummaryInReview the sentence above it. Both are fields nothing else
	// bounds: the bundle contract asks a summary to be one line and a source to
	// be non-empty, and neither to be short.
	maxSourceInReview  = 200
	maxSummaryInReview = 2000
	// maxNoticeBytes is room for the two notices: what was omitted, and what
	// could not be determined without preventing a pass.
	maxNoticeBytes = 400
)

// Marker identifies the inputs a review is about, so a workflow can update one
// comment instead of appending one per push.
//
// It names the plan and the contract and nothing else. A marker carrying a run
// number, a commit, or a timestamp would be new on every push, which is the
// thing it exists to prevent -- and one carrying only the contract would make
// two plans in one pull request overwrite each other.
func Marker(subject evidence.Subject) string {
	sum := sha256.Sum256([]byte(subject.PlanDigest + "\x00" + subject.IntentDigest))
	return "infraproof:" + hex.EncodeToString(sum[:8])
}

// reviewRow is one finding, as a table row.
func reviewRow(f evidence.Finding) string {
	resource := "-"
	if f.Resource != nil {
		resource = code(f.Resource.Address)
	}
	return "| " + strings.Join([]string{
		escapeCell(string(f.Severity)),
		escapeCell(code(f.RuleID)),
		escapeCell(resource),
		escapeCell(prose(f.Claim)),
	}, " | ") + " |\n"
}

// requiredUnknowns returns the unknowns that prevent a pass. The others bound
// the evidence rather than the conclusion, and a reviewer with thirty seconds
// is reading for what stops the change.
func requiredUnknowns(unknowns []evidence.Unknown) []evidence.Unknown {
	out := make([]evidence.Unknown, 0, len(unknowns))
	for _, unknown := range unknowns {
		if unknown.Required {
			out = append(out, unknown)
		}
	}
	return out
}

// short renders a digest at a length a person can compare by eye.
func short(digest string) string {
	body, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(body) < 12 {
		return inlineText(digest)
	}
	return body[:12]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
