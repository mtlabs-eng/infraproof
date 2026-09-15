package render

import (
	"fmt"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

// Markdown renders the bundle as a review-oriented report: one section per
// finding, tables for verification coverage and unknowns. It is derived from
// the same in-memory bundle as the canonical JSON and is equally deterministic.
//
// It returns the validation error without rendering when the bundle violates
// the contract.
func Markdown(b evidence.Bundle) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}
	c := evidence.Canonical(b)

	blocks := []string{
		"# InfraProof: " + string(c.Decision),
		prose(c.Summary),
		"## Subject",
		subjectBlock(c.Subject),
		"## Verification",
		verificationTable(c.Verification),
		"## Findings",
	}
	blocks = append(blocks, findingBlocks(c.Findings)...)
	blocks = append(blocks, "## Unknowns")
	blocks = append(blocks, unknownsBlock(c.Unknowns))

	return []byte(strings.Join(blocks, "\n\n") + "\n"), nil
}

// subjectBlock lists the verification inputs.
func subjectBlock(s evidence.Subject) string {
	return strings.Join([]string{
		"- Intent source: " + code(s.IntentSource),
		"- Plan format version: " + code(s.PlanFormatVersion),
		"- Plan digest: " + code(s.PlanDigest),
	}, "\n")
}

// verificationTable reports which checks ran, in the order the producer chose.
func verificationTable(checks []evidence.Verification) string {
	rows := make([][]string, 0, len(checks))
	for _, v := range checks {
		rows = append(rows, []string{inlineText(v.Name), string(v.Status), inlineText(v.Method)})
	}
	return table([]string{"Check", "Status", "Method"}, rows)
}

// findingBlocks renders one section per finding, or a single "None." block.
func findingBlocks(findings []evidence.Finding) []string {
	if len(findings) == 0 {
		return []string{"None."}
	}

	blocks := make([]string, 0, len(findings)*3)
	for _, f := range findings {
		blocks = append(blocks,
			fmt.Sprintf("### %s / %s - %s", f.Severity, f.Disposition, f.RuleID),
			prose(f.Claim),
			strings.Join(findingBullets(f), "\n"),
		)
	}
	return blocks
}

// findingBullets renders the facts of one finding. A bullet is omitted rather
// than emitted empty when the finding does not carry that fact.
func findingBullets(f evidence.Finding) []string {
	bullets := make([]string, 0, 5+len(f.Evidence))

	if f.Resource != nil {
		bullets = append(bullets, fmt.Sprintf("- Resource: %s (%s, %s)",
			code(f.Resource.Address), f.Resource.Cloud, f.Resource.Provider))
	}
	if f.Expected != nil {
		bullets = append(bullets, fmt.Sprintf("- Expected: %s = %s",
			code(f.Expected.Path), code(f.Expected.Value.Display())))
	}
	if f.Observed != nil {
		bullets = append(bullets, "- Observed: "+observedText(*f.Observed))
	}
	for _, ref := range f.Evidence {
		bullets = append(bullets, "- Evidence: "+evidenceText(ref))
	}
	bullets = append(bullets, "- Remediation: "+inlineText(f.Remediation))

	return bullets
}

// observedText renders an observed fact. Only a KNOWN fact has a value slot at
// all, so an unknown, absent, or redacted field cannot read as a value.
func observedText(o evidence.ObservedFact) string {
	if o.State == evidence.FactKnown {
		return fmt.Sprintf("%s = %s (%s)", code(o.Path), code(o.Value.Display()), o.State)
	}
	return fmt.Sprintf("%s (%s)", code(o.Path), o.State)
}

// evidenceText renders one evidence reference: where the data was read from,
// never what it contained.
func evidenceText(ref evidence.EvidenceRef) string {
	parts := []string{ref.Source}
	if ref.ResourceAddress != "" {
		parts = append(parts, code(ref.ResourceAddress))
	}
	parts = append(parts, code(ref.Path))
	text := strings.Join(parts, " ")
	if ref.Redacted {
		text += " (redacted)"
	}
	return text
}

// unknownsBlock renders the unknowns table, or a single "None." block.
func unknownsBlock(unknowns []evidence.Unknown) string {
	if len(unknowns) == 0 {
		return "None."
	}

	rows := make([][]string, 0, len(unknowns))
	for _, u := range unknowns {
		rows = append(rows, []string{
			u.CheckID,
			yesNo(u.Required),
			inlineText(u.Reason),
			optionalCode(u.ResourceAddress),
			evidenceList(u.Evidence),
		})
	}
	return table([]string{"Check", "Required", "Reason", "Resource", "Evidence"}, rows)
}

// evidenceList flattens evidence references into one table cell.
func evidenceList(refs []evidence.EvidenceRef) string {
	if len(refs) == 0 {
		return "-"
	}
	texts := make([]string, 0, len(refs))
	for _, ref := range refs {
		texts = append(texts, evidenceText(ref))
	}
	return strings.Join(texts, "; ")
}

// table renders a GitHub-flavored Markdown table with escaped cells.
func table(headers []string, rows [][]string) string {
	lines := make([]string, 0, len(rows)+2)
	lines = append(lines, row(headers), row(dividers(len(headers))))
	for _, r := range rows {
		lines = append(lines, row(r))
	}
	return strings.Join(lines, "\n")
}

func row(cells []string) string {
	escaped := make([]string, 0, len(cells))
	for _, cell := range cells {
		escaped = append(escaped, escapeCell(cell))
	}
	return "| " + strings.Join(escaped, " | ") + " |"
}

func dividers(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "---"
	}
	return out
}

// escapeCell keeps a cell on one row: a literal pipe is escaped and any line
// break collapses to a space, so free-text reasons cannot break the table.
func escapeCell(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.ReplaceAll(s, "|", `\|`)
}

// prose renders a free-text field as a standalone paragraph. The bundle
// contract already forbids line breaks in prose, so the remaining risk is a
// leading sequence that Markdown reads as the start of a block: a paragraph
// beginning "## " would become a heading, and one beginning "- " a list item.
//
// Escaping fires only where a sequence genuinely opens a block. A claim that
// leads with a resource address in a code span, with emphasis, or with a
// negative number is ordinary phrasing and is left untouched — over-escaping
// would corrupt the most natural way a rule has to describe a finding.
//
// Raw HTML is neutralised anywhere in the line, not only at its start: a
// Markdown renderer that permits HTML — GitHub's does — would otherwise let a
// mid-sentence tag produce real structure.
func prose(s string) string {
	s = inlineText(strings.TrimSpace(s))
	if at := blockOpenerAt(s); at >= 0 {
		return s[:at] + `\` + s[at:]
	}
	return s
}

// blockOpenerAt returns the index at which a backslash must be inserted to stop
// s from opening a Markdown block, or -1 when s opens no block.
func blockOpenerAt(s string) int {
	if s == "" {
		return -1
	}

	switch s[0] {
	case '#', '>', '|':
		// Heading, blockquote, table row. A raw HTML block needs no case here:
		// inlineText has already neutralised the opening "<".
		return 0
	case '-', '+', '*', '_':
		// A bullet needs a following space; a thematic break needs a run of
		// three. Neither "-1 replicas" nor "*emphasis*" is either.
		if isBullet(s) || hasRunOfThree(s) {
			return 0
		}
	case '`', '~':
		// One or two backticks open a code span, which is inline and harmless.
		// Three open a fenced code block.
		if hasRunOfThree(s) {
			return 0
		}
	}

	// An ordered list marker: digits, then "." or ")", then a space. "1.5 GiB"
	// is a decimal number, not a list.
	digits := leadingDigits(s)
	if digits > 0 && digits < len(s) && (s[digits] == '.' || s[digits] == ')') {
		if digits+1 == len(s) || s[digits+1] == ' ' {
			return digits
		}
	}

	return -1
}

// isBullet reports whether s opens a bullet list item: a marker followed by a
// space, or a marker alone.
func isBullet(s string) bool {
	return len(s) == 1 || s[1] == ' '
}

// hasRunOfThree reports whether s opens with three or more of its first byte,
// the length at which a fence or thematic break takes effect.
func hasRunOfThree(s string) bool {
	return len(s) >= 3 && s[1] == s[0] && s[2] == s[0]
}

// leadingDigits returns the length of the run of ASCII digits starting s.
func leadingDigits(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return i
		}
	}
	return len(s)
}

// inlineText neutralises raw HTML in a free-text field. It is applied only to
// plain prose, never to content inside a code span: a span already renders its
// contents literally, so escaping there would show a reader "&amp;amp;" where the
// data says "&amp;".
func inlineText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	return strings.ReplaceAll(s, "<", "&lt;")
}

// code wraps a value in a Markdown code span wide enough to contain it. A value
// carrying backticks gets a longer fence, and one that begins or ends with a
// backtick is padded, so the span cannot terminate early and spill a resource
// address or field path into the surrounding prose as markup.
func code(s string) string {
	fence := "`"
	for strings.Contains(s, fence) {
		fence += "`"
	}
	padding := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		padding = " "
	}
	return fence + padding + s + padding + fence
}

// optionalCode renders a pointer as code, or "-" when it is nil.
func optionalCode(s *string) string {
	if s == nil {
		return "-"
	}
	return code(*s)
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
