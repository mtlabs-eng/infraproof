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
		"- Intent digest: " + code(s.IntentDigest),
		"- Plan format version: " + code(s.PlanFormatVersion),
		"- Plan digest: " + code(s.PlanDigest),
	}, "\n")
}

// verificationTable reports which checks ran, in the order the producer chose.
func verificationTable(checks []evidence.Verification) string {
	rows := make([][]string, 0, len(checks))
	for _, v := range checks {
		rows = append(rows, []string{inlineText(v.Name), inlineText(string(v.Status)), inlineText(v.Method)})
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
		// The provider is a plan value, so it goes in a code span like every
		// other one. inlineText neutralises a tag and leaves a link, an image
		// and emphasis alone — enough for a plan to make a report the reader
		// trusts carry a clickable host of its choosing.
		bullets = append(bullets, fmt.Sprintf("- Resource: %s (%s, %s)%s",
			code(f.Resource.Address), inlineText(string(f.Resource.Cloud)),
			code(f.Resource.Provider), locationText(f.Resource.Location)))
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
	parts := []string{inlineText(ref.Source)}
	if ref.ResourceAddress != "" {
		parts = append(parts, code(ref.ResourceAddress))
	}
	parts = append(parts, code(ref.Path))
	text := strings.Join(parts, " ")
	if ref.Redacted {
		text += " (redacted)"
	}
	return text + locationText(ref.Location)
}

// locationText renders where a declaration is written, and nothing when it is
// not known.
//
// The path goes in a code span like every other value this build did not
// author. A location is produced here, but its path comes from a filesystem
// somebody else writes to: a file called "a`b.tf" would otherwise end the span
// it is printed in, and one called "[x](...)" would plant a link in a report a
// reader trusts.
func locationText(l *evidence.Location) string {
	if l == nil {
		return ""
	}
	return " at " + code(fmt.Sprintf("%s:%d", l.File, l.Line))
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

// escapeCell makes a value safe to place between two cell boundaries.
//
// A pipe must not open a cell, and the run of backslashes before it decides
// whether it does: the table scanner reads a pipe as literal when that run is
// odd and as a boundary when it is even. So a run immediately before a pipe is
// doubled, and the pipe is then escaped, which leaves the run odd.
//
// A backslash anywhere else is left alone. Doubling every backslash also fixed
// the boundary problem and cost the report its content: inside a code span a
// Markdown renderer does no escape processing, so a doubled backslash is shown
// doubled, and an address containing one stopped being the address the plan
// held.
func escapeCell(s string) string {
	s = collapseBreaks(s)

	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			if s[i] == '|' {
				out.WriteString(`\|`)
				continue
			}
			out.WriteByte(s[i])
			continue
		}

		run := 0
		for i+run < len(s) && s[i+run] == '\\' {
			run++
		}
		if i+run < len(s) && s[i+run] == '|' {
			// The run would otherwise decide the pipe's parity for us.
			out.WriteString(strings.Repeat(`\\`, run) + `\|`)
			i += run
			continue
		}
		out.WriteString(strings.Repeat(`\`, run))
		i += run - 1
	}
	return out.String()
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
	// Trimmed after the escaping, not only before it. Collapsing a control
	// character leaves a space where the character was, and up to three spaces
	// before a "#" is still a heading — so a summary beginning with one hid the
	// opener from the check below and forged a heading with it.
	s = strings.TrimSpace(inlineText(strings.TrimSpace(s)))
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

// inlineText neutralises the markup a free-text field could otherwise open. It
// is applied only to plain prose, never to content inside a code span: a span
// already renders its contents literally, so escaping there would show a reader
// "&amp;amp;" where the data says "&amp;".
//
// Raw HTML is one half: a renderer that permits it reads a mid-sentence tag as
// real structure. The other half is the bracket. An image is a request the
// report makes on the reader's behalf, to a host the text names, from a build
// whose whole premise is that nothing leaves the machine; a link invites a
// click; a reference definition consumes the paragraph it sits in. All three
// need an opening bracket, so the bracket is escaped and none of them can
// form. A backslash before it is how CommonMark says "this is the character,
// not the syntax", and it renders as the character.
func inlineText(s string) string {
	// Every prose path, for the reason code() collapses them in a span: the
	// bundle forbids a break in the four fields that existed when the rule was
	// written, and a rule that names its fields cannot cover a field added
	// later.
	s = collapseBreaks(s)
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	// The backslash first, and for the sake of the one after it. A value ending
	// in a backslash met the escape added below and produced "\\[", which
	// CommonMark reads as an escaped backslash followed by a live bracket --
	// the escape defeated by the thing it was escaping.
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, "[", `\[`)
}

// code wraps a value in a Markdown code span wide enough to contain it. A value
// carrying backticks gets a longer fence, and one that begins or ends with a
// backtick is padded, so the span cannot terminate early and spill a resource
// address or field path into the surrounding prose as markup.
func code(s string) string {
	// A break inside a code span ends the span and, if it is blank, the
	// paragraph too: everything after it becomes document text. The bundle
	// contract forbids breaks in the four prose fields, but a code span renders
	// addresses, paths and values, and a rule that names its fields cannot
	// cover a field added later. Collapsing here makes the guarantee a property
	// of the span rather than of a list.
	s = collapseBreaks(s)

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

// collapseBreaks turns every control character into a space.
//
// A break ends a code span and, if it is blank, the paragraph too; an escape
// sequence moves a terminal's cursor or clears the line. The contract package
// says which characters those are, because it is the one that says what a
// single-line field may hold — and a renderer keeping its own copy of that rule
// is how the two come to disagree.
func collapseBreaks(s string) string {
	return evidence.Inline(s)
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
