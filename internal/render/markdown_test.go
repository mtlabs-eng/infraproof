package render_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/render"
)

func TestMarkdownGoldens(t *testing.T) {
	cases := map[string]evidence.Bundle{
		"block":    contractBundle(),
		"pass":     passBundle(),
		"redacted": redactedBundle(),
	}
	for name, bundle := range cases {
		t.Run(name, func(t *testing.T) {
			want := mustReadFile(t, filepath.Join("testdata", name+".golden.md"))
			got, err := render.Markdown(bundle)
			if err != nil {
				t.Fatalf("render.Markdown: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("Markdown mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}

func TestMarkdownIsByteIdenticalOnRepeat(t *testing.T) {
	bundle := redactedBundle()
	first, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := render.Markdown(bundle)
		if err != nil {
			t.Fatalf("render.Markdown: %v", err)
		}
		if string(again) != string(first) {
			t.Fatal("repeated rendering produced different bytes")
		}
	}
}

func TestMarkdownRendersRedactedFactWithoutAValue(t *testing.T) {
	got, err := render.Markdown(redactedBundle())
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	out := string(got)
	if !strings.Contains(out, "`object_storage.policy_document` (REDACTED)") {
		t.Fatalf("redacted fact is not marked as redacted:\n%s", out)
	}
	if strings.Contains(out, "policy_document` = ") {
		t.Fatalf("redacted fact rendered a value slot:\n%s", out)
	}
}

func TestMarkdownOrdersFindingsCanonically(t *testing.T) {
	bundle := contractBundle()
	bundle.Findings = append([]evidence.Finding{{
		RuleID:      "ZZZ_RULE",
		Severity:    evidence.SeverityInfo,
		Disposition: evidence.DispositionInfo,
		Claim:       "An informational observation.",
		Remediation: "No remediation required.",
		Evidence:    []evidence.EvidenceRef{},
	}}, bundle.Findings...)

	got, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	out := string(got)
	critical := strings.Index(out, "STORAGE_PUBLIC")
	informational := strings.Index(out, "ZZZ_RULE")
	if critical < 0 || informational < 0 {
		t.Fatalf("both findings should be rendered:\n%s", out)
	}
	if critical > informational {
		t.Fatalf("CRITICAL finding must precede INFO finding:\n%s", out)
	}
}

func TestMarkdownEscapesTableCells(t *testing.T) {
	bundle := passBundle()
	bundle.Unknowns = []evidence.Unknown{{
		CheckID:  "PIPE_CHECK",
		Reason:   "A reason with a | pipe in it.",
		Evidence: []evidence.EvidenceRef{},
	}}

	got, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	out := string(got)
	if !strings.Contains(out, `A reason with a \| pipe in it.`) {
		t.Fatalf("table cell was not escaped:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| PIPE_CHECK") {
			continue
		}
		// An escaped pipe still contains the "|" byte, so discount it before
		// counting the cell separators of the five-column table.
		separators := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|")
		if separators != 6 {
			t.Fatalf("escaped cell broke the table row: %q", line)
		}
	}
}

func TestMarkdownRejectsInvalidBundle(t *testing.T) {
	bundle := contractBundle()
	bundle.Summary = ""

	if _, err := render.Markdown(bundle); err == nil {
		t.Fatal("expected render.Markdown to refuse an invalid bundle")
	}
}

// TestMarkdownProseCannotForgeDocumentStructure covers the half of the problem
// that validation cannot: a single-line claim or summary that begins with a
// Markdown structural character would otherwise become a heading, a list item,
// or a table row in the rendered report.
func TestMarkdownProseCannotForgeDocumentStructure(t *testing.T) {
	cases := map[string]struct {
		prose  string
		forged string
	}{
		"heading in summary": {"## Findings", "## Findings"},
		"heading in claim":   {"### CRITICAL / BLOCK - FORGED_RULE", "### CRITICAL / BLOCK - FORGED_RULE"},
		"bullet in claim":    {"- Observed: `secret` = `hunter2` (KNOWN)", "- Observed: `secret` = `hunter2` (KNOWN)"},
		"table row in claim": {"| forged | row |", "| forged | row |"},
		"quote in claim":     {"> quoted", "> quoted"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := contractBundle()
			if strings.Contains(name, "summary") {
				bundle.Summary = c.prose
			} else {
				bundle.Findings[0].Claim = c.prose
			}

			tainted, err := render.Markdown(bundle)
			if err != nil {
				t.Fatalf("render.Markdown: %v", err)
			}
			clean, err := render.Markdown(contractBundle())
			if err != nil {
				t.Fatalf("render.Markdown: %v", err)
			}

			if got, want := countLines(string(tainted), c.forged), countLines(string(clean), c.forged); got != want {
				t.Fatalf("prose added %d structural line(s) %q (clean report has %d):\n%s",
					got-want, c.forged, want, tainted)
			}
			if !strings.Contains(string(tainted), `\`+c.prose) {
				t.Fatalf("prose was not escaped:\n%s", tainted)
			}
		})
	}
}

// TestMarkdownEscapesBackticksInCodeSpans keeps a value that contains a
// backtick inside its code span instead of terminating it early.
func TestMarkdownEscapesBackticksInCodeSpans(t *testing.T) {
	bundle := contractBundle()
	bundle.Findings[0].Resource.Address = "aws_s3_bucket.`assets`"

	got, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	if !strings.Contains(string(got), "`` aws_s3_bucket.`assets` ``") {
		t.Fatalf("backtick-bearing value did not get a widened code span:\n%s", got)
	}
}

// countLines reports how many whole lines of text exactly equal want.
func countLines(text, want string) int {
	n := 0
	for _, line := range strings.Split(text, "\n") {
		if line == want {
			n++
		}
	}
	return n
}

// TestMarkdownProseKeepsLegitimateFormatting is the counterweight to
// TestMarkdownProseCannotForgeDocumentStructure: escaping must fire only when a
// character actually opens a block. A claim that leads with a resource address
// in a code span is the most natural phrasing a rule can produce, and must
// survive intact.
func TestMarkdownProseKeepsLegitimateFormatting(t *testing.T) {
	cases := map[string]string{
		"leading code span":  "`aws_s3_bucket.assets` permits public access.",
		"leading emphasis":   "*Every* bucket in the plan permits public access.",
		"negative number":    "-1 replicas were requested.",
		"hyphenated opener":  "-prefixed flags were supplied.",
		"decimal number":     "1.5 GiB of storage was requested.",
		"inline pipe":        "Either `public` | `private` is required.",
		"trailing structure": "The plan is missing a value for #count.",
	}

	for name, claim := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := contractBundle()
			bundle.Findings[0].Claim = claim

			got, err := render.Markdown(bundle)
			if err != nil {
				t.Fatalf("render.Markdown: %v", err)
			}
			if !strings.Contains(string(got), "\n"+claim+"\n") {
				t.Fatalf("legitimate claim was altered; wanted it verbatim:\n%s", got)
			}
		})
	}
}

// TestMarkdownProseEscapesBlockOpeners covers the structural openers that the
// narrower rule must still catch, including the ones a leading-character check
// alone would miss.
func TestMarkdownProseEscapesBlockOpeners(t *testing.T) {
	cases := map[string]string{
		"indented heading":  "   ## Forged Section",
		"ordered list":      "1. A forged list item.",
		"ordered paren":     "1) A forged list item.",
		"bullet":            "- A forged list item.",
		"asterisk bullet":   "* A forged list item.",
		"plus bullet":       "+ A forged list item.",
		"blockquote":        "> A forged quotation.",
		"table row":         "| forged | row |",
		"fenced code":       "``` forged fence",
		"tilde fence":       "~~~ forged fence",
		"raw html block":    "<h2>Unknowns</h2><p>None.</p>",
		"setext-style rule": "--- forged rule",
	}

	for name, claim := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := contractBundle()
			bundle.Findings[0].Claim = claim

			got, err := render.Markdown(bundle)
			if err != nil {
				t.Fatalf("render.Markdown: %v", err)
			}
			for _, line := range strings.Split(string(got), "\n") {
				if line == claim || line == strings.TrimSpace(claim) {
					t.Fatalf("block opener %q was rendered unescaped:\n%s", claim, got)
				}
			}
		})
	}
}

// TestMarkdownEvidencePathCannotForgeATableRow covers the escapeCell line-break
// path, which is still reachable: evidence sources, paths, and addresses are
// checked for blankness but not for line breaks, so only the renderer keeps a
// crafted path from splitting the unknowns table.
func TestMarkdownEvidencePathCannotForgeATableRow(t *testing.T) {
	address := "aws_s3_bucket.assets"
	bundle := passBundle()
	bundle.Unknowns = []evidence.Unknown{{
		CheckID:         "STORAGE_PUBLIC_DETERMINABLE",
		Required:        false,
		Reason:          "Public access could not be determined.",
		ResourceAddress: &address,
		Evidence: []evidence.EvidenceRef{{
			Source:          "terraform_plan",
			ResourceAddress: address,
			Path:            "change.after\n| forged | row | x | y |",
		}},
	}}

	got, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	out := string(got)
	if strings.Contains(out, "\n| forged | row | x | y |\n") {
		t.Fatalf("an evidence path forged a table row:\n%s", out)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| STORAGE_PUBLIC_DETERMINABLE") {
			continue
		}
		separators := strings.Count(strings.ReplaceAll(line, `\|`, ""), "|")
		if separators != 6 {
			t.Fatalf("evidence path broke the table row: %q", line)
		}
	}
}

// TestMarkdownNeutralizesInlineHTML closes the remaining half of the prose
// forgery problem: escaping block openers stops a paragraph from becoming a
// heading, but raw HTML mid-line is rendered as structure by any Markdown
// renderer that permits HTML, including the one on GitHub.
func TestMarkdownNeutralizesInlineHTML(t *testing.T) {
	cases := map[string]func(*evidence.Bundle){
		"summary":     func(b *evidence.Bundle) { b.Summary = "Public access <h2>Unknowns</h2> enabled." },
		"claim":       func(b *evidence.Bundle) { b.Findings[0].Claim = "Storage <h2>Unknowns</h2> is public." },
		"remediation": func(b *evidence.Bundle) { b.Findings[0].Remediation = "Disable <b>public</b> access." },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := contractBundle()
			mutate(&bundle)

			got, err := render.Markdown(bundle)
			if err != nil {
				t.Fatalf("render.Markdown: %v", err)
			}
			for _, tag := range []string{"<h2>", "</h2>", "<b>", "</b>"} {
				if strings.Contains(string(got), tag) {
					t.Fatalf("raw HTML %q reached the report:\n%s", tag, got)
				}
			}
		})
	}
}

func TestMarkdownNeutralizesInlineHTMLInUnknownReason(t *testing.T) {
	bundle := passBundle()
	bundle.Unknowns = []evidence.Unknown{{
		CheckID:  "LIVE_STATE_AVAILABLE",
		Reason:   "No collector <b>was</b> supplied.",
		Evidence: []evidence.EvidenceRef{},
	}}

	got, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	if strings.Contains(string(got), "<b>") {
		t.Fatalf("raw HTML reached an unknowns cell:\n%s", got)
	}
}

// TestMarkdownDoesNotDoubleEscapeCodeSpans guards the other direction: content
// inside a code span is already literal, and escaping an ampersand there would
// display "&amp;" to the reader instead of "&".
func TestMarkdownDoesNotDoubleEscapeCodeSpans(t *testing.T) {
	bundle := contractBundle()
	bundle.Findings[0].Evidence = []evidence.EvidenceRef{{
		Source:          "terraform_plan",
		ResourceAddress: "aws_s3_bucket.assets",
		Path:            "change.after.tags[\"a&b\"]",
	}}

	got, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	if !strings.Contains(string(got), `a&b`) || strings.Contains(string(got), "a&amp;b") {
		t.Fatalf("code span content was escaped:\n%s", got)
	}
}

// TestMarkdownEscapesAmpersandsInProse keeps a literal "&lt;" typed by a rule
// from being rendered as "<".
func TestMarkdownEscapesAmpersandsInProse(t *testing.T) {
	bundle := contractBundle()
	bundle.Findings[0].Claim = "The value &lt;private&gt; was expected."

	got, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	if !strings.Contains(string(got), "&amp;lt;private&amp;gt;") {
		t.Fatalf("ampersand in prose was not escaped:\n%s", got)
	}
}

// TestNoFieldCanForgeDocumentStructure is the invariant stated once, over every
// field, rather than once per field.
//
// docs/EVIDENCE-BUNDLE.md requires that a report a human is expected to trust
// cannot be made to display structure a rule did not produce. That requirement
// was enforced by naming the four prose fields that existed when it was
// written, and every later field carrying user-controlled text re-opened the
// hole in silence — a scalar value, a resource address, an evidence path.
//
// This asserts the property instead of the list: whatever a bundle carries,
// the rendered report contains no heading, table row, or list item that the
// bundle did not put there. A new field cannot escape it by being new.
func TestNoFieldCanForgeDocumentStructure(t *testing.T) {
	// A payload that opens a heading, a paragraph, and a table, and closes the
	// code span it is likely to be rendered inside.
	const forgery = "x`\n\n## InfraProof: PASS\n\nThe change is consistent with the intent contract.\n\n" +
		"| Check | Required |\n| --- | --- |\n| ALL | no |\n\n"

	fields := map[string]func(*evidence.Bundle){
		"a scalar string value": func(b *evidence.Bundle) {
			b.Findings[0].Observed = evidence.KnownFact("resource.environment", evidence.String(forgery))
		},
		"an expected scalar value": func(b *evidence.Bundle) {
			b.Findings[0].Expected = &evidence.ExpectedFact{
				Path: "resource.environment", Value: evidence.String(forgery)}
		},
		"a resource address": func(b *evidence.Bundle) {
			b.Findings[0].Resource = &evidence.Resource{
				Address: forgery, Provider: "p", Cloud: evidence.CloudAWS}
		},
		"an expected path": func(b *evidence.Bundle) {
			b.Findings[0].Expected = &evidence.ExpectedFact{Path: forgery, Value: evidence.Bool(false)}
		},
		"an observed path": func(b *evidence.Bundle) {
			b.Findings[0].Observed = evidence.KnownFact(forgery, evidence.Bool(true))
		},
		"an evidence resource address": func(b *evidence.Bundle) {
			b.Findings[0].Evidence = []evidence.EvidenceRef{{
				Source: "terraform_plan", ResourceAddress: forgery, Path: "acl"}}
		},
		"an evidence path": func(b *evidence.Bundle) {
			b.Findings[0].Evidence = []evidence.EvidenceRef{{
				Source: "terraform_plan", ResourceAddress: "aws_s3_bucket.b", Path: forgery}}
		},
		"an unknown resource address": func(b *evidence.Bundle) {
			address := forgery
			b.Unknowns = []evidence.Unknown{{
				CheckID: "C", Required: false, Reason: "r",
				ResourceAddress: &address, Evidence: []evidence.EvidenceRef{}}}
		},
	}

	for name, mutate := range fields {
		t.Run(name, func(t *testing.T) {
			hostile := contractBundle()
			mutate(&hostile)

			out, err := render.Markdown(hostile)
			if err != nil {
				// Refusing the bundle is an acceptable answer: a report that is
				// not produced cannot mislead anyone.
				return
			}

			// The property, stated without naming a field: what a field
			// contains must not change what the document is. A benign value in
			// the same place produces the reference structure.
			benign := contractBundle()
			mutateBenign(&benign, mutate)
			reference, err := render.Markdown(benign)
			if err != nil {
				t.Fatalf("the benign bundle did not render: %v", err)
			}

			if got, want := structureOf(string(out)), structureOf(string(reference)); got != want {
				t.Fatalf("a field changed the document structure\n got: %s\nwant: %s\n\n%s",
					got, want, out)
			}
		})
	}
}

// structureOf reduces a document to the shape a reader navigates by: its
// headings and its table rows, with all inline content removed. Two documents
// with the same structure differ only in what they say, never in what they are.
func structureOf(document string) string {
	var shape []string
	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			// The heading level and nothing else: the text is content.
			shape = append(shape, strings.Repeat("#", len(trimmed)-len(strings.TrimLeft(trimmed, "#"))))
		case strings.HasPrefix(trimmed, "|"):
			// Only unescaped pipes are cell boundaries. An escaped one is
			// content that happens to contain the character.
			shape = append(shape, fmt.Sprintf("|%d", countUnescaped(trimmed, '|')))
		case strings.HasPrefix(trimmed, "- "):
			shape = append(shape, "-")
		}
	}
	return strings.Join(shape, " ")
}

// countUnescaped counts occurrences of a character that are not preceded by a
// backslash, which is how Markdown distinguishes a cell boundary from a pipe a
// cell contains.
func countUnescaped(line string, target byte) int {
	var found int
	for i := 0; i < len(line); i++ {
		if line[i] != target {
			continue
		}
		if i > 0 && line[i-1] == '\\' {
			continue
		}
		found++
	}
	return found
}

// mutateBenign applies the same mutation with harmless content, so the
// reference document differs from the hostile one only in what a field holds.
func mutateBenign(b *evidence.Bundle, mutate func(*evidence.Bundle)) {
	mutate(b)
	replaceForgery(b)
}

// replaceForgery swaps the hostile payload for an ordinary value of the same
// shape wherever it was placed.
func replaceForgery(b *evidence.Bundle) {
	const benign = "ordinary-value"

	for i := range b.Findings {
		f := &b.Findings[i]
		if f.Resource != nil && strings.Contains(f.Resource.Address, "InfraProof: PASS") {
			f.Resource.Address = benign
		}
		if f.Expected != nil {
			if strings.Contains(f.Expected.Path, "InfraProof: PASS") {
				f.Expected.Path = benign
			}
			if strings.Contains(f.Expected.Value.Display(), "InfraProof: PASS") {
				f.Expected.Value = evidence.String(benign)
			}
		}
		if f.Observed != nil {
			if strings.Contains(f.Observed.Path, "InfraProof: PASS") {
				f.Observed.Path = benign
			}
			if strings.Contains(f.Observed.Value.Display(), "InfraProof: PASS") {
				f.Observed.Value = evidence.String(benign)
			}
		}
		for j := range f.Evidence {
			if strings.Contains(f.Evidence[j].ResourceAddress, "InfraProof: PASS") {
				f.Evidence[j].ResourceAddress = benign
			}
			if strings.Contains(f.Evidence[j].Path, "InfraProof: PASS") {
				f.Evidence[j].Path = benign
			}
		}
	}
	for i := range b.Unknowns {
		if address := b.Unknowns[i].ResourceAddress; address != nil &&
			strings.Contains(*address, "InfraProof: PASS") {
			ordinary := benign
			b.Unknowns[i].ResourceAddress = &ordinary
		}
	}
}

// TestCodeSpansCannotBeClosedFromInside keeps a code span a code span. A value
// rendered inside backticks that contains a line break ends the span and the
// paragraph, and everything after it becomes document text.
func TestCodeSpansCannotBeClosedFromInside(t *testing.T) {
	for name, payload := range map[string]string{
		"a newline":         "a\nb",
		"a carriage return": "a\rb",
		"a CRLF":            "a\r\nb",
		"a blank line":      "a\n\nb",
	} {
		t.Run(name, func(t *testing.T) {
			bundle := contractBundle()
			bundle.Findings[0].Resource = &evidence.Resource{
				Address: payload, Provider: "p", Cloud: evidence.CloudAWS}

			out, err := render.Markdown(bundle)
			if err != nil {
				return
			}
			for _, line := range strings.Split(string(out), "\n") {
				if !strings.Contains(line, "- Resource:") {
					continue
				}
				if strings.Count(line, "`")%2 != 0 {
					t.Fatalf("a code span was left open: %q", line)
				}
			}
			if strings.Contains(string(out), "\n\nb") {
				t.Fatalf("a value escaped its span:\n%s", out)
			}
		})
	}
}
