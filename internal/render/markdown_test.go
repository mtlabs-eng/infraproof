package render_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
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
			Path:            `change.after | forged | row | x | y |`,
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

// TestNoFieldCanForgeDocumentStructure states the invariant once, over every
// field, rather than once per field.
//
// docs/EVIDENCE-BUNDLE.md requires that a report a human is expected to trust
// cannot be made to display structure a rule did not produce. That requirement
// was first enforced by naming the four prose fields that existed when it was
// written, and every field added afterwards re-opened the hole in silence.
//
// An earlier form of this test was itself two field lists: a table of eight
// cases and a second function that built the benign reference. A field in
// neither produced a hostile bundle and a reference identical to it, so the
// comparison held trivially and the answer for an unknown field was "safe" —
// absence read as permission, inside the mechanism written to stop absence
// being read as permission.
//
// Both lists are gone. The fields are discovered by walking the bundle, and
// the reference is the same walk with an ordinary value. A field added later
// is covered by existing, which is the only guarantee that survives someone
// forgetting.
func TestNoFieldCanForgeDocumentStructure(t *testing.T) {
	// A payload the bundle contract accepts, so the renderer is what is under
	// test. Line breaks are refused at the contract now, which is a stronger
	// answer and is asserted in internal/evidence; a payload carrying one
	// would make every case below exit before it compared anything, which is
	// what an earlier form of this test did.
	//
	// What is left forges structure without a break: a pipe opens a table
	// cell, a backtick closes a code span, and a Markdown renderer that
	// permits HTML — GitHub's does — reads a tag mid-sentence as real
	// structure.
	const forgery = "x` | forged | cell | <h1>ALL CLEAR</h1> <!-- x"
	const benign = "ordinary-value"

	paths := stringFieldsOf(hostileBundle())
	if len(paths) < 15 {
		t.Fatalf("the walk found only %d fields, which is too few to be walking anything", len(paths))
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			hostile := hostileBundle()
			if !setStringAt(&hostile, path, forgery) {
				t.Fatalf("could not reach %s", path)
			}
			out, err := render.Markdown(hostile)
			if err != nil {
				// Refusing the bundle is an acceptable answer: a report that is
				// not produced cannot mislead anyone.
				return
			}

			reference := hostileBundle()
			if !setStringAt(&reference, path, benign) {
				t.Fatalf("could not reach %s in the reference", path)
			}
			want, err := render.Markdown(reference)
			if err != nil {
				t.Fatalf("the benign bundle did not render: %v", err)
			}

			if got, expected := structureOf(string(out)), structureOf(string(want)); got != expected {
				t.Fatalf("%s changed the document structure\n got: %s\nwant: %s\n\n%s",
					path, got, expected, out)
			}
		})
	}
}

// hostileBundle is a bundle with every optional field populated, so the walk
// reaches everything a report can carry.
func hostileBundle() evidence.Bundle {
	address := "aws_s3_bucket.assets"
	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionBlock,
		Summary:       "The change violates the intent contract in 1 way.",
		Subject: evidence.Subject{IntentSource: "intent.json", PlanFormatVersion: "1.2",
			PlanDigest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"}},
		Findings: []evidence.Finding{{
			RuleID: "STORAGE_PUBLIC", Severity: evidence.SeverityCritical,
			Disposition: evidence.DispositionBlock,
			Claim:       "The change grants public access to object storage.",
			Resource: &evidence.Resource{Address: address,
				Provider: "registry.terraform.io/hashicorp/aws", Cloud: evidence.CloudAWS},
			Expected: &evidence.ExpectedFact{Path: "object_storage.public_access",
				Value: evidence.String("private")},
			Observed: evidence.KnownFact("object_storage.public_access", evidence.String("public")),
			Evidence: []evidence.EvidenceRef{{Source: "terraform_plan",
				ResourceAddress: address, Path: "acl"}},
			Remediation: "Remove the grant.",
		}},
		Unknowns: []evidence.Unknown{{
			CheckID: "STORAGE_PUBLIC_DETERMINABLE", Required: false,
			Reason: "A control is not in this plan.", ResourceAddress: &address,
			Evidence: []evidence.EvidenceRef{{Source: "terraform_plan",
				ResourceAddress: address, Path: "policy"}},
		}},
	}
}

// stringFieldsOf returns the path of every string a bundle carries.
func stringFieldsOf(bundle evidence.Bundle) []string {
	var paths []string
	walkStrings(reflect.ValueOf(bundle), "", func(path string) { paths = append(paths, path) })
	slices.Sort(paths)
	return paths
}

func walkStrings(value reflect.Value, path string, visit func(string)) {
	switch value.Kind() {
	case reflect.String:
		visit(path)
	case reflect.Pointer:
		if !value.IsNil() {
			walkStrings(value.Elem(), path, visit)
		}
	case reflect.Slice:
		for i := range value.Len() {
			walkStrings(value.Index(i), fmt.Sprintf("%s[%d]", path, i), visit)
		}
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			name := field.Name
			if path != "" {
				name = path + "." + name
			}
			walkStrings(value.Field(i), name, visit)
		}
	}
}

// setStringAt writes a value at a path produced by walkStrings. A Scalar is
// unexported inside and is set through its constructor instead.
func setStringAt(bundle *evidence.Bundle, path, text string) bool {
	switch path {
	case "Findings[0].Expected.Value":
		bundle.Findings[0].Expected.Value = evidence.String(text)
		return true
	case "Findings[0].Observed.Value":
		bundle.Findings[0].Observed.Value = evidence.String(text)
		return true
	}

	var done bool
	walkSettable(reflect.ValueOf(bundle).Elem(), "", path, text, &done)
	return done
}

func walkSettable(value reflect.Value, path, target, text string, done *bool) {
	if *done {
		return
	}
	switch value.Kind() {
	case reflect.String:
		if path == target && value.CanSet() {
			value.SetString(text)
			*done = true
		}
	case reflect.Pointer:
		if !value.IsNil() {
			walkSettable(value.Elem(), path, target, text, done)
		}
	case reflect.Slice:
		for i := range value.Len() {
			walkSettable(value.Index(i), fmt.Sprintf("%s[%d]", path, i), target, text, done)
		}
	case reflect.Struct:
		for i := range value.NumField() {
			field := value.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			name := field.Name
			if path != "" {
				name = path + "." + name
			}
			walkSettable(value.Field(i), name, target, text, done)
		}
	}
}

// structureOf reduces a document to the shape a reader navigates by: its
// headings, table rows and list items, with all inline content removed. Two
// documents with the same structure differ only in what they say, never in
// what they are.
func structureOf(document string) string {
	var shape []string
	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			shape = append(shape, strings.Repeat("#", len(trimmed)-len(strings.TrimLeft(trimmed, "#"))))
		case strings.HasPrefix(trimmed, "|"):
			// Only unescaped pipes are cell boundaries. An escaped one is
			// content that happens to contain the character.
			shape = append(shape, fmt.Sprintf("|%d", countUnescaped(trimmed, '|')))
		case strings.HasPrefix(trimmed, "- "):
			shape = append(shape, "-")
		}
		// Raw HTML is structure wherever it sits, not only at the start of a
		// line: a renderer that permits it — GitHub's does — reads a
		// mid-sentence tag as a real heading. Inside a code span it is inert,
		// because the backticks protect it, so the spans come out first.
		if bare := withoutCodeSpans(line); strings.Contains(bare, "<h1") ||
			strings.Contains(bare, "<!--") {
			shape = append(shape, "html")
		}
	}
	return strings.Join(shape, " ")
}

// withoutCodeSpans removes the content of every closed code span, which a
// Markdown renderer does not interpret.
//
// An unmatched backtick run is not a span: CommonMark renders it literally and
// the bytes after it are live. An earlier form treated one as opening a span to
// the end of the line, which hid live HTML from the forgery test and made it
// blind to the mutant it exists to catch — a code() that opens a span and
// never closes it.
//
// So a run is a delimiter only once its partner has been found. The line is
// scanned first to learn which runs pair up.
func withoutCodeSpans(line string) string {
	type run struct{ start, length int }

	var runs []run
	for i := 0; i < len(line); i++ {
		if line[i] != '`' {
			continue
		}
		length := 0
		for i+length < len(line) && line[i+length] == '`' {
			length++
		}
		runs = append(runs, run{start: i, length: length})
		i += length - 1
	}

	// Pair each opener with the next run of equal length, as CommonMark does.
	removed := map[int]int{}
	used := make([]bool, len(runs))
	for a := range runs {
		if used[a] {
			continue
		}
		for b := a + 1; b < len(runs); b++ {
			if used[b] || runs[b].length != runs[a].length {
				continue
			}
			removed[runs[a].start] = runs[b].start + runs[b].length
			used[a], used[b] = true, true
			break
		}
	}

	var out strings.Builder
	for i := 0; i < len(line); i++ {
		if end, ok := removed[i]; ok {
			i = end - 1
			continue
		}
		out.WriteByte(line[i])
	}
	return out.String()
}

// countUnescaped counts the cell boundaries in a table row.
//
// It models the table scanner rather than the escaper: a backslash escapes the
// character after it, so a pipe is a boundary when the run of backslashes
// before it is of even length and literal when the run is odd. An earlier form
// looked back one character and answered "escaped" for both "\|" and "\\|",
// which is the same mistake the escaper made — and a test whose oracle repeats
// the code's model cannot see the code's mistake.
func countUnescaped(line string, target byte) int {
	var found int
	for i := 0; i < len(line); i++ {
		if line[i] != target {
			continue
		}
		preceding := 0
		for j := i - 1; j >= 0 && line[j] == '\\'; j-- {
			preceding++
		}
		if preceding%2 == 1 {
			continue
		}
		found++
	}
	return found
}

// TestABundleCarryingALineBreakIsRefusedNotRendered records where this
// guarantee moved.
//
// A break inside a code span ends the span and, if blank, the paragraph too,
// and everything after it becomes document text. The renderer collapses breaks,
// and the bundle contract now refuses them outright — which is the stronger
// answer, because a report that is not produced cannot mislead anyone. An
// earlier form of this test rendered such a bundle and inspected the output;
// once the contract began refusing it, that form returned early and asserted
// nothing.
func TestABundleCarryingALineBreakIsRefusedNotRendered(t *testing.T) {
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

			if _, err := render.Markdown(bundle); err == nil {
				t.Fatal("a bundle carrying a line break was rendered rather than refused")
			}
		})
	}
}

// TestABackslashDoesNotAddATableCell keeps a cell's escaping from being undone
// by the character that does the escaping.
//
// Escaping the pipe alone turns a cell holding `\|` into `\\|`, which a
// Markdown renderer reads as an escaped backslash followed by a live pipe. The
// row gains a cell, and GitHub discards everything past the header count — so
// the columns after the one carrying the address vanish from the report
// without any sign that they did.
//
// A for_each key may contain a backslash, so a plan can produce one.
func TestABackslashDoesNotAddATableCell(t *testing.T) {
	address := `aws_s3_bucket.b["c:\|drive"]`
	bundle := contractBundle()
	bundle.Unknowns = []evidence.Unknown{{
		CheckID:         "STORAGE_PUBLIC_DETERMINABLE",
		Required:        false,
		Reason:          "Public access could not be determined.",
		ResourceAddress: &address,
		Evidence:        []evidence.EvidenceRef{{Source: "terraform_plan", Path: "acl"}},
	}}

	out, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}

	var header int
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := countUnescaped(trimmed, '|')
		if strings.Contains(trimmed, "Check") && strings.Contains(trimmed, "Required") {
			header = cells
			continue
		}
		if header != 0 && cells != header {
			t.Fatalf("a row has %d cell boundaries where the header has %d: %q",
				cells, header, trimmed)
		}
	}
	if header == 0 {
		t.Fatal("the unknowns table was not rendered")
	}
}

// TestABackslashSurvivesTheReport keeps the fix for the cell boundary from
// costing the report its content.
//
// Doubling every backslash also stops a pipe opening a cell, and inside a code
// span a Markdown renderer does no escape processing — so a doubled backslash
// is shown doubled, and an address containing one stops being the address the
// plan held. Only a run that decides a pipe's parity needs doubling.
func TestABackslashSurvivesTheReport(t *testing.T) {
	address := `aws_s3_bucket.b["c:\drive"]`
	bundle := contractBundle()
	bundle.Findings[0].Resource = &evidence.Resource{
		Address: address, Provider: "p", Cloud: evidence.CloudAWS}
	bundle.Unknowns = []evidence.Unknown{{
		CheckID:         "STORAGE_PUBLIC_DETERMINABLE",
		Required:        false,
		Reason:          "Public access could not be determined.",
		ResourceAddress: &address,
		Evidence:        []evidence.EvidenceRef{{Source: "terraform_plan", Path: "acl"}},
	}}

	out, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	if !strings.Contains(string(out), address) {
		t.Fatalf("the report does not print the address the plan held:\n%s", out)
	}
}

// TestAnUnterminatedCodeSpanIsNotASpan pins the oracle the umbrella forgery
// test depends on.
//
// CommonMark renders an unmatched backtick run literally, so the bytes after
// it are live. Treating one as opening a span to end of line made the umbrella
// test blind to exactly the mutant it exists to catch: a code() that opens a
// span and never closes it.
func TestAnUnterminatedCodeSpanIsNotASpan(t *testing.T) {
	for name, line := range map[string]string{
		"one unmatched tick":    "a ` <h1>live</h1>",
		"mismatched runs":       "a ``b` <h1>live</h1>",
		"closed then unmatched": "a `b`` c <h1>live</h1>",
		"trailing run":          "a `b` c <h1>live</h1> `",
	} {
		t.Run(name, func(t *testing.T) {
			if bare := withoutCodeSpans(line); !strings.Contains(bare, "<h1") {
				t.Fatalf("live HTML was hidden behind an unmatched backtick: %q -> %q", line, bare)
			}
		})
	}

	// A properly closed span does protect its content.
	if bare := withoutCodeSpans("a `<h1>inert</h1>` b"); strings.Contains(bare, "<h1") {
		t.Errorf("a closed code span did not protect its content: %q", bare)
	}
}
