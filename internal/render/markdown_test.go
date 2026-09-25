package render_test

import (
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"
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
	const forgery = "x` | forged | cell | <h1>ALL CLEAR</h1> <!-- x " +
		"![](https://host.invalid/p.png) [link](https://host.invalid/) [ref]: https://host.invalid/"
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
		Subject: evidence.Subject{IntentSource: "intent.json",
			IntentDigest:      "sha256:1111111111111111111111111111111111111111111111111111111111111111",
			PlanFormatVersion: "1.2",
			PlanDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
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
		if value.Type() == reflect.TypeFor[evidence.Scalar]() {
			// A Scalar holds its text unexported, so the walk finds nothing
			// inside it and the field went uncovered. "A field added later is
			// covered by what exists" does not hold for anything behind
			// unexported state, and these two carry plan values.
			visit(path)
			return
		}
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
// autolink is CommonMark's absolute-URI autolink: a scheme of two or more
// characters, a colon, and no space or angle bracket until the closing one.
var autolink = regexp.MustCompile(`<[A-Za-z][A-Za-z0-9+.\-]{1,31}:[^<>[:space:]]*>`)

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

		// A link, an image and a link reference definition are all structure a
		// reader can act on: an image fires a request from a report this build
		// exists to keep offline, and a definition consumes the paragraph it
		// sits in. Each of them needs an opening bracket, and prose escapes
		// one, so an unescaped bracket outside a code span is the signal.
		if brackets := countUnescaped(withoutCodeSpans(line), '['); brackets > 0 {
			shape = append(shape, fmt.Sprintf("[%d", brackets))
		}
		// Raw HTML is structure wherever it sits, not only at the start of a
		// line: a renderer that permits it — GitHub's does — reads a
		// mid-sentence tag as a real heading. Inside a code span it is inert,
		// because the backticks protect it, so the spans come out first.
		bare := withoutCodeSpans(line)
		if strings.Contains(bare, "<h1") || strings.Contains(bare, "<!--") {
			shape = append(shape, "html")
		}
		// An autolink is a link nobody wrote as one: CommonMark turns
		// "<scheme:anything>" into a live anchor, and a report that offers a
		// reader something to click is a report that reaches the network this
		// build exists to stay off. It is matched by none of the three signals
		// above, which look for a bracket or for a tag by name.
		if autolink.MatchString(bare) {
			shape = append(shape, "autolink")
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
// Escapes and spans interleave, and that is the part a local rule cannot get
// right. Outside a span a backslash makes the next character literal, so an
// escaped backtick is not part of a run: "\\```0```[" is a literal backtick
// followed by a run of two, which finds no partner, so nothing is a span and
// everything is text. Inside a span a backslash is an ordinary character, so
// "`[\\`" is a closed span whose content happens to end in one — which is why
// skipping the character after every backslash is wrong in the other direction.
//
// So the line is walked once, left to right, in the order the two rules apply.
func withoutCodeSpans(line string) string {
	var out strings.Builder

	for i := 0; i < len(line); {
		switch {
		case line[i] == '\\' && i+1 < len(line):
			// Both characters are literal, and the escaped one cannot open a
			// span. They are kept, because countUnescaped reads the backslash
			// to decide whether what follows is syntax.
			out.WriteString(line[i : i+2])
			i += 2

		case line[i] == '`':
			opener := backtickRun(line, i)
			closer := closingRun(line, i+opener, opener)
			if closer < 0 {
				// No partner, so this is text rather than a delimiter.
				out.WriteString(line[i : i+opener])
				i += opener
				continue
			}
			i = closer + opener

		default:
			out.WriteByte(line[i])
			i++
		}
	}

	return out.String()
}

// backtickRun returns the length of the run of backticks starting at i.
func backtickRun(line string, i int) int {
	length := 0
	for i+length < len(line) && line[i+length] == '`' {
		length++
	}
	return length
}

// closingRun returns the offset of the first run of exactly n backticks at or
// after from, or -1. A backslash inside a span is an ordinary character, so the
// search for a closer does not honour escapes.
func closingRun(line string, from, n int) int {
	for i := from; i < len(line); {
		if line[i] != '`' {
			i++
			continue
		}
		length := backtickRun(line, i)
		if length == n {
			return i
		}
		i += length
	}
	return -1
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
	// The last three are the interleaving of the two rules, and every expected
	// answer here was checked against a CommonMark implementation rather than
	// reasoned about. A backslash inside a span is an ordinary character, so
	// the run after "b\\" still closes the span and what follows is live.
	for name, line := range map[string]string{
		"one unmatched tick":                       "a ` <h1>live</h1>",
		"mismatched runs":                          "a ``b` <h1>live</h1>",
		"closed then unmatched":                    "a `b`` c <h1>live</h1>",
		"trailing run":                             "a `b` c <h1>live</h1> `",
		"a span whose content ends in a backslash": "a `b\\`<h1>live</h1>` c",
		"and the same with text after it":          "a `b\\` c <h1>live</h1>",
	} {
		t.Run(name, func(t *testing.T) {
			if bare := withoutCodeSpans(line); !strings.Contains(bare, "<h1") {
				t.Fatalf("live HTML was hidden behind an unmatched backtick: %q -> %q", line, bare)
			}
		})
	}

	// A properly closed span does protect its content.
	for name, line := range map[string]string{
		"a closed span":                       "a `<h1>inert</h1>` b",
		"a span opened after an escaped tick": "a \\`b`<h1>inert</h1>` c",
	} {
		t.Run(name, func(t *testing.T) {
			// Escaping the first backtick leaves the run one shorter, so the
			// span opens later and closes around the tag. CommonMark agrees;
			// an oracle that skipped the character after every backslash does
			// not, and would report this as live.
			if bare := withoutCodeSpans(line); strings.Contains(bare, "<h1") {
				t.Errorf("a closed code span did not protect its content: %q -> %q", line, bare)
			}
		})
	}
}

// TestTheShapeOfADocumentIncludesEveryLinkAReaderCanFollow pins the oracle
// rather than the renderer.
//
// Prose escapes "<", so no field can produce an autolink today and the umbrella
// test cannot exercise this signal through the renderer. That is an argument
// for testing the signal here, not for leaving it out: what structureOf calls
// structure is the definition the umbrella test compares against, and a
// definition that omits a live link would pass a report carrying one. An
// autolink is matched by none of the other signals -- there is no bracket and
// no tag name to look for.
func TestTheShapeOfADocumentIncludesEveryLinkAReaderCanFollow(t *testing.T) {
	plain := structureOf("a line of text")

	for name, line := range map[string]string{
		"an absolute URI":   "a <https://host.invalid/x> b",
		"another scheme":    "a <mailto:someone@host.invalid> b",
		"no space needed":   "<ftp:x>",
		"beside other text": "The change grants access. <https://host.invalid/> Remove it.",
	} {
		t.Run(name, func(t *testing.T) {
			if structureOf(line) == plain {
				t.Errorf("a live link is not part of this document's shape: %q", line)
			}
		})
	}

	for name, line := range map[string]string{
		"escaped, as prose renders it": "a &lt;https://host.invalid/x&gt; b",
		"inside a code span":           "a `<https://host.invalid/x>` b",
		"not a scheme":                 "a <not a uri> b",
		"no colon":                     "a <https> b",
	} {
		t.Run(name, func(t *testing.T) {
			if structureOf(line) != plain {
				t.Errorf("inert text was counted as a link: %q -> %q", line, structureOf(line))
			}
		})
	}
}

// TestATableCellPrintsWhatThePlanHeld holds the half of the escaping that
// structure tests cannot see.
//
// countUnescaped counts boundaries and structureOf compares shapes; neither
// looks at what a cell says. So the change that stopped escapeCell doubling
// every backslash — made because a doubled backslash is shown doubled inside a
// code span, and an address stopped being the address the plan held — could be
// reverted wholesale with the suite still green.
//
// Structure and content are two guarantees and they need two oracles.
func TestATableCellPrintsWhatThePlanHeld(t *testing.T) {
	// Addresses that need no escaping to sit in a cell. A pipe is the one
	// character the table format reserves, so it cannot appear as the plan
	// held it; it is asserted separately below. Everything else must survive.
	for name, address := range map[string]string{
		"a windows path":       `aws_s3_bucket.b["c:\drive"]`,
		"a doubled backslash":  `aws_s3_bucket.b["a\\b"]`,
		"a trailing backslash": `aws_s3_bucket.b["a\"]`,
		"an escaped quote":     `aws_s3_bucket.b["a\"b"]`,
		"an ordinary key":      `aws_s3_bucket.b["assets"]`,
	} {
		t.Run(name, func(t *testing.T) {
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

			// The address appears as the plan held it, inside its code span.
			// A cell whose content has been mangled is a cell that no longer
			// identifies the resource a reader has to go and look at.
			if !strings.Contains(string(out), address) {
				t.Fatalf("the report does not print the address the plan held\nwant: %s\n\n%s",
					address, out)
			}
		})
	}
}

// TestAPipeIsEscapedExactlyOnce covers the one character a table cell reserves.
// It cannot appear as the plan held it, and it must appear exactly once rather
// than being doubled, dropped, or left to open a cell.
func TestAPipeIsEscapedExactlyOnce(t *testing.T) {
	address := `aws_s3_bucket.b["a|b"]`
	bundle := contractBundle()
	bundle.Unknowns = []evidence.Unknown{{
		CheckID: "STORAGE_PUBLIC_DETERMINABLE", Required: false,
		Reason: "Public access could not be determined.", ResourceAddress: &address,
		Evidence: []evidence.EvidenceRef{{Source: "terraform_plan", Path: "acl"}},
	}}

	out, err := render.Markdown(bundle)
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	if !strings.Contains(string(out), `aws_s3_bucket.b["a\|b"]`) {
		t.Fatalf("the pipe was not escaped exactly once:\n%s", out)
	}
}
