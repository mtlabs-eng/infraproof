package tfconfig

import (
	"os"
	"path/filepath"
	"testing"
)

// fixtureSource reads one configuration file the repository ships. The scanner
// is tested against real HCL for the reason milestone 02 learned the hard way:
// a hand-authored fixture can misrepresent the format, and one did.
func fixtureSource(t *testing.T, parts ...string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{"testdata"}, parts...)...))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return raw
}

// attributeLine is the line an argument is written on, or zero when it is not
// written in that block.
func attributeLine(d declaration, name string) int {
	if line, written := d.lineOf(name); written {
		return line
	}
	return 0
}

// found returns the one declaration of a type and name, and fails if the file
// holds none or several.
func found(t *testing.T, declarations []declaration, kind, resourceType, name string) declaration {
	t.Helper()
	var hits []declaration
	for _, d := range declarations {
		if d.Kind == kind && d.Type == resourceType && d.Name == name {
			hits = append(hits, d)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("%s %q %q: found %d declarations, want 1 (all: %v)", kind, resourceType, name, len(hits), declarations)
	}
	return hits[0]
}

// TestScanFindsDeclarationsInGeneratedConfiguration reads the configuration
// Terraform itself turned into the fixture plan. Every line here can be checked
// by opening the file, which is the point of generating it.
func TestScanFindsDeclarationsInGeneratedConfiguration(t *testing.T) {
	declarations := scan(fixtureSource(t, "generated", "main.tf"))

	if len(declarations) != 3 {
		t.Fatalf("found %d declarations, want 3: %v", len(declarations), declarations)
	}

	cases := []struct {
		name      string
		line      int
		attribute string
		at        int
	}{
		{"root", 11, "input", 12},
		{"tricky", 17, "input", 18},
		{"braces", 26, "input", 27},
	}
	for _, c := range cases {
		d := found(t, declarations, "resource", "terraform_data", c.name)
		if d.Line != c.line {
			t.Errorf("%s declared at line %d, want %d", c.name, d.Line, c.line)
		}
		if got := attributeLine(d, c.attribute); got != c.at {
			t.Errorf("%s attribute %s at line %d, want %d", c.name, c.attribute, got, c.at)
		}
	}
}

// TestScanIgnoresADeclarationInsideAHeredoc is the case that separates a lexer
// from a search. The fixture's "tricky" resource has a heredoc whose body reads
// like a resource block; a scanner that misses heredocs reports the decoy and
// shifts every line after it.
func TestScanIgnoresADeclarationInsideAHeredoc(t *testing.T) {
	declarations := scan(fixtureSource(t, "generated", "main.tf"))

	for _, d := range declarations {
		if d.Name == "decoy" {
			t.Fatalf("a declaration inside a heredoc was reported at line %d", d.Line)
		}
	}
	// The declaration after the heredoc is where the file says it is, which is
	// what proves the body was skipped rather than merely unmatched.
	if d := found(t, declarations, "resource", "terraform_data", "braces"); d.Line != 26 {
		t.Fatalf("the declaration after the heredoc is at line %d, want 26", d.Line)
	}
}

// TestScanIgnoresNonResourceBlocks covers the milestone's scope: lines are
// reported for resource and data declarations, and for nothing else.
func TestScanIgnoresNonResourceBlocks(t *testing.T) {
	declarations := scan(fixtureSource(t, "generated", "main.tf"))

	for _, d := range declarations {
		if d.Kind != "resource" && d.Kind != "data" {
			t.Fatalf("reported a %q block at line %d", d.Kind, d.Line)
		}
		if d.Type == "storage" || d.Type == "keyed" || d.Type == "tag" {
			t.Fatalf("a module call or variable was reported as a declaration: %v", d)
		}
	}
}

// TestScanFindsAttributesInShippedAwsConfiguration covers the attribute a
// finding actually rests on, and a nested one whose first segment is what an
// evidence path names.
func TestScanFindsAttributesInShippedAwsConfiguration(t *testing.T) {
	declarations := scan(fixtureSource(t, "aws", "main.tf"))

	bucket := found(t, declarations, "resource", "aws_s3_bucket", "assets")
	if bucket.Line != 6 {
		t.Errorf("bucket declared at line %d, want 6", bucket.Line)
	}
	if attributeLine(bucket, "tags") != 9 {
		t.Errorf("tags at line %d, want 9", attributeLine(bucket, "tags"))
	}
	// owner is written at depth two, inside tags. It is not an attribute of the
	// resource and must not be reported as one.
	if line, present := bucket.lineOf("owner"); present {
		t.Errorf("a nested attribute was reported as the resource's own, at line %d", line)
	}

	acl := found(t, declarations, "resource", "aws_s3_bucket_acl", "assets")
	if acl.Line != 23 || attributeLine(acl, "acl") != 25 {
		t.Errorf("acl block at line %d, acl attribute at line %d, want 23 and 25", acl.Line, attributeLine(acl, "acl"))
	}

	block := found(t, declarations, "resource", "aws_s3_bucket_public_access_block", "assets")
	for attribute, want := range map[string]int{
		"bucket":                  15,
		"block_public_acls":       17,
		"block_public_policy":     18,
		"ignore_public_acls":      19,
		"restrict_public_buckets": 20,
	} {
		if got := attributeLine(block, attribute); got != want {
			t.Errorf("%s at line %d, want %d", attribute, got, want)
		}
	}
}

// TestScanFailsClosed covers the whole safety argument. A file this scanner
// cannot lex to the end yields nothing at all: the positions it thought it saw
// before losing track are exactly the plausible-but-wrong lines the milestone
// refuses to report.
func TestScanFailsClosed(t *testing.T) {
	cases := map[string]string{
		"unterminated string": `resource "aws_s3_bucket" "a" {
  bucket = "never closed
}
`,
		"unterminated heredoc": `resource "aws_s3_bucket" "a" {
  policy = <<-EOT
    still going
`,
		"unterminated block comment": `resource "aws_s3_bucket" "a" {
  bucket = "a"
}
/* and then
`,
		"unclosed block": `resource "aws_s3_bucket" "a" {
  bucket = "a"
`,
		"one brace too many": `resource "aws_s3_bucket" "a" {
  bucket = "a"
}
}
`,
		"unterminated interpolation": `resource "aws_s3_bucket" "a" {
  bucket = "${join("
}
`,
		// A backslash before a newline. HCL has no line continuation in a
		// quoted template, and reading one as an escape consumes a newline
		// without counting it, so every line after it is reported one too low.
		"backslash before a newline": "{\"\\\n\"}resource \"aws_s3_bucket\" \"a\" {\n}\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if got := scan([]byte(source)); got != nil {
				t.Fatalf("a file that does not lex yielded %v", got)
			}
		})
	}
}

// TestScanReadsWhatTheGrammarAllows covers the forms a real configuration uses
// that a naive scan gets wrong. Each case names the declaration it must find and
// the line it is on.
func TestScanReadsWhatTheGrammarAllows(t *testing.T) {
	sources := map[string]string{
		"line comments": "# resource \"aws_s3_bucket\" \"decoy\" {\n// another\nresource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\"\n}\n",
		// line 3, bucket on 4
		"block comment holding a block": "/* resource \"aws_s3_bucket\" \"decoy\" {\n} */\nresource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\"\n}\n",
		"braces inside a string":        "resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"} {\"\n}\n",
		"escaped quote in a string":     "resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\\\"b\"\n}\n",
		"interpolation with braces":     "resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"${join(\"\", [\"{\", \"}\"])}\"\n}\n",
		"directive with braces":         "resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"%{ if true }x%{ endif }\"\n}\n",
		"heredoc with a closing brace":  "resource \"aws_s3_bucket\" \"a\" {\n  bucket = <<EOT\n}\nEOT\n}\n",
		"carriage returns":              "resource \"aws_s3_bucket\" \"a\" {\r\n  bucket = \"a\"\r\n}\r\n",
		"comment after an attribute":    "resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\" # trailing\n}\n",
		"nested block before it":        "resource \"aws_s3_bucket\" \"a\" {\n  lifecycle {\n    prevent_destroy = true\n  }\n  bucket = \"a\"\n}\n",
	}
	want := map[string]struct{ line, at int }{
		"line comments":                 {3, 4},
		"block comment holding a block": {3, 4},
		"braces inside a string":        {1, 2},
		"escaped quote in a string":     {1, 2},
		"interpolation with braces":     {1, 2},
		"directive with braces":         {1, 2},
		"heredoc with a closing brace":  {1, 2},
		"carriage returns":              {1, 2},
		"comment after an attribute":    {1, 2},
		"nested block before it":        {1, 5},
	}
	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			declarations := scan([]byte(source))
			d := found(t, declarations, "resource", "aws_s3_bucket", "a")
			expected := want[name]
			if d.Line != expected.line {
				t.Errorf("declared at line %d, want %d", d.Line, expected.line)
			}
			if got := attributeLine(d, "bucket"); got != expected.at {
				t.Errorf("bucket at line %d, want %d", got, expected.at)
			}
			for _, other := range declarations {
				if other.Name == "decoy" {
					t.Errorf("a commented-out declaration was reported at line %d", other.Line)
				}
			}
		})
	}
}

// TestScanReportsDataSourcesSeparately covers the distinction the plan makes and
// the locator depends on: a data source and a managed resource can share a type
// and a name, and they are two declarations.
func TestScanReportsDataSourcesSeparately(t *testing.T) {
	source := `data "aws_s3_bucket" "a" {
  bucket = "a"
}

resource "aws_s3_bucket" "a" {
  bucket = "a"
}
`
	declarations := scan([]byte(source))

	if d := found(t, declarations, "data", "aws_s3_bucket", "a"); d.Line != 1 {
		t.Errorf("data source at line %d, want 1", d.Line)
	}
	if d := found(t, declarations, "resource", "aws_s3_bucket", "a"); d.Line != 5 {
		t.Errorf("resource at line %d, want 5", d.Line)
	}
}

// TestScanKeepsBothOfTwoIdenticalDeclarations covers what must not be decided
// here. Terraform refuses a duplicate, but this build may be reading files that
// are not the ones the plan came from, and collapsing two declarations into one
// would report a line for something ambiguous. The scanner reports both and the
// locator refuses to choose.
func TestScanKeepsBothOfTwoIdenticalDeclarations(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "first"
}

resource "aws_s3_bucket" "a" {
  bucket = "second"
}
`
	declarations := scan([]byte(source))

	if len(declarations) != 2 {
		t.Fatalf("found %d declarations, want both: %v", len(declarations), declarations)
	}
	if declarations[0].Line != 1 || declarations[1].Line != 5 {
		t.Fatalf("lines = %d and %d, want 1 and 5", declarations[0].Line, declarations[1].Line)
	}
}

// TestScanRecordsTheFirstOfARepeatedAttribute covers a file Terraform would
// reject, read by a build that cannot assume these are the files the plan came
// from. The first is reported and the reading is stated rather than accidental.
func TestScanRecordsTheFirstOfARepeatedAttribute(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "first"
  bucket = "second"
}
`
	d := found(t, scan([]byte(source)), "resource", "aws_s3_bucket", "a")

	if attributeLine(d, "bucket") != 2 {
		t.Fatalf("bucket at line %d, want the first at 2", attributeLine(d, "bucket"))
	}
}

// TestScanIgnoresABlockLabelThatIsNotALabel covers the headers that are not
// declarations: too few labels, too many, or a label that is not a string.
func TestScanIgnoresMalformedHeaders(t *testing.T) {
	cases := map[string]string{
		"one label":          "resource \"aws_s3_bucket\" {\n  bucket = \"a\"\n}\n",
		"three labels":       "resource \"aws_s3_bucket\" \"a\" \"b\" {\n  bucket = \"a\"\n}\n",
		"identifier label":   "resource aws_s3_bucket \"a\" {\n  bucket = \"a\"\n}\n",
		"no labels":          "resource {\n  bucket = \"a\"\n}\n",
		"resource as a name": "locals {\n  resource = \"aws_s3_bucket\"\n}\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if got := scan([]byte(source)); len(got) != 0 {
				t.Fatalf("reported %v", got)
			}
		})
	}
}

// TestScanRefusesADeclarationInsideAnotherBlock covers scope. A resource block
// is written at the top level of a file; something that looks like one nested
// inside another block is not one, and reporting it would be a line for a
// declaration the plan cannot contain.
func TestScanRefusesADeclarationInsideAnotherBlock(t *testing.T) {
	source := `locals {
  x = 1
  resource "aws_s3_bucket" "a" {
    bucket = "a"
  }
}
`
	if got := scan([]byte(source)); len(got) != 0 {
		t.Fatalf("a nested declaration was reported: %v", got)
	}
}

// TestScanRefusesRunawayNesting covers the bound. Depth past what a
// configuration uses is refused rather than followed.
func TestScanRefusesRunawayNesting(t *testing.T) {
	source := "resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\"\n"
	for range maxBraceDepth + 1 {
		source += "  nested {\n"
	}
	for range maxBraceDepth + 1 {
		source += "  }\n"
	}
	source += "}\n"

	if got := scan([]byte(source)); got != nil {
		t.Fatalf("runaway nesting yielded %v", got)
	}
}

// TestScanHandlesAnEmptyFile covers the ordinary boundary: nothing found is not
// a failure.
func TestScanHandlesAnEmptyFile(t *testing.T) {
	if got := scan(nil); got != nil {
		t.Fatalf("an empty file yielded %v", got)
	}
	if got := scan([]byte("\n\n# just a comment\n")); got != nil {
		t.Fatalf("a file with no declarations yielded %v", got)
	}
}

// TestScanDoesNotResynchronizeOnALaterQuote covers what an unterminated string
// costs when the file goes on. A lexer that lets a string run past the end of
// its line finds its closing quote somewhere in a later declaration, and from
// there every position it reports is about text it has misread.
func TestScanDoesNotResynchronizeOnALaterQuote(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "unterminated
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`
	if got := scan([]byte(source)); got != nil {
		t.Fatalf("a file with an unterminated string yielded %v", got)
	}
}

// TestScanRefusesAValueThatSpansALine covers the quote that opens on one line
// and closes on the next. HCL does not allow it, and a lexer that does reads the
// text between as a value: everything after it is structure it has misread,
// including the braces that decide whether the file balances at all.
func TestScanRefusesAValueThatSpansALine(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "a"
}

description = "opens here
  and closes here"
`
	if got := scan([]byte(source)); got != nil {
		t.Fatalf("a value spanning a line yielded %v", got)
	}
}

// TestScanRefusesAFileThatStopsBalancing covers the declaration that closed
// cleanly before the file stopped making sense. It is not reported: this build
// cannot tell whether what follows changes what came before, and a location is
// a claim about a file it could not read.
func TestScanRefusesAFileThatStopsBalancing(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "a"
}

locals {
`
	if got := scan([]byte(source)); got != nil {
		t.Fatalf("a file that stops balancing yielded %v", got)
	}
}

// TestScanRefusesAStrayClosingBrace is the case a final balance check alone does
// not catch. One closing brace too early shifts every depth in the file, so a
// block nested inside another arrives at the top level and is read as a
// declaration -- and a second stray brace puts the count back to zero, leaving
// nothing for a balance check to notice.
func TestScanRefusesAStrayClosingBrace(t *testing.T) {
	source := `}
locals {
  resource "aws_s3_bucket" "a" {
    bucket = "a"
  }
}
{
`
	if got := scan([]byte(source)); got != nil {
		t.Fatalf("a nested declaration surfaced by a stray brace was reported: %v", got)
	}
}

// TestScanIgnoresASecondHeaderOnOneLine covers a file Terraform rejects. The
// scan reports nothing rather than the second header, because a position for a
// declaration in a file that does not parse is a position for nothing.
func TestScanIgnoresASecondHeaderOnOneLine(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" resource "aws_s3_bucket" "b" {
}
`
	if got := scan([]byte(source)); len(got) != 0 {
		t.Fatalf("reported %v", got)
	}
}

// TestScanIgnoresAnUnknownTwoLabelBlock covers the keyword check. Terraform has
// no other two-label block today, and a build that reported one as a declaration
// would be claiming a plan can contain it.
func TestScanIgnoresAnUnknownTwoLabelBlock(t *testing.T) {
	source := `mystery "aws_s3_bucket" "a" {
  bucket = "a"
}
`
	if got := scan([]byte(source)); len(got) != 0 {
		t.Fatalf("reported %v", got)
	}
}

// TestScanRecordsOnlyUnlabelledNestedBlocks covers which nested blocks are
// attributes. An unlabelled one -- grant, versioning, lifecycle -- is an
// attribute path a plan can name. A labelled one is not addressable that way, so
// recording it would offer a line for a path no evidence can carry.
func TestScanRecordsOnlyUnlabelledNestedBlocks(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  provisioner "local-exec" {
    command = "x"
  }

  versioning {
    enabled = true
  }

  bucket = "y"
}
`
	d := found(t, scan([]byte(source)), "resource", "aws_s3_bucket", "a")

	want := map[string]int{"versioning": 6, "bucket": 10}
	if len(d.Attributes) != len(want) {
		t.Fatalf("attributes = %v, want %v", d.Attributes, want)
	}
	for name, line := range want {
		if attributeLine(d, name) != line {
			t.Errorf("%s at line %d, want %d", name, attributeLine(d, name), line)
		}
	}
}

// TestScanDoesNotReadAComparisonAsAnArgument covers the two characters that
// separate an assignment from an equality. Reading "==" as "=" makes whatever is
// to its left look like an argument written at that line.
func TestScanDoesNotReadAComparisonAsAnArgument(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "a"
  mistake == 1
}
`
	d := found(t, scan([]byte(source)), "resource", "aws_s3_bucket", "a")

	if line, present := d.lineOf("mistake"); present {
		t.Fatalf("a comparison was recorded as an argument at line %d", line)
	}
}

// TestScanRefusesTwoArgumentsOnOneLine covers the other half of the same rule.
// HCL separates arguments by newline; two on one line is a file Terraform
// rejects, and inventing a position for the second is inventing a position.
func TestScanRefusesTwoArgumentsOnOneLine(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "a"  acl = "public-read"
}
`
	d := found(t, scan([]byte(source)), "resource", "aws_s3_bucket", "a")

	if line, present := d.lineOf("acl"); present {
		t.Fatalf("a second argument on one line was recorded at line %d", line)
	}
}

// TestScanRefusesAHeredocWithoutATag covers the marker this build cannot read.
// An empty tag terminates at the first blank line, which ends the body
// somewhere in the middle of a value and leaves the rest of the file being read
// as structure.
func TestScanRefusesAHeredocWithoutATag(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  policy = <<

}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`
	if got := scan([]byte(source)); got != nil {
		t.Fatalf("a heredoc with no tag yielded %v", got)
	}
}
