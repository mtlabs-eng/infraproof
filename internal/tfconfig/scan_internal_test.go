package tfconfig

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// read scans a file that must be readable, and fails if it is not. It keeps the
// two answers apart at every call site: a file with nothing in it is not a file
// this build could not read.
func read(t *testing.T, source []byte) []declaration {
	t.Helper()
	declarations, readable := scan(source)
	if !readable {
		t.Fatalf("this file should be readable and was refused:\n%s", source)
	}
	return declarations
}

// refused asserts that a file could not be read at all, which is the safe answer
// and the one every position in it depends on not being given.
func refused(t *testing.T, source []byte) {
	t.Helper()
	declarations, readable := scan(source)
	if readable {
		t.Fatalf("this file should be refused and was read as %v:\n%s", declarations, source)
	}
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
	declarations := read(t, fixtureSource(t, "generated", "main.tf"))

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
	declarations := read(t, fixtureSource(t, "generated", "main.tf"))

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
	declarations := read(t, fixtureSource(t, "generated", "main.tf"))

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
	declarations := read(t, fixtureSource(t, "aws", "main.tf"))

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
			refused(t, []byte(source))
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
			declarations := read(t, []byte(source))
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
	declarations := read(t, []byte(source))

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
	declarations := read(t, []byte(source))

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
	d := found(t, read(t, []byte(source)), "resource", "aws_s3_bucket", "a")

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
			if got := read(t, []byte(source)); len(got) != 0 {
				t.Fatalf("reported %v", got)
			}
		})
	}
}

// TestScanIgnoresAHeaderSpreadOverLines covers where a header ends. HCL ends one
// at a newline, so a keyword on one line and its labels on the next is a file
// Terraform refuses, and a position claimed in it is a position in a file nothing
// could have planned.
func TestScanIgnoresAHeaderSpreadOverLines(t *testing.T) {
	cases := map[string]string{
		"labels on the next line": "resource\n\"aws_s3_bucket\" \"a\" {\n  bucket = \"a\"\n}\n",
		"second label below":      "resource \"aws_s3_bucket\"\n\"a\" {\n  bucket = \"a\"\n}\n",
		"brace below":             "resource \"aws_s3_bucket\" \"a\"\n{\n  bucket = \"a\"\n}\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if got := read(t, []byte(source)); len(got) != 0 {
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
	if got := read(t, []byte(source)); len(got) != 0 {
		t.Fatalf("reported %v", got)
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

	refused(t, []byte(source))
}

// TestScanRefusesAFileWithTooManyTokens covers the other bound on one file, which
// is reachable well inside the 512 KiB this build reads: three hundred thousand
// commas is a quarter of a megabyte. It was argued for in a comment and held by
// nothing until independent review mutated it away and the suite stayed green.
func TestScanRefusesAFileWithTooManyTokens(t *testing.T) {
	source := "resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\"\n}\n" +
		strings.Repeat(",", maxTokens+1)

	refused(t, []byte(source))
}

// TestScanRefusesRunawayTemplateNesting covers the bound on a quoted template.
// An interpolation holds an expression, which holds strings, which hold
// interpolations, and the nesting is followed rather than guessed at -- so it
// needs a floor, and seventy levels is past any real configuration.
func TestScanRefusesRunawayTemplateNesting(t *testing.T) {
	source := "resource \"aws_s3_bucket\" \"a\" {\n  bucket = " +
		strings.Repeat("\"${", maxBraceDepth+2) + "x" +
		strings.Repeat("}\"", maxBraceDepth+2) + "\n}\n"

	refused(t, []byte(source))
}

// TestScanRefusesALoneCarriageReturn covers the byte that is a line ending only
// in company. Terraform refuses one on its own, and reading it as whitespace put
// a name and its assignment on one line while the file has them on two.
func TestScanRefusesALoneCarriageReturn(t *testing.T) {
	cases := map[string]string{
		"between a name and its assignment": "resource \"a\" \"b\" {\n  x\r= 1\n}\n",
		"at the end of a line":              "resource \"a\" \"b\" {\r  x = 1\r}\r",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			refused(t, []byte(source))
		})
	}
}

// TestScanReadsAFileWithNothingInIt covers the boundary this scanner used to
// blur. A file with no declarations was read completely and has nothing to offer,
// which is not the same answer as a file that could not be read -- and for a
// while both were spelled the same way, so this package could not have said
// whether it had refused the whole repository.
func TestScanReadsAFileWithNothingInIt(t *testing.T) {
	cases := map[string][]byte{
		"empty":           nil,
		"a comment":       []byte("\n\n# just a comment\n"),
		"only a module":   []byte("module \"storage\" {\n  source = \"./modules/storage\"\n}\n"),
		"only a variable": []byte("variable \"tag\" {\n  type = string\n}\n"),
		"only whitespace": []byte("\n\t \n"),
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			declarations, readable := scan(source)
			if !readable {
				t.Fatal("a file with nothing in it was refused")
			}
			if len(declarations) != 0 {
				t.Fatalf("reported %v", declarations)
			}
		})
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
	refused(t, []byte(source))
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
	refused(t, []byte(source))
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
	refused(t, []byte(source))
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
	refused(t, []byte(source))
}

// TestScanIgnoresASecondHeaderOnOneLine covers a file Terraform rejects. The
// scan reports nothing rather than the second header, because a position for a
// declaration in a file that does not parse is a position for nothing.
func TestScanIgnoresASecondHeaderOnOneLine(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" resource "aws_s3_bucket" "b" {
}
`
	if got := read(t, []byte(source)); len(got) != 0 {
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
	if got := read(t, []byte(source)); len(got) != 0 {
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
	d := found(t, read(t, []byte(source)), "resource", "aws_s3_bucket", "a")

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
	d := found(t, read(t, []byte(source)), "resource", "aws_s3_bucket", "a")

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
	d := found(t, read(t, []byte(source)), "resource", "aws_s3_bucket", "a")

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
	refused(t, []byte(source))
}

// TestScanRefusesAHeredocTagItCannotRead is the defect independent review found,
// and the only one in this milestone that produced a wrong line on a file
// Terraform itself accepts.
//
// An HCL identifier is Unicode; this lexer's is ASCII. A tag with a letter
// outside ASCII therefore stops early, and the prefix it holds is a proper prefix
// of the real terminator -- so the heredoc ends at the first body line equal to
// the prefix and the rest of the body is read as structure. In the committed
// fixture that put `input` four lines from where it is written, with the
// resource's own identity checking out, which is precisely the failure the rule
// "a location is reported only when the declaration found at it matches" cannot
// catch: the declaration did match.
//
// The fixture is a file Terraform validates, and its plan.json was produced by
// Terraform from those exact bytes, so "the files may have changed" does not
// apply to it.
func TestScanRefusesAHeredocTagItCannotRead(t *testing.T) {
	refused(t, fixtureSource(t, "heredoc-tag", "main.tf"))

	// And the specific wrong answer, in case a later change makes the file
	// readable again by some other route: input is written on line 6, and line 4
	// is inside the heredoc.
	declarations, _ := scan(fixtureSource(t, "heredoc-tag", "main.tf"))
	for _, d := range declarations {
		if line, written := d.lineOf("input"); written && line != 6 {
			t.Fatalf("input located at line %d, which is inside a string", line)
		}
	}
}

// TestScanRefusesATruncatedTagWhereverTheLetterIs covers the same rule for the
// forms the fixture does not have.
func TestScanRefusesATruncatedTagWhereverTheLetterIs(t *testing.T) {
	cases := map[string]string{
		"letter after the tag":    "resource \"a\" \"b\" {\n  x = <<EOTÖ\nEOT\n}\nEOTÖ\n",
		"letter inside the tag":   "resource \"a\" \"b\" {\n  x = <<EÖT\nEÖT\n}\n",
		"letter starting the tag": "resource \"a\" \"b\" {\n  x = <<Önly\nÖnly\n}\n",
		"dedented form":           "resource \"a\" \"b\" {\n  x = <<-EOTÖ\n  EOT\n}\n  EOTÖ\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			refused(t, []byte(source))
		})
	}
}

// TestScanCountsLinesInsideAnInterpolation covers the one place left where this
// lexer consumes a newline, which is the same shape as the defect the fuzzer found
// in a quoted string: a newline swallowed without being counted puts every line
// after it one too low. Independent review removed that line++ and the whole
// suite stayed green, because no fixture had a multi-line interpolation followed
// by anything whose position is asserted.
func TestScanCountsLinesInsideAnInterpolation(t *testing.T) {
	source := `resource "aws_s3_bucket" "a" {
  bucket = "${join(
    "",
    ["a", "b"]
  )}"
  acl = "private"
}
`
	d := found(t, read(t, []byte(source)), "resource", "aws_s3_bucket", "a")

	if line, _ := d.lineOf("acl"); line != 6 {
		t.Fatalf("acl at line %d, want 6: a newline inside the interpolation was not counted", line)
	}

	// And the same again, so that one uncounted newline cannot be absorbed by an
	// off-by-one somewhere else.
	twice := source[:len(source)-1] + `
resource "aws_s3_bucket" "b" {
  bucket = "${join(
    "",
    ["c"]
  )}"
  acl = "private"
}
`
	second := found(t, read(t, []byte(twice)), "resource", "aws_s3_bucket", "b")
	if second.Line != 8 {
		t.Fatalf("the second declaration is at line %d, want 8", second.Line)
	}
	if line, _ := second.lineOf("acl"); line != 13 {
		t.Fatalf("the second acl is at line %d, want 13", line)
	}
}

// TestScanReadsADirectiveHoldingAString covers the second template sigil, which
// nothing held: ignoring %{ altogether left every existing case reading the same.
//
// Separating the two takes a brace inside a string inside a directive's
// condition, which is what this is. Read as a directive, the brace is inside a
// nested string and says nothing about the file's structure. Read as ordinary
// text, the quotes pair up differently, the brace is exposed as a real one, and
// the file stops balancing -- so the whole scan is refused and nothing in it is
// located. The condition is a bool, so Terraform accepts the file; several
// shorter candidates do not, which is why this one is shaped the way it is.
func TestScanReadsADirectiveHoldingAString(t *testing.T) {
	source := "resource \"aws_s3_bucket\" \"a\" {\n" +
		"  bucket = \"%{ if length(\"{\") > 0 }y%{ endif }\"\n" +
		"  acl    = \"private\"\n}\n"

	d := found(t, read(t, []byte(source)), "resource", "aws_s3_bucket", "a")

	if line, _ := d.lineOf("acl"); line != 3 {
		t.Fatalf("acl at line %d, want 3", line)
	}
}

// TestScanTreatsASlashSlashCommentAsAComment covers what the existing case could
// not: its comment held no brace, so disabling // comments altogether changed
// nothing. A commented-out block header carries one.
func TestScanTreatsASlashSlashCommentAsAComment(t *testing.T) {
	source := "// resource \"aws_s3_bucket\" \"decoy\" {\n" +
		"resource \"aws_s3_bucket\" \"a\" {\n  bucket = \"a\"\n}\n"

	declarations := read(t, []byte(source))

	d := found(t, declarations, "resource", "aws_s3_bucket", "a")
	if d.Line != 2 {
		t.Fatalf("declared at line %d, want 2", d.Line)
	}
	if len(declarations) != 1 {
		t.Fatalf("a commented-out header was read: %v", declarations)
	}
}

// TestScanAcceptsAHeredocTerminatorWithTrailingWhitespace covers both trims in
// trimmed, each of which Terraform accepts and neither of which any fixture had:
// a terminator followed by spaces, and one followed by a carriage return.
func TestScanAcceptsAHeredocTerminatorWithTrailingWhitespace(t *testing.T) {
	cases := map[string]string{
		"trailing spaces":       "resource \"a\" \"b\" {\n  x = <<EOT\n  body\nEOT   \n  y = 1\n}\n",
		"carriage return":       "resource \"a\" \"b\" {\n  x = <<EOT\n  body\nEOT\r\n  y = 1\n}\n",
		"tab":                   "resource \"a\" \"b\" {\n  x = <<EOT\n  body\nEOT\t\n  y = 1\n}\n",
		"indented and dedented": "resource \"a\" \"b\" {\n  x = <<-EOT\n    body\n  EOT  \n  y = 1\n}\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			d := found(t, read(t, []byte(source)), "resource", "a", "b")
			if line, written := d.lineOf("y"); !written || line != 5 {
				t.Fatalf("y at line %d (written %v), want 5: the terminator was not recognised", line, written)
			}
		})
	}
}

// TestScanDoesNotRecordAnArgumentSharingALineWithABrace covers what a name is:
// the first token on its line. Terraform refuses a file that writes an argument
// on the same line as the brace that opens the block, so a position claimed
// inside one is a position inside a file nothing could have planned.
//
// The first argument of a block, written on its own line after the brace, is
// still an argument -- that is the ordinary case, and the line comparison covers
// it.
func TestScanDoesNotRecordAnArgumentSharingALineWithABrace(t *testing.T) {
	source := "resource \"a\" \"b\" { first = 1\n  versioning { enabled = true } second = 2\n  third = 3\n}\n"

	d := found(t, read(t, []byte(source)), "resource", "a", "b")

	for _, name := range []string{"first", "second"} {
		if line, written := d.lineOf(name); written {
			t.Errorf("%s shares a line with a brace and was recorded at line %d", name, line)
		}
	}
	if line, written := d.lineOf("third"); !written || line != 3 {
		t.Fatalf("third at line %d (written %v), want 3", line, written)
	}
}

// TestScanReadsAComparisonAgainstALessThan covers the byte a heredoc shares with
// an operator. HCL compares with "<", and treating a lone one as a heredoc marker
// makes the tag empty, which refuses the whole file.
func TestScanReadsAComparisonAgainstALessThan(t *testing.T) {
	source := "resource \"a\" \"b\" {\n  count = var.x < var.y ? 1 : 0\n  acl   = \"private\"\n}\n"

	d := found(t, read(t, []byte(source)), "resource", "a", "b")

	if line, written := d.lineOf("acl"); !written || line != 3 {
		t.Fatalf("acl at line %d (written %v), want 3", line, written)
	}
}

// TestScanReadsConstructsTerraformAccepts covers six forms independent review
// found that Terraform validates and this build refused outright. None of them
// produced a wrong line -- the refusal is the safe direction -- but the cost is
// the limitation the milestone names: the bundle is not told a scan was refused,
// so a reader cannot tell "not written here" from "not read", and the blast
// radius was the whole file rather than the one argument.
//
// Each source here was checked against terraform validate on v1.14.0.
func TestScanReadsConstructsTerraformAccepts(t *testing.T) {
	cases := map[string]string{
		"escaped interpolation sigil": "resource \"a\" \"b\" {\n  x = \"$${\"\n  y = 1\n}\n",
		"escaped directive sigil":     "resource \"a\" \"b\" {\n  x = \"%%{\"\n  y = 1\n}\n",
		"escaped sigil in an object":  "resource \"a\" \"b\" {\n  x = { k = \"$${\" }\n  y = 1\n}\n",
		// A raw quote inside the comment, not an escaped one: a comment is lexed
		// before string rules, so the quote is text and must not open a string.
		"block comment in an interpolation": "resource \"a\" \"b\" {\n  x = \"${ 1 /* \" */ }\"\n  y = 1\n}\n",
		"hash comment in an interpolation":  "resource \"a\" \"b\" {\n  x = \"${ 1 # }\n}\"\n  y = 1\n}\n",
		"slash comment in an interpolation": "resource \"a\" \"b\" {\n  x = \"${ 1 // }\n}\"\n  y = 1\n}\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			declarations := read(t, []byte(source))
			if declarations == nil {
				t.Fatal("refused a file Terraform accepts, so nothing in it can be located")
			}
			d := found(t, declarations, "resource", "a", "b")
			if line, written := d.lineOf("y"); !written || line < 3 {
				t.Fatalf("y at line %d (written %v), want the line after the template", line, written)
			}
		})
	}
}

// TestScanSkipsAByteOrderMark covers a file Terraform reads and this build used
// to lose the first declaration of. The mark's three bytes were the token before
// the first keyword, so startsStatement decided the keyword did not begin a
// statement -- and the declaration was invisible with nothing said about it.
func TestScanSkipsAByteOrderMark(t *testing.T) {
	source := "\ufeffresource \"terraform_data\" \"first\" {\n  input = \"a\"\n}\n" +
		"\nresource \"terraform_data\" \"second\" {\n  input = \"b\"\n}\n"

	declarations := read(t, []byte(source))

	if len(declarations) != 2 {
		t.Fatalf("found %d declarations, want both: %v", len(declarations), declarations)
	}
	if d := found(t, declarations, "resource", "terraform_data", "first"); d.Line != 1 {
		t.Fatalf("the first declaration is at line %d, want 1", d.Line)
	}
	if d := found(t, declarations, "resource", "terraform_data", "second"); d.Line != 5 {
		t.Fatalf("the second declaration is at line %d, want 5", d.Line)
	}
}

// TestScanRefusesContentAfterAHeredocMarker covers a line Terraform rejects and
// this build swallowed: whatever follows the marker was read as part of the
// heredoc, so a file that is an error to Terraform was read as configuration.
func TestScanRefusesContentAfterAHeredocMarker(t *testing.T) {
	source := "resource \"a\" \"b\" {\n  x = <<EOT trailing\n  body\nEOT\n}\n"

	refused(t, []byte(source))
}

// TestScanRefusesATagThatIsNotAnIdentifier covers the first byte of a heredoc
// tag. An identifier does not start with a digit or a dash, and Terraform
// refuses both forms.
func TestScanRefusesATagThatIsNotAnIdentifier(t *testing.T) {
	for _, source := range []string{
		"resource \"a\" \"b\" {\n  x = <<9EOT\n  body\n9EOT\n}\n",
		"resource \"a\" \"b\" {\n  x = <<--EOT\n  body\n-EOT\n}\n",
	} {
		refused(t, []byte(source))
	}
}

// TestScanDoesNotMatchANameAgainstADistantBrace covers the token an argument is
// recognised by. It is the next token on the same line, not simply the next
// token: a heredoc or a run of blank lines in between would otherwise let a name
// claim a position for a brace somewhere else entirely.
func TestScanDoesNotMatchANameAgainstADistantBrace(t *testing.T) {
	source := "resource \"a\" \"b\" {\n  far\n\n  {\n    x = 1\n  }\n}\n"

	d := found(t, read(t, []byte(source)), "resource", "a", "b")

	if line, written := d.lineOf("far"); written {
		t.Fatalf("a name was matched against a brace two lines away, at line %d", line)
	}
}

// TestEveryConfigurationThisRepositoryShipsIsRead is the canary for the failure
// no other test here can see: a file Terraform accepts that this build refuses.
//
// Every refusal in this scanner is the safe direction and is tested. Refusing too
// much is not tested anywhere by construction -- FuzzScan returns the moment scan
// yields nil, because there is nothing to check the lines of, so tightening the
// lexer until it reads nothing at all would leave the suite green. The cost is
// silent: a reader who expected a line and sees none cannot tell "not written
// here" from "not read".
//
// So every .tf file this repository ships is scanned, and must produce something.
// They are real configuration, written to be read: the generated fixture was run
// through Terraform, the aws one matches a shipped plan, and examples/infra is
// what the README tells a reader to point at.
func TestEveryConfigurationThisRepositoryShipsIsRead(t *testing.T) {
	// The one file that must not be read, and why. It is a deliberate refusal:
	// its heredoc tag holds a letter outside ASCII, which this lexer cannot read
	// without truncating it.
	deliberatelyRefused := map[string]string{
		filepath.Join("testdata", "heredoc-tag", "main.tf"): "its heredoc tag holds a letter outside ASCII",
	}

	var scanned, skipped int
	for _, root := range []string{"testdata", filepath.Join("..", "..", "examples")} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || filepath.Ext(path) != ".tf" {
				return err
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			declarations, readable := scan(source)
			if reason, deliberate := deliberatelyRefused[path]; deliberate {
				if readable {
					t.Errorf("%s is meant to be refused because %s, and was read as %v",
						path, reason, declarations)
				}
				skipped++
				return nil
			}
			if !readable {
				t.Errorf("%s was refused, so nothing in it can be located", path)
				return nil
			}
			scanned++
			return nil
		})
		if err != nil {
			t.Fatalf("walking %s: %v", root, err)
		}
	}

	if scanned < 5 {
		t.Fatalf("only %d configuration files were found, which is too few to be the set", scanned)
	}
	if skipped != len(deliberatelyRefused) {
		t.Fatalf("the deliberate refusals were not all found: %d of %d", skipped, len(deliberatelyRefused))
	}
}
