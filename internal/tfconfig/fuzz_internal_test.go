package tfconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzScan checks what a scanner can be checked for without writing a second
// scanner to compare it against.
//
// The oracle is independent of the lexer: a reported line is looked up by
// splitting the input on newlines, and what is written there has to begin with
// the declaration or the argument the position claims. A line count that drifts
// by one -- through a heredoc, a block comment, a string holding a newline --
// moves the reported line off the text it claims, and that is exactly the defect
// this milestone cannot ship.
//
// What it cannot catch, and no single-implementation oracle can: a heredoc body
// read as configuration is textually indistinguishable from configuration. The
// defect independent review found that way -- a truncated heredoc tag -- reports
// a line that really does read "input = ...", because it is a line of a string
// that looks like a line of HCL. That class is held by refusing the file, by the
// committed fixture Terraform itself planned, and in the end only by a second
// parser.
func FuzzScan(f *testing.F) {
	for _, name := range []string{
		filepath.Join("testdata", "generated", "main.tf"),
		filepath.Join("testdata", "generated", "modules", "storage", "main.tf"),
		filepath.Join("testdata", "aws", "main.tf"),
	} {
		if raw, err := os.ReadFile(name); err == nil {
			f.Add(raw)
		}
	}
	// One seed per hazard the scan has to survive, so the corpus starts with the
	// shapes a random mutation would take a long time to build.
	seeds := []string{
		"",
		"resource \"a\" \"b\" {\n}\n",
		"data \"a\" \"b\" {\n  x = 1\n}\n",
		"resource \"a\" \"b\" {\n  x = <<-EOT\n    resource \"c\" \"d\" {\n  EOT\n}\n",
		"resource \"a\" \"b\" {\n  x = \"${\"}\"}\"\n}\n",
		"resource \"a\" \"b\" {\n  x = \"%{ if true }}%{ endif }\"\n}\n",
		"/* resource \"a\" \"b\" {\n*/\nresource \"c\" \"d\" {\n}\n",
		"# \nresource \"a\" \"b\" {\n}\n",
		"resource \"a\" \"b\" {\n  x = \"unterminated\n}\n",
		"resource \"a\" \"b\" {\n",
		"}\n{\n",
		"resource \"a\" \"b\" {\n  x = 1 == 2\n}\n",
		"<<\n",
		"\"\\\n",
		"resource \"a\" \"b\" {\r\n  x = 1\r\n}\r\n",
		// The one the fuzzer found: a backslash before a newline swallowed the
		// newline without counting it, and the declaration after it was reported
		// a line early. A seed only the corpus holds is a seed the next reader
		// loses.
		"{\"\\\n\"}resource\"\"\"\"{}",
		// The heredoc tag review found: ASCII-only tag reading truncates it, so
		// the body ends early and is lexed as structure.
		"resource \"a\" \"b\" {\n  x = <<EOTÖ\nEOT\ninput = \"inside a string\"\nEOTÖ\n  input = \"real\"\n}\n",
		"resource \"a\" \"b\" {\n  x = \"$${\"\n}\n",
		"resource \"a\" \"b\" {\n  x = \"${ 1 /* \" */ }\"\n}\n",
		"\ufeffresource \"a\" \"b\" {\n}\n",
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, source []byte) {
		declarations, readable := scan(source)
		if !readable {
			// Nothing to check the lines of. That a file Terraform accepts is not
			// refused here is a different property, and a test asserts it over
			// every configuration this repository ships.
			return
		}

		lines := bytes.Split(source, []byte("\n"))
		at := func(line int) string {
			if line < 1 || line > len(lines) {
				t.Fatalf("line %d is outside a file of %d lines", line, len(lines))
			}
			// A byte order mark is not content, for the oracle for the same
			// reason as for the lexer: it is a mark about the file's encoding,
			// and leaving it in front of the first line makes the first
			// declaration in every such file look misreported.
			return strings.TrimPrefix(string(lines[line-1]), "\ufeff")
		}

		for _, d := range declarations {
			if d.Kind != "resource" && d.Kind != "data" {
				t.Fatalf("reported kind %q", d.Kind)
			}
			// A word that is used, not a word that merely appears. "contains"
			// was the first version of this oracle and accepts a line that
			// mentions the word anywhere, which is most lines of a
			// configuration.
			//
			// Anchoring it to the start of the line was the second version, and
			// the fuzzer refuted it twice: a comment may precede a block header
			// on its line, and a block comment may end on it. Teaching the
			// oracle where comments start and end would be writing this lexer a
			// second time, in the one place that is supposed to disagree with
			// it. So what is checked is use: a declaration's keyword is followed
			// by a quoted label, and an argument's name by an assignment or a
			// block.
			if !usedAs(at(d.Line), d.Kind, `"`) {
				t.Fatalf("declaration reported at line %d, which does not use %q: %q", d.Line, d.Kind, at(d.Line))
			}
			for _, a := range d.Attributes {
				if a.line < d.Line {
					t.Fatalf("attribute %q at line %d, before its declaration at %d", a.name, a.line, d.Line)
				}
				if !usedAs(at(a.line), a.name, "=", "{") {
					t.Fatalf("attribute %q reported at line %d, where nothing is assigned: %q", a.name, a.line, at(a.line))
				}
			}
		}

		// Two scans of one file must agree, or a report is not reproducible.
		if again, _ := scan(source); len(again) != len(declarations) {
			t.Fatalf("scanning twice found %d then %d declarations", len(declarations), len(again))
		}
	})
}

// afterGap skips what HCL allows between two tokens on one line: horizontal
// whitespace and complete block comments. Terraform accepts
// `resource/**/"a"/**/"b" {`, so an oracle that insists on a quote immediately
// after the keyword refuses a file this build is right about.
//
// This is a second reading of the grammar, which is what an oracle is for. The
// production lexer must not carry one; this file exists to disagree with it.
func afterGap(text string) string {
	for {
		text = strings.TrimLeft(text, " \t")
		if !strings.HasPrefix(text, "/*") {
			return text
		}
		end := strings.Index(text[2:], "*/")
		if end < 0 {
			return text
		}
		text = text[2+end+2:]
	}
}

// usedAs reports whether text uses word as a name followed by one of the given
// openers, rather than merely containing the letters somewhere.
//
// A name is a whole word: the character before it cannot continue an identifier,
// or "input" would be found inside "no_input". "=" does not match "==", which is
// a comparison and not an assignment.
func usedAs(text, word string, openers ...string) bool {
	for offset := 0; ; {
		at := strings.Index(text[offset:], word)
		if at < 0 {
			return false
		}
		at += offset
		offset = at + len(word)

		if at > 0 && identPart(text[at-1]) {
			continue
		}
		rest := afterGap(text[offset:])
		for _, opener := range openers {
			if !strings.HasPrefix(rest, opener) {
				continue
			}
			if opener == "=" && strings.HasPrefix(rest, "==") {
				continue
			}
			return true
		}
	}
}
