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
// splitting the input on newlines, and the text there must contain the word the
// position is about. A line count that drifts by one -- through a heredoc, a
// block comment, a string holding a newline -- moves the reported line off the
// text it claims, and that is exactly the defect this milestone cannot ship.
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
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, source []byte) {
		declarations := scan(source)
		if declarations == nil {
			return
		}

		lines := bytes.Split(source, []byte("\n"))
		at := func(line int) string {
			if line < 1 || line > len(lines) {
				t.Fatalf("line %d is outside a file of %d lines", line, len(lines))
			}
			return string(lines[line-1])
		}

		for _, d := range declarations {
			if d.Kind != "resource" && d.Kind != "data" {
				t.Fatalf("reported kind %q", d.Kind)
			}
			if text := at(d.Line); !strings.Contains(text, d.Kind) {
				t.Fatalf("declaration reported at line %d, which does not hold %q", d.Line, d.Kind)
			}
			for name, line := range d.Attributes {
				if line < d.Line {
					t.Fatalf("attribute %q at line %d, before its declaration at %d", name, line, d.Line)
				}
				if text := at(line); !strings.Contains(text, name) {
					t.Fatalf("attribute %q reported at line %d, which does not hold it", name, line)
				}
			}
		}

		// Two scans of one file must agree, or a report is not reproducible.
		if again := scan(source); len(again) != len(declarations) {
			t.Fatalf("scanning twice found %d then %d declarations", len(declarations), len(again))
		}
	})
}
