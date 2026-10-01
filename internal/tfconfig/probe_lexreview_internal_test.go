package tfconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLexReviewProbe(t *testing.T) {
	dir := os.Getenv("PROBE_DIR")
	if dir == "" {
		t.Skip("no PROBE_DIR")
	}
	names, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(raw), "\n")
		at := func(n int) string {
			if n < 1 || n > len(lines) {
				return fmt.Sprintf("<<OUT OF RANGE, file has %d lines>>", len(lines))
			}
			return lines[n-1]
		}
		ds := scan(raw)
		fmt.Printf("\n### %s  (%d declarations)\n", filepath.Base(name), len(ds))
		if ds == nil {
			fmt.Printf("   REFUSED (nil)\n")
			continue
		}
		for _, d := range ds {
			fmt.Printf("   %s %q %q at line %d -> %q\n", d.Kind, d.Type, d.Name, d.Line, at(d.Line))
			keys := make([]string, 0, len(d.Attributes))
			for k := range d.Attributes {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Printf("       attr %q at line %d -> %q\n", k, d.Attributes[k], at(d.Attributes[k]))
			}
		}
	}
}

// FuzzLexReviewStrict is the oracle FuzzScan does not have. A reported line must
// actually hold the declaration or the argument: the text from the reported
// position onward has to parse, by an independent regexp, as the very header or
// argument scan claims is there. A drift of one line moves the position off the
// text and the match fails.
func FuzzLexReviewStrict(f *testing.F) {
	for _, name := range []string{
		filepath.Join("testdata", "generated", "main.tf"),
		filepath.Join("testdata", "generated", "modules", "storage", "main.tf"),
		filepath.Join("testdata", "aws", "main.tf"),
	} {
		if raw, err := os.ReadFile(name); err == nil {
			f.Add(raw)
		}
	}
	for _, seed := range []string{
		"",
		"resource \"a\" \"b\" {\n}\n",
		"data \"a\" \"b\" {\n  x = 1\n}\n",
		"resource \"a\" \"b\" {\n  x = <<-EOT\n    resource \"c\" \"d\" {\n  EOT\n}\n",
		"resource \"a\" \"b\" {\n  x = \"${\"}\"}\"\n}\n",
		"resource \"a\" \"b\" {\n  x = \"$${\" == \"}\" ? \"p\" : \"q\"\n}\n",
		"resource \"a\" \"b\" {\n  x = \"%%{\"\n}\n",
		"resource \"a\" \"b\" {\n  x = \"${ 1 /* \" */ }\"\n}\n",
		"resource \"a\" \"b\" {\n  x = \"${ <<EOT\n{\nEOT\n }\"\n}\n",
		"\xef\xbb\xbfresource \"a\" \"b\" {\n}\n",
		"resource \"a\" \"b\" {\n  x = <<EOT\nEOT\t\n}\nresource \"a\" \"c\" {\n  y = {\n}\nEOT\n}\n",
		"resource \"a\" \"b\" { x = 1 }\n",
		"resource \"a\" \"b\" {\n  x = \"a\\\\\"\n}\n",
		"resource\"\"\n\"\"{}",
		"resource\"\"\"\"{A\n{}0}",
		"resource\"\"\"\"{\rA=}",
		"resource#\n\"\"\"\"{}",
		"{\"\\\n\"}resource\"\"\"\"{}",
		"resource \"a\" \"b\" {\n  x = { k = \"$${\" }\n  y = { k = \"}\" }\n  z = 1\n}\n",
		"resource \"a\" \"b\" {\r\n  x = <<EOT\r\nbody\r\nEOT\r\n}\r\n",
	} {
		f.Add([]byte(seed))
	}

	// sep is any run of whitespace and comments: a header or an argument may
	// legally have either between its tokens, and the oracle must not fail on
	// the layout.
	const sep = `(?:\s|#[^\n]*|//[^\n]*|/\*(?:[^*]|\*+[^*/])*\*+/)*`

	f.Fuzz(func(t *testing.T, source []byte) {
		if !utf8.Valid(source) {
			// HCL is UTF-8; the oracle builds patterns out of the text.
			return
		}
		declarations := scan(source)
		if declarations == nil {
			return
		}
		lines := strings.Split(string(source), "\n")
		from := func(n int) (string, bool) {
			if n < 1 || n > len(lines) {
				return "", false
			}
			return strings.Join(lines[n-1:], "\n"), true
		}
		statementStart := func(text string, at int) bool {
			for i := at - 1; i >= 0; i-- {
				switch text[i] {
				case ' ', '\t', '\r':
				case '{', '}', '\n':
					return true
				default:
					return false
				}
			}
			return true
		}
		for _, d := range declarations {
			text, inRange := from(d.Line)
			if !inRange {
				t.Fatalf("declaration %v at line %d, outside a file of %d lines", d, d.Line, len(lines))
			}
			header := regexp.MustCompile(`^` + regexp.QuoteMeta(d.Kind) + sep + `"` + regexp.QuoteMeta(d.Type) + `"` + sep + `"` + regexp.QuoteMeta(d.Name) + `"` + sep + `\{`)
			matched := false
			for _, at := range regexp.MustCompile(regexp.QuoteMeta(d.Kind)).FindAllStringIndex(text, -1) {
				if at[0] > len(lines[d.Line-1]) {
					break
				}
				if statementStart(text, at[0]) && header.MatchString(text[at[0]:]) {
					matched = true
				}
			}
			if !matched {
				t.Fatalf("declaration %s %q %q reported at line %d, which holds %q", d.Kind, d.Type, d.Name, d.Line, lines[d.Line-1])
			}
			for name, line := range d.Attributes {
				text, inRange := from(line)
				if !inRange {
					t.Fatalf("attribute %q at line %d, outside a file of %d lines", name, line, len(lines))
				}
				argument := regexp.MustCompile(`^` + regexp.QuoteMeta(name) + sep + `(=[^=]|=$|\{)`)
				matched := false
				for _, at := range regexp.MustCompile(regexp.QuoteMeta(name)).FindAllStringIndex(text, -1) {
					if at[0] > len(lines[line-1]) {
						break
					}
					if statementStart(text, at[0]) && argument.MatchString(text[at[0]:]) {
						matched = true
					}
				}
				if !matched {
					t.Fatalf("attribute %q of %s %q %q reported at line %d, which holds %q", name, d.Kind, d.Type, d.Name, line, lines[line-1])
				}
			}
		}
	})
}
