package render_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/render"
)

// withoutLocations returns the contract bundle as a run with no configuration
// directory produces it.
func withoutLocations() evidence.Bundle {
	bundle := contractBundle()
	bundle.Findings[0].Resource.Location = nil
	for i := range bundle.Findings[0].Evidence {
		bundle.Findings[0].Evidence[i].Location = nil
	}
	return bundle
}

// withLocations returns the contract bundle with a location on its finding, on
// its evidence, and on an unknown's evidence.
func withLocations() evidence.Bundle {
	bundle := contractBundle()
	bundle.Findings[0].Resource.Location = &evidence.Location{File: "main.tf", Line: 6}
	bundle.Findings[0].Evidence[0].Location = &evidence.Location{File: "modules/storage/main.tf", Line: 25}
	bundle.Unknowns[0].Evidence = []evidence.EvidenceRef{{
		Source:          "terraform_plan",
		ResourceAddress: "aws_s3_bucket.assets",
		Path:            "tags.environment",
		Location:        &evidence.Location{File: "main.tf", Line: 9},
	}}
	return bundle
}

// TestMarkdownShowsWhereADeclarationIsWritten covers the whole point of the
// milestone reaching a reader: the report says which file and line, next to the
// address it is about.
func TestMarkdownShowsWhereADeclarationIsWritten(t *testing.T) {
	out, err := render.Markdown(withLocations())
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}
	text := string(out)

	for _, want := range []string{"main.tf:6", "modules/storage/main.tf:25", "main.tf:9"} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown does not carry %q:\n%s", want, text)
		}
	}
}

// TestMarkdownWithoutLocationsSaysNothingAboutFiles keeps the addition out of
// the way when there is nothing to say. A report that printed an empty position
// would be claiming to have looked.
func TestMarkdownWithoutLocationsSaysNothingAboutFiles(t *testing.T) {
	out, err := render.Markdown(withoutLocations())
	if err != nil {
		t.Fatalf("render.Markdown: %v", err)
	}

	if strings.Contains(string(out), ".tf") {
		t.Fatalf("markdown mentions a file with no location to report:\n%s", out)
	}
}

// TestReviewShowsWhereADeclarationIsWritten covers the format a reviewer reads
// with a diff open, which is where a line number is worth the most.
func TestReviewShowsWhereADeclarationIsWritten(t *testing.T) {
	out, err := render.Review(withLocations())
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}

	if !strings.Contains(string(out), "main.tf:6") {
		t.Fatalf("the review does not say where the declaration is:\n%s", out)
	}
}

// TestReviewWithLocationsStaysInsideItsBound covers the budget. A location makes
// every row longer, and the comment has one size it must fit in.
func TestReviewWithLocationsStaysInsideItsBound(t *testing.T) {
	bundle := withLocations()
	long := strings.Repeat("deeply/nested/", 15) + "main.tf"
	for i := range 200 {
		finding := bundle.Findings[0]
		finding.RuleID = "STORAGE_PUBLIC"
		resource := *finding.Resource
		resource.Address = strings.Repeat("a", 40) + string(rune('a'+i%26))
		resource.Location = &evidence.Location{File: long, Line: 100000 + i}
		finding.Resource = &resource
		bundle.Findings = append(bundle.Findings, finding)
	}

	out, err := render.Review(bundle)
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}
	if len(out) > render.MaxReviewBytes {
		t.Fatalf("the review is %d bytes, past the %d it must fit in", len(out), render.MaxReviewBytes)
	}
	if !strings.Contains(string(out), "not shown here") {
		t.Fatalf("rows were dropped without saying so:\n%s", out)
	}
}

// TestAFileNameCannotForgeAReport covers the escaping discipline every other
// field in this build is held to. A location is produced by this build, but its
// path comes from a filesystem somebody else writes to: a file whose name holds
// a backtick, a pipe or a bracket must not be able to end a code span, add a
// table cell, or plant a link.
//
// Several of these names never reach a renderer at all -- a path that is not in
// cleaned form is refused by the contract, which is the stronger answer, and the
// subtest says so by skipping. What the contract accepts is held here for the
// table, and by FuzzMarkdownStructure for the document structure, which compares
// against the same bundle rendered with a benign value.
func TestAFileNameCannotForgeAReport(t *testing.T) {
	hostile := []string{
		"a`b.tf",
		"a|b.tf",
		"a`` ``b.tf",
		"[click](https://example.invalid)/main.tf",
		"a<script>b.tf",
		"a*b_c.tf",
	}
	for _, name := range hostile {
		t.Run(name, func(t *testing.T) {
			bundle := withoutLocations()
			bundle.Findings[0].Resource.Location = &evidence.Location{File: name, Line: 6}
			bundle.Findings[0].Evidence[0].Location = &evidence.Location{File: name, Line: 7}
			if err := bundle.Validate(); err != nil {
				t.Skipf("the contract refuses this name already: %v", err)
			}

			markdown, err := render.Markdown(bundle)
			if err != nil {
				t.Fatalf("render.Markdown: %v", err)
			}
			if strings.Contains(string(markdown), "](") {
				t.Fatalf("a file name planted a link:\n%s", markdown)
			}

			review, err := render.Review(bundle)
			if err != nil {
				t.Fatalf("render.Review: %v", err)
			}
			for _, line := range strings.Split(string(review), "\n") {
				if !strings.HasPrefix(line, "|") {
					continue
				}
				// Every row of this table has four cells, so five boundaries.
				// An escaped pipe is text inside a cell and is not one of them,
				// which is the whole job of the escaping being tested.
				if got := unescapedPipes(line); got != 5 {
					t.Fatalf("a file name changed a table row's shape (%d boundaries): %q", got, line)
				}
			}
		})
	}
}

// unescapedPipes counts the cell boundaries in a table row: a pipe that is not
// preceded by a backslash.
func unescapedPipes(line string) int {
	count := 0
	for i := 0; i < len(line); i++ {
		if line[i] == '\\' {
			i++
			continue
		}
		if line[i] == '|' {
			count++
		}
	}
	return count
}
