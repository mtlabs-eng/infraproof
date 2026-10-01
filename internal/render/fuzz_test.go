package render_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/render"
)

// FuzzMarkdownStructure holds the renderer's one guarantee over inputs nobody
// chose.
//
// Four functions in this package each restate part of a Markdown grammar —
// which characters open a block, which close a code span, which divide a table
// cell — and a review round found that the test oracle for one of them had
// restated the same grammar a second time, with the same error, so the test
// passed with the defect it was written to pin.
//
// Enumerating the constructs a renderer must neutralise is the field list this
// project keeps being caught by. The property is smaller and does not need the
// grammar: what a field contains must not change what the document is. A
// benign value in the same place gives the reference, and the two must have the
// same shape.
//
// Every value that reaches a report goes through one of the four, so a defect
// in any of them shows here as a shape that moved.
func FuzzMarkdownStructure(f *testing.F) {
	f.Add("ordinary-value")
	f.Add("| forged | cell |")
	f.Add("`closed` span")
	f.Add("x` <h1>live</h1>")
	f.Add(`c:\|drive`)
	f.Add("## heading")
	f.Add("- item")
	f.Add("> quote")
	f.Add("1. item")
	f.Add("***")
	f.Add("<!-- comment -->")
	f.Add("&amp;lt;h1&amp;gt;")
	f.Add("a\\`b")

	// Where the oracle itself was wrong, twice. Escapes and code spans
	// interleave: outside a span a backslash makes the next character literal,
	// so an escaped backtick is not part of a run and "```0```[" renders inert;
	// inside a span a backslash is ordinary, so "`[\\`" is a closed span whose
	// content ends in one. A seed that only the fuzzer had found is a seed the
	// next reader loses.
	f.Add("```0```[")
	f.Add("``````0``````[")
	f.Add("`[\\")
	f.Add("`\\`[")
	f.Add("\\`[")
	f.Add("``a``[")
	f.Add("`0`[")
	f.Add("\\\\[")
	// A value ending in a backslash, which is the case that tells the two
	// directions apart: inside a code span the backslash is ordinary, so the
	// fence that follows it still closes the span. An oracle that honoured
	// escapes there would pair this span's opener with the next span's, and
	// swallow the cell boundary between them.
	f.Add("x\\")
	// Paths, which is what a location carries.
	f.Add("main.tf")
	f.Add("a`b.tf")
	f.Add("a|b.tf")
	f.Add("modules/a`b/main.tf")

	f.Fuzz(func(t *testing.T, value string) {
		// The contract refuses a line break in an inline field, which is a
		// stronger answer than escaping and is asserted in internal/evidence.
		// Everything else is the renderer's to make safe.
		if strings.ContainsAny(value, "\r\n") {
			t.Skip()
		}

		for _, place := range placements() {
			hostile := placedBundle(place, value)
			out, err := render.Markdown(hostile)
			if err != nil {
				// A bundle the contract refuses produces no report, which
				// cannot mislead anyone.
				continue
			}

			reference, err := render.Markdown(placedBundle(place, place.benign))
			if err != nil {
				t.Fatalf("the benign bundle did not render: %v", err)
			}

			if got, want := structureOf(string(out)), structureOf(string(reference)); got != want {
				t.Fatalf("%s changed the document structure with %q\n got: %s\nwant: %s\n\n%s",
					place.name, value, got, want, out)
			}
		}
	})
}

// placement is one field a value can reach a report through, with a benign
// value the contract accepts in that position. A field with a closed format —
// a check id, a decision — needs its own, or the reference bundle does not
// render and the property cannot be compared.
type placement struct {
	name   string
	benign string
	put    func(*evidence.Bundle, string)
}

// placements covers one field of each kind the renderer treats differently:
// prose, a code span, a table cell, and a scalar.
func placements() []placement {
	return []placement{
		{"summary", "ordinary-value", func(b *evidence.Bundle, v string) { b.Summary = v }},
		{"a finding's claim", "ordinary-value", func(b *evidence.Bundle, v string) { b.Findings[0].Claim = v }},
		{"a remediation", "ordinary-value", func(b *evidence.Bundle, v string) { b.Findings[0].Remediation = v }},
		{"a resource address", "ordinary-value", func(b *evidence.Bundle, v string) { b.Findings[0].Resource.Address = v }},
		{"a provider", "ordinary-value", func(b *evidence.Bundle, v string) { b.Findings[0].Resource.Provider = v }},
		{"a capability path", "ordinary-value", func(b *evidence.Bundle, v string) { b.Findings[0].Observed.Path = v }},
		{"a scalar value", "ordinary-value", func(b *evidence.Bundle, v string) {
			b.Findings[0].Observed = evidence.KnownFact("object_storage.public_access", evidence.String(v))
		}},
		{"an evidence source", "ordinary-value", func(b *evidence.Bundle, v string) { b.Findings[0].Evidence[0].Source = v }},
		{"an evidence path", "ordinary-value", func(b *evidence.Bundle, v string) { b.Findings[0].Evidence[0].Path = v }},
		{"an unknown's reason", "ordinary-value", func(b *evidence.Bundle, v string) { b.Unknowns[0].Reason = v }},
		{"an unknown's address", "ordinary-value", func(b *evidence.Bundle, v string) { b.Unknowns[0].ResourceAddress = &v }},
		{"a check id", "ORDINARY_CHECK", func(b *evidence.Bundle, v string) { b.Unknowns[0].CheckID = v }},
		{"a verification name", "ordinary-value", func(b *evidence.Bundle, v string) { b.Verification[0].Name = v }},
		{"an intent source", "ordinary-value", func(b *evidence.Bundle, v string) { b.Subject.IntentSource = v }},
		// A location's path comes from a filesystem somebody else writes to, so
		// it is a value this build did not author and belongs here with the
		// rest. Most of what a fuzzer puts in it is refused by the contract,
		// which is the stronger answer; what the contract accepts the renderer
		// has to make safe.
		{"a resource location", "ordinary-value", func(b *evidence.Bundle, v string) {
			b.Findings[0].Resource.Location = &evidence.Location{File: v, Line: 6}
		}},
		{"an evidence location", "ordinary-value", func(b *evidence.Bundle, v string) {
			b.Findings[0].Evidence[0].Location = &evidence.Location{File: v, Line: 7}
		}},
	}
}

func placedBundle(place placement, value string) evidence.Bundle {
	bundle := hostileBundle()
	place.put(&bundle, value)
	return bundle
}
