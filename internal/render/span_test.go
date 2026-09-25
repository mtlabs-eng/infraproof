package render

import (
	"strings"
	"testing"
)

// TestACodeSpanContainsWhateverItIsGiven covers the span's own guarantee,
// which no bundle can currently exercise.
//
// Markdown validates before it renders, and the contract refuses a line break
// in every field that reaches a code span today. That makes the collapsing
// inside code unreachable through the public entry point — and a guarantee
// nothing exercises is one a later change removes without a word. The point of
// putting it in the span rather than in a list of fields was that a field added
// later inherits it, so it is tested where it lives.
func TestACodeSpanContainsWhateverItIsGiven(t *testing.T) {
	cases := map[string]string{
		"a line break":        "a\nb",
		"a carriage return":   "a\r\nb",
		"a blank line":        "a\n\nb",
		"a backtick":          "a`b",
		"a leading backtick":  "`ab",
		"a trailing backtick": "ab`",
		"a run of backticks":  "a``b`c",
	}

	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			span := code(value)
			for _, char := range []string{"\n", "\r"} {
				if strings.Contains(span, char) {
					t.Errorf("the span carries a break, which would end it: %q", span)
				}
			}
			if !spanIsClosedByItsOwnFence(span) {
				t.Errorf("the span can be ended by its own contents: %q", span)
			}
		})
	}
}

// spanIsClosedByItsOwnFence reports whether the fence is longer than every run
// of backticks inside, which is what keeps the span from ending early and
// spilling its contents into the document as markup.
func spanIsClosedByItsOwnFence(span string) bool {
	fence := 0
	for fence < len(span) && span[fence] == '`' {
		fence++
	}
	if fence == 0 || len(span) < 2*fence {
		return false
	}
	if span[len(span)-fence:] != span[:fence] {
		return false
	}

	inner := span[fence : len(span)-fence]
	longest, run := 0, 0
	for i := range len(inner) {
		if inner[i] == '`' {
			run++
			if run > longest {
				longest = run
			}
			continue
		}
		run = 0
	}
	return longest < fence
}

// TestACodeSpanCarriesNoControlCharacter covers what a terminal does with a
// value a plan author chose.
//
// A report is read in a terminal as often as in a browser, and an escape
// sequence there is not text: it moves the cursor, clears the line, or colours
// what follows. A resource address carrying one can hide the finding under it.
// The bundle refuses a line break in these fields and says nothing about the
// rest of the C0 range, so the span is where it is handled -- the same place,
// and for the same reason, as the break.
func TestACodeSpanCarriesNoControlCharacter(t *testing.T) {
	for name, value := range map[string]string{
		"an escape sequence": "a\x1b[2Kb",
		"a bell":             "a\ab",
		"a backspace":        "ab\b\b\bcd",
		"a vertical tab":     "a\vb",
		"a form feed":        "a\fb",
		"a delete":           "a\x7fb",
	} {
		t.Run(name, func(t *testing.T) {
			span := code(value)
			for _, char := range span {
				if char < 0x20 || char == 0x7f || (char >= 0x80 && char <= 0x9f) {
					t.Errorf("the span carries %U, which a terminal acts on: %q", char, span)
				}
			}
		})
	}
}

// TestProseCarriesNoControlCharacter is the same guarantee outside a code span.
//
// Nothing reachable through Markdown exercises it today, because the bundle
// refuses a break in the four prose fields that existed when that rule was
// written. That is exactly why it is here: the guarantee belongs to the
// renderer, so a prose field added later inherits it instead of re-opening the
// hole in silence.
func TestProseCarriesNoControlCharacter(t *testing.T) {
	for name, value := range map[string]string{
		"an escape sequence": "a\x1b[2Kb",
		"a line break":       "a\nb",
		"a carriage return":  "a\r\nb",
		"a delete":           "a\x7fb",
	} {
		t.Run(name, func(t *testing.T) {
			for _, rendered := range []string{prose(value), inlineText(value)} {
				for _, char := range rendered {
					if char < 0x20 || char == 0x7f || (char >= 0x80 && char <= 0x9f) {
						t.Errorf("the text carries %U, which a reader's terminal acts on: %q",
							char, rendered)
					}
				}
			}
		})
	}
}
