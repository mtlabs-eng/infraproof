package terraformplan

import "testing"

// TestIsExpressionTellsAnAttributeFromASingleNestedBlock tests the decision the
// configuration walker turns on, because the walker's own single-nested path is
// unreachable through any provider measured.
//
// `nesting_mode: single` blocks exist in their hundreds on all three providers
// and every one of them is `timeouts`, which holds duration strings and names no
// resource. So a reference inside a single-nested block cannot be produced from a
// real plan, and a hand-authored fixture carrying one would be the fiction this
// project has been burned by. The predicate is the thing to pin.
//
// The last case is the format's ambiguity rather than this reader's: a provider
// attribute literally named `references` would be read as an expression. Nothing
// here can do better, and the grammar's comment says so instead of claiming
// certainty.
func TestIsExpressionTellsAnAttributeFromASingleNestedBlock(t *testing.T) {
	cases := map[string]struct {
		body map[string]any
		want bool
		why  string
	}{
		"a constant": {
			map[string]any{"constant_value": "40m"}, true,
			"an attribute written literally"},
		"a reference": {
			map[string]any{"references": []any{"aws_security_group.a"}}, true,
			"an attribute written from something else"},
		"both at once": {
			map[string]any{"constant_value": "x", "references": []any{"a"}}, true,
			"an interpolated string carries both"},
		"a single-nested block": {
			map[string]any{"create": map[string]any{"constant_value": "40m"}}, false,
			"timeouts, written as a bare object rather than an array of one"},
		"a block that also writes an attribute named like an expression key": {
			map[string]any{"create": map[string]any{}, "references": []any{"a"}}, false,
			"one key outside the pair is enough to make it a block"},
		"nothing at all": {
			map[string]any{}, true,
			"an empty object records no argument and names no reference either way, " +
				"and reading it as an expression is the answer that invents least"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isExpression(c.body); got != c.want {
				t.Fatalf("isExpression = %v, want %v: %s", got, c.want, c.why)
			}
		})
	}
}
