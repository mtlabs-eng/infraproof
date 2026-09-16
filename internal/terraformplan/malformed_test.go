package terraformplan

import (
	"strings"
	"testing"
)

func TestMalformedFixtureIsRejected(t *testing.T) {
	_, err := Parse(fixtureBytes(t, "malformed"))
	if err == nil {
		t.Fatal("truncated JSON should be rejected")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "json") {
		t.Fatalf("error %q should identify the input as unparseable JSON", err.Error())
	}
}

// TestStructuralErrorsCarrySafeFieldContext covers the acceptance criterion
// that input errors locate the problem. Each case names a path; none may quote
// a value.
func TestStructuralErrorsCarrySafeFieldContext(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want string
	}{
		"resource_changes is not an array": {
			`{"format_version": "1.2", "resource_changes": {}}`,
			"resource_changes",
		},
		"resource change is not an object": {
			`{"format_version": "1.2", "resource_changes": [3]}`,
			"resource_changes[0]",
		},
		"change is not an object": {
			`{"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": 7}]}`,
			"resource_changes[0].change",
		},
		"actions is not an array": {
			`{"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": {"actions": "create"}}]}`,
			"resource_changes[0].change.actions",
		},
		"action is not a string": {
			`{"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": {"actions": [5]}}]}`,
			"resource_changes[0].change.actions[0]",
		},
		"missing address": {
			`{"format_version": "1.2", "resource_changes": [{"change": {"actions": ["create"]}}]}`,
			"address",
		},
		"missing change": {
			`{"format_version": "1.2", "resource_changes": [{"address": "a.b"}]}`,
			"change",
		},
		"mode is not a string": {
			`{"format_version": "1.2", "resource_changes": [{"address": "a.b", "mode": 1, "change": {"actions": ["create"]}}]}`,
			"mode",
		},
		"replace_paths is not an array of arrays": {
			`{"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": {"actions": ["create"], "replace_paths": ["bucket"]}}]}`,
			"replace_paths[0]",
		},
		"after_unknown is not a mask": {
			`{"format_version": "1.2", "resource_changes": [{"address": "a.b", "change": {"actions": ["create"], "after_unknown": "yes"}}]}`,
			"after_unknown",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(c.raw))
			if err == nil {
				t.Fatalf("expected an error mentioning %q", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not locate %q", err.Error(), c.want)
			}
		})
	}
}

// TestMalformedInputNeverPanics is the boundary guarantee: plan JSON is
// untrusted input and a panic in a verifier is a denial of the verification.
func TestMalformedInputNeverPanics(t *testing.T) {
	inputs := []string{
		"", " ", "null", "[]", "3", `""`, "{", "}", `{"format_version"`,
		`{"format_version": "1.2"}`,
		`{"format_version": "1.2", "resource_changes": null}`,
		`{"format_version": "1.2", "resource_changes": [null]}`,
		`{"format_version": "1.2", "resource_changes": [{}]}`,
		`{"format_version": "1.2", "configuration": 5, "resource_changes": []}`,
		`{"format_version": "1.2", "configuration": {"root_module": {"module_calls": {"a": {"module": {"module_calls": {"b": {}}}}}}}, "resource_changes": []}`,
		`{"format_version": ["1.2"], "resource_changes": []}`,
	}

	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Parse panicked on %q: %v", input, r)
				}
			}()
			_, _ = Parse([]byte(input))
		})
	}
}

func TestEmptyPlanIsValid(t *testing.T) {
	plan, err := Parse([]byte(`{"format_version": "1.2", "resource_changes": []}`))
	if err != nil {
		t.Fatalf("a plan with no changes should parse: %v", err)
	}
	if len(plan.ResourceChanges) != 0 {
		t.Fatalf("resource changes = %v, want none", plan.ResourceChanges)
	}
}
