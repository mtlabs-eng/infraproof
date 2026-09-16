package terraformplan

import "testing"

// TestFiveStatesRemainDistinguishable is the reason this milestone exists. A
// parser that collapses any pair of these makes every rule built on top of it
// capable of a confident wrong answer: absent must not read as false, and
// unknown must not read as absent.
func TestFiveStatesRemainDistinguishable(t *testing.T) {
	after := onlyChange(t, "absent-fields").After

	cases := []struct {
		field string
		state State
		kind  Kind
	}{
		{"missing_entirely", StateAbsent, KindAbsent},
		{"null_field", StateKnown, KindNull},
		{"false_field", StateKnown, KindBool},
		{"true_field", StateKnown, KindBool},
		{"zero_field", StateKnown, KindNumber},
		{"empty_string", StateKnown, KindString},
		{"empty_object", StateKnown, KindObject},
		{"empty_array", StateKnown, KindArray},
		{"unknown_field", StateUnknown, KindAbsent},
		{"redacted_field", StateRedacted, KindAbsent},
	}

	seen := map[string]bool{}
	for _, c := range cases {
		t.Run(c.field, func(t *testing.T) {
			got := after.Field(c.field)
			if got.State() != c.state {
				t.Fatalf("state = %q, want %q", got.State(), c.state)
			}
			if got.Kind() != c.kind {
				t.Fatalf("kind = %q, want %q", got.Kind(), c.kind)
			}
			seen[string(c.state)+"/"+string(c.kind)] = true
		})
	}

	if len(seen) != len(cases)-1 {
		t.Fatalf("expected %d distinct state/kind pairs, got %d: %v", len(cases)-1, len(seen), seen)
	}
}

func TestFalseIsNotAbsentAndZeroIsNotNull(t *testing.T) {
	after := onlyChange(t, "absent-fields").After

	if after.Field("false_field").Bool() {
		t.Fatal("false_field should be false")
	}
	if after.Field("false_field").State() == after.Field("missing_entirely").State() {
		t.Fatal("a false value and an absent field share a state")
	}
	if got := after.Field("zero_field").Number().String(); got != "0" {
		t.Fatalf("zero_field = %q, want 0", got)
	}
	if after.Field("zero_field").Kind() == after.Field("null_field").Kind() {
		t.Fatal("zero and null share a kind")
	}
}

// TestLargeIntegerKeepsItsPrecision is why the decoder uses json.Number: a
// float64 silently rounds this value.
func TestLargeIntegerKeepsItsPrecision(t *testing.T) {
	after := onlyChange(t, "absent-fields").After

	if got := after.Field("big_number").Number().String(); got != "9007199254740993" {
		t.Fatalf("big_number = %q, want 9007199254740993", got)
	}
}

// TestUnknownKeyAbsentFromAfterIsStillPresent covers the union rule: a key that
// appears only in the unknown mask is present and unknown, not absent.
func TestUnknownKeyAbsentFromAfterIsStillPresent(t *testing.T) {
	after := onlyChange(t, "unknown-after").After

	arn := after.Field("arn")
	if arn.State() != StateUnknown {
		t.Fatalf("arn state = %q, want %q", arn.State(), StateUnknown)
	}
	if !arn.Unknown() {
		t.Fatal("arn should report itself unknown")
	}

	if got := after.Field("nested").Field("known").Text(); got != "yes" {
		t.Fatalf("nested.known = %q", got)
	}
	if got := after.Field("nested").Field("pending").State(); got != StateUnknown {
		t.Fatalf("nested.pending state = %q, want %q", got, StateUnknown)
	}
}

// TestUnknownArrayFromMaskOnly covers the same union rule for arrays.
func TestUnknownArrayFromMaskOnly(t *testing.T) {
	rules := onlyChange(t, "unknown-after").After.Field("rules")

	if rules.Kind() != KindArray {
		t.Fatalf("rules kind = %q, want %q", rules.Kind(), KindArray)
	}
	if rules.Len() != 2 {
		t.Fatalf("rules length = %d, want 2", rules.Len())
	}
	if got := rules.At(0).State(); got != StateUnknown {
		t.Fatalf("rules[0] state = %q, want %q", got, StateUnknown)
	}
	if got := rules.At(1).Field("inner").State(); got != StateUnknown {
		t.Fatalf("rules[1].inner state = %q, want %q", got, StateUnknown)
	}
}

func TestKeysAreSortedAndComplete(t *testing.T) {
	keys := onlyChange(t, "absent-fields").After.Keys()

	want := []string{
		"big_number", "empty_array", "empty_object", "empty_string", "false_field",
		"null_field", "redacted_field", "true_field", "unknown_field", "zero_field",
	}
	if len(keys) != len(want) {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("keys = %v, want %v", keys, want)
		}
	}
}

func TestZeroValueIsAbsent(t *testing.T) {
	var v Value

	if v.State() != StateAbsent {
		t.Fatalf("the zero Value must be absent, got %q", v.State())
	}
	if v.Kind() != KindAbsent {
		t.Fatalf("the zero Value must have no kind, got %q", v.Kind())
	}
	if v.Len() != 0 || v.Keys() != nil {
		t.Fatal("the zero Value must have no children")
	}
	if v.Field("anything").State() != StateAbsent {
		t.Fatal("a field of the zero Value must be absent")
	}
	if v.At(0).State() != StateAbsent {
		t.Fatal("an index of the zero Value must be absent")
	}
}

func TestAccessorsOfMismatchedKindAreZero(t *testing.T) {
	after := onlyChange(t, "absent-fields").After

	if after.Field("empty_string").Bool() {
		t.Fatal("Bool of a string must be false")
	}
	if got := after.Field("false_field").Text(); got != "" {
		t.Fatalf("Text of a bool = %q, want empty", got)
	}
	if got := after.Field("unknown_field").Text(); got != "" {
		t.Fatalf("Text of an unknown value = %q, want empty", got)
	}
}

// TestKeyPresentOnlyInTheSensitiveMask completes the union rule. A key can
// reach the key set through any of the three documents, and the sensitive mask
// is the one a reader is least likely to think of.
func TestKeyPresentOnlyInTheSensitiveMask(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_db_instance.main",
	      "mode": "managed",
	      "type": "aws_db_instance",
	      "name": "main",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {
	        "actions": ["create"],
	        "before": null,
	        "after": {"engine": "postgres"},
	        "after_sensitive": {"password": true}
	      }
	    }
	  ]
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	after := plan.ResourceChanges[0].After

	if got := after.Field("password").State(); got != StateRedacted {
		t.Fatalf("password state = %q, want %q", got, StateRedacted)
	}
	if keys := after.Keys(); len(keys) != 2 {
		t.Fatalf("keys = %v, want engine and password", keys)
	}
}

// TestMaskEntryThatMarksNothingCreatesNoField keeps the union rule from
// inventing fields. A mask key whose value is false describes nothing, so the
// field is absent rather than present-and-empty.
func TestMaskEntryThatMarksNothingCreatesNoField(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets",
	      "mode": "managed",
	      "type": "aws_s3_bucket",
	      "name": "assets",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {
	        "actions": ["create"],
	        "before": null,
	        "after": {"bucket": "example-assets"},
	        "after_unknown": {"nothing": false},
	        "after_sensitive": {"also_nothing": false}
	      }
	    }
	  ]
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	after := plan.ResourceChanges[0].After

	for _, name := range []string{"nothing", "also_nothing"} {
		if got := after.Field(name).State(); got != StateAbsent {
			t.Fatalf("%s state = %q, want %q", name, got, StateAbsent)
		}
	}
	if keys := after.Keys(); len(keys) != 1 || keys[0] != "bucket" {
		t.Fatalf("keys = %v, want [bucket]", keys)
	}
	if after.Len() != 1 {
		t.Fatalf("length = %d, want 1", after.Len())
	}
}

// TestBeforeIsNotAffectedByTheAfterUnknownMask pins the two sides apart. There
// is no before_unknown by design — the prior state is already known — so
// applying the after mask to the before value would report a value that exists
// as one that does not.
func TestBeforeIsNotAffectedByTheAfterUnknownMask(t *testing.T) {
	raw := []byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "aws_s3_bucket.assets",
	      "mode": "managed",
	      "type": "aws_s3_bucket",
	      "name": "assets",
	      "provider_name": "registry.terraform.io/hashicorp/aws",
	      "change": {
	        "actions": ["update"],
	        "before": {"arn": "arn-of-the-existing-bucket"},
	        "after": {},
	        "after_unknown": {"arn": true}
	      }
	    }
	  ]
	}`)

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	change := plan.ResourceChanges[0]

	if got := change.Before.Field("arn").State(); got != StateKnown {
		t.Fatalf("before.arn state = %q, want %q", got, StateKnown)
	}
	if got := change.Before.Field("arn").Text(); got != "arn-of-the-existing-bucket" {
		t.Fatalf("before.arn = %q", got)
	}
	if got := change.After.Field("arn").State(); got != StateUnknown {
		t.Fatalf("after.arn state = %q, want %q", got, StateUnknown)
	}
}
