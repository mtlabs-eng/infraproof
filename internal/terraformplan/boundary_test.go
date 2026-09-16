package terraformplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// planWithMasks builds a one-resource plan so a single mask shape can be
// examined in isolation.
func planWithMasks(after, unknownMask, sensitiveMask string) []byte {
	return []byte(fmt.Sprintf(`{
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
	        "after": %s,
	        "after_unknown": %s,
	        "after_sensitive": %s
	      }
	    }
	  ]
	}`, after, unknownMask, sensitiveMask))
}

// TestMaskShapeContradictionFailsClosed is the boundary rule. Plan JSON reaches
// this package from a coding agent or a third-party tool, not only from
// Terraform, so a mask that claims something is sensitive but whose shape
// cannot be applied to the value must redact rather than be ignored. Reading it
// as "nothing is sensitive" would disclose exactly the value the producer asked
// to have protected.
func TestMaskShapeContradictionFailsClosed(t *testing.T) {
	const secret = "s3cr3t"

	cases := map[string]struct {
		after, sensitive string
		field            string
	}{
		"object mask over a scalar": {`{"pw": "s3cr3t"}`, `{"pw": {"anything": true}}`, "pw"},
		"array mask over a scalar":  {`{"pw": "s3cr3t"}`, `{"pw": [true]}`, "pw"},
		"object mask over a null":   {`{"pw": null}`, `{"pw": {"anything": true}}`, "pw"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			plan, _ := Parse(planWithMasks(c.after, `{}`, c.sensitive))
			after := plan.ResourceChanges[0].After

			value := after.Field(c.field)
			if value.State() != StateRedacted {
				t.Fatalf("%s state = %q, want %q", c.field, value.State(), StateRedacted)
			}
			if leaked := findLeak(after, secret); leaked != "" {
				t.Fatalf("value disclosed at %s", leaked)
			}
		})
	}
}

// TestContradictionIsContainedToTheOffendingNode keeps the rule proportionate:
// the contradicted field is redacted, and its readable siblings are not.
func TestContradictionIsContainedToTheOffendingNode(t *testing.T) {
	plan, _ := Parse(planWithMasks(
		`{"outer": {"pw": "s3cr3t", "name": "visible"}}`,
		`{}`,
		`{"outer": {"pw": {"deeper": true}}}`))

	outer := plan.ResourceChanges[0].After.Field("outer")
	if got := outer.Field("pw").State(); got != StateRedacted {
		t.Fatalf("outer.pw state = %q, want %q", got, StateRedacted)
	}
	if got := outer.Field("name").Text(); got != "visible" {
		t.Fatalf("a readable sibling was lost: outer.name = %q", got)
	}
	if leaked := findLeak(plan.ResourceChanges[0].After, "s3cr3t"); leaked != "" {
		t.Fatalf("value disclosed at %s", leaked)
	}
}

// TestUnknownMaskContradictionFailsClosed applies the same rule to unknown.
// CLAUDE.md requires unknown values to be preserved as unknown; silently
// reading a contradictory mask as "known" reports certainty the plan denies.
func TestUnknownMaskContradictionFailsClosed(t *testing.T) {
	plan, _ := Parse(planWithMasks(`{"f": "old"}`, `{"f": {"x": true}}`, `{}`))

	value := plan.ResourceChanges[0].After.Field("f")
	if value.State() != StateUnknown {
		t.Fatalf("state = %q, want %q", value.State(), StateUnknown)
	}
	if value.Text() != "" {
		t.Fatalf("a contradicted value was still readable as %q", value.Text())
	}
}

// TestUnparseableMaskNodeFailsClosed covers the case where the parser already
// reports the mask as malformed. Reporting the problem and returning the value
// anyway is the worst of both outcomes.
func TestUnparseableMaskNodeFailsClosed(t *testing.T) {
	plan, err := Parse(planWithMasks(`{"pw": "s3cr3t"}`, `{}`, `{"pw": 1}`))
	if err == nil {
		t.Fatal("a mask node that is not a boolean, object or array should be reported")
	}
	if len(plan.ResourceChanges) != 0 {
		t.Fatalf("a rejected plan returned %d resource change(s)", len(plan.ResourceChanges))
	}
}

// TestShortMaskArrayFailsClosed covers the array case. Terraform preserves
// indices by writing false for unmarked elements, so a mask array shorter than
// the value array does not describe the tail at all.
func TestShortMaskArrayFailsClosed(t *testing.T) {
	plan, _ := Parse(planWithMasks(`{"list": ["public", "s3cr3t"]}`, `{}`, `{"list": [false]}`))

	list := plan.ResourceChanges[0].After.Field("list")
	if list.Len() != 2 {
		t.Fatalf("length = %d, want 2", list.Len())
	}
	if got := list.At(0).Text(); got != "public" {
		t.Fatalf("the described element was altered: %q", got)
	}
	if got := list.At(1).State(); got != StateRedacted {
		t.Fatalf("the undescribed element state = %q, want %q", got, StateRedacted)
	}
}

// TestFullLengthMaskArrayIsHonoured is the counterweight: the shape Terraform
// actually emits must not be treated as a contradiction.
func TestFullLengthMaskArrayIsHonoured(t *testing.T) {
	plan, err := Parse(planWithMasks(`{"list": ["public", "s3cr3t"]}`, `{}`, `{"list": [false, true]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	list := plan.ResourceChanges[0].After.Field("list")
	if got := list.At(0).Text(); got != "public" {
		t.Fatalf("list[0] = %q, want public", got)
	}
	if got := list.At(1).State(); got != StateRedacted {
		t.Fatalf("list[1] state = %q, want %q", got, StateRedacted)
	}
}

// TestNullMaskMeansNoMask pins a shape left unspecified until now. Terraform
// writes false, never null, for "nothing here is marked"; null is treated the
// same way rather than being left to chance in either direction.
func TestNullMaskMeansNoMask(t *testing.T) {
	plan, err := Parse(planWithMasks(`{"pw": "visible"}`, `null`, `null`))
	if err != nil {
		t.Fatalf("a null mask should be accepted as no mask: %v", err)
	}

	value := plan.ResourceChanges[0].After.Field("pw")
	if value.State() != StateKnown || value.Text() != "visible" {
		t.Fatalf("state = %q text = %q, want a known visible value", value.State(), value.Text())
	}
}

// TestTrailingBytesAreRejected closes an evasion route. A file holding two
// concatenated plans would otherwise report the first and silently discard the
// second, so the reviewer of a change and the verifier of it would not be
// looking at the same document.
func TestTrailingBytesAreRejected(t *testing.T) {
	document := `{"format_version": "1.2", "resource_changes": []}`

	rejected := map[string]string{
		"a second document": document + document,
		"trailing text":     document + " garbage",
		"trailing array":    document + "[1,2,3]",
		"trailing NUL":      document + "\x00",
	}
	for name, raw := range rejected {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Fatal("content after the plan document should be rejected")
			}
		})
	}

	accepted := map[string]string{
		"trailing newline":    document + "\n",
		"trailing whitespace": document + "  \n\t ",
	}
	for name, raw := range accepted {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err != nil {
				t.Fatalf("trailing whitespace is not content: %v", err)
			}
		})
	}
}

// TestSecondDocumentCannotHideAChange states the consequence directly.
func TestSecondDocumentCannotHideAChange(t *testing.T) {
	harmless := `{"format_version":"1.2","resource_changes":[{"address":"null_resource.harmless","mode":"managed",
	"type":"null_resource","name":"harmless","provider_name":"p","change":{"actions":["no-op"],"before":{},"after":{}}}]}`
	destructive := `{"format_version":"1.2","resource_changes":[{"address":"aws_s3_bucket.public","mode":"managed",
	"type":"aws_s3_bucket","name":"public","provider_name":"p","change":{"actions":["delete","create"],"before":{},"after":{}}}]}`

	plan, err := Parse([]byte(harmless + destructive))
	if err == nil {
		t.Fatalf("a hidden second document was accepted, reporting %d change(s)", len(plan.ResourceChanges))
	}
}

// TestErrorsDoNotEchoUnboundedInput covers the one diagnostic that interpolated
// plan content. errors.go promises a ParseError carries a path and an
// explanation; an attacker-controlled string reaching a CI log is not that.
func TestErrorsDoNotEchoUnboundedInput(t *testing.T) {
	hostile := strings.Repeat("A", 300) + "\n\x1b[31mINJECTED\x1b[0m"

	// Encoded with the JSON marshaller: Go's %q would emit \x1b, which JSON
	// does not accept, and the document would fail for the wrong reason.
	encoded, err := json.Marshal(hostile)
	if err != nil {
		t.Fatalf("encoding the test input: %v", err)
	}
	_, err = Parse([]byte(`{"format_version": ` + string(encoded) + `, "resource_changes": []}`))
	if err == nil {
		t.Fatal("expected an unsupported version error")
	}
	if strings.Contains(err.Error(), "INJECTED") || strings.Contains(err.Error(), strings.Repeat("A", 50)) {
		t.Fatalf("the error echoed unbounded input: %q", err.Error())
	}
	if !errors.Is(err, ErrUnsupportedFormatVersion) {
		t.Fatalf("error %v should still match ErrUnsupportedFormatVersion", err)
	}
	if !strings.Contains(err.Error(), "format_version") {
		t.Fatalf("error %q should still name the field", err.Error())
	}
}

// TestShortVersionsAreStillReported keeps the diagnostic useful: a plausible
// version string is short and bounded, and saying which one was rejected is
// most of the value of the message.
func TestShortVersionsAreStillReported(t *testing.T) {
	_, err := Parse([]byte(`{"format_version": "2.0", "resource_changes": []}`))
	if err == nil {
		t.Fatal("expected an unsupported version error")
	}
	if !strings.Contains(err.Error(), "2.0") {
		t.Fatalf("error %q should name the rejected version", err.Error())
	}
}

// TestJSONSyntaxErrorLocatesTheOffset gives a reader something to act on
// without quoting content. The decoder supplies a position only for a document
// it read up to a bad token, so the two failure modes are reported differently
// rather than one of them being given a position of zero that means nothing.
func TestJSONSyntaxErrorLocatesTheOffset(t *testing.T) {
	_, err := Parse([]byte(`{"format_version": "1.2", "resource_changes": [ @ ]}`))
	if err == nil {
		t.Fatal("a bad token should be rejected")
	}
	if !strings.Contains(err.Error(), "offset") {
		t.Fatalf("error %q does not locate the bad token", err.Error())
	}
}

// TestSyntaxErrorOffsetIsTheRealPosition checks the offset is computed rather
// than constant: two documents failing at different places report differently.
func TestSyntaxErrorOffsetIsTheRealPosition(t *testing.T) {
	_, early := Parse([]byte(`{@}`))
	_, late := Parse([]byte(`{"format_version": "1.2", "terraform_version": "1.12.0", "resource_changes": [ @ ]}`))
	if early == nil || late == nil {
		t.Fatal("both documents contain a bad token and should be rejected")
	}
	if early.Error() == late.Error() {
		t.Fatalf("both failures reported the same position: %v", early)
	}
	if strings.Contains(late.Error(), "offset 0") || strings.Contains(late.Error(), "offset 1") {
		t.Fatalf("a failure deep in the document was reported at the start: %v", late)
	}
}

// TestTruncatedInputIsNamedNotPositioned covers the other failure mode. A
// document that simply stops has no meaningful position to report.
func TestTruncatedInputIsNamedNotPositioned(t *testing.T) {
	_, err := Parse([]byte(`{"format_version": "1.2", "resource_changes": [`))
	if err == nil {
		t.Fatal("truncated JSON should be rejected")
	}
	if strings.Contains(err.Error(), "offset 0") {
		t.Fatalf("a truncated document should not be given a position: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "ended before") {
		t.Fatalf("error %q does not say the input ended early", err.Error())
	}
}

// TestRejectedPlanReturnsOnlyItsDigest keeps a failed parse from handing back a
// half-built plan. The digest is the one thing that stays useful, because it
// identifies the bytes that were rejected.
func TestRejectedPlanReturnsOnlyItsDigest(t *testing.T) {
	raw := planWithMasks(`{"pw": "s3cr3t"}`, `{}`, `{"pw": 1}`)

	plan, err := Parse(raw)
	if err == nil {
		t.Fatal("expected this plan to be rejected")
	}
	if !strings.HasPrefix(plan.Digest, "sha256:") {
		t.Fatalf("digest = %q", plan.Digest)
	}
	if len(plan.ResourceChanges) != 0 {
		t.Fatalf("a rejected plan returned %d resource change(s)", len(plan.ResourceChanges))
	}
	if plan.FormatVersion != "" || plan.TerraformVersion != "" || plan.ProviderConfigs != nil {
		t.Fatalf("a rejected plan returned populated fields: %+v", plan)
	}
}

// findLeak reports the path of the first readable string equal to needle.
func findLeak(v Value, needle string) string {
	switch v.Kind() {
	case KindString:
		if v.Text() == needle {
			return "<value>"
		}
	case KindObject:
		for _, key := range v.Keys() {
			if found := findLeak(v.Field(key), needle); found != "" {
				return "." + key + found
			}
		}
	case KindArray:
		for i := range v.Len() {
			if found := findLeak(v.At(i), needle); found != "" {
				return fmt.Sprintf("[%d]%s", i, found)
			}
		}
	}
	return ""
}

// TestInvalidMaskNodeMarksItsSubtree pins the fail-closed reading at the level
// where it is observable. Parse rejects a plan containing such a mask and
// returns no plan at all, so this invariant cannot be seen from outside — but
// it is the reason that rejection is safe rather than merely correct.
func TestInvalidMaskNodeMarksItsSubtree(t *testing.T) {
	var errs []error
	m := parseMask("change.after_sensitive.pw", 7, true, &errs)

	if len(errs) == 0 {
		t.Fatal("a mask node that is not a boolean, object or array should be reported")
	}
	if !m.isSet() {
		t.Fatal("an unreadable mask must cover its subtree rather than degrade to no mask")
	}

	value := merge("s3cr3t", true, mask{}, m)
	if value.State() != StateRedacted {
		t.Fatalf("state = %q, want %q", value.State(), StateRedacted)
	}
	if value.Text() != "" {
		t.Fatalf("the value survived as %q", value.Text())
	}
}

// TestLongButPlausibleVersionIsNotEchoed covers the length bound on its own. A
// string can be entirely ordinary characters and still be far too long to
// belong in a log line.
func TestLongButPlausibleVersionIsNotEchoed(t *testing.T) {
	long := strings.Repeat("1.2.3.", 50)

	_, err := Parse([]byte(`{"format_version": "` + long + `", "resource_changes": []}`))
	if err == nil {
		t.Fatal("expected an unsupported version error")
	}
	if strings.Contains(err.Error(), strings.Repeat("1.2.3.", 3)) {
		t.Fatalf("the error echoed an over-long version: %q", err.Error())
	}
}

// TestShortHostileVersionIsNotEchoed covers the character bound on its own. A
// value can be short enough to look harmless and still carry terminal control
// sequences or line breaks that rewrite the log around it.
func TestShortHostileVersionIsNotEchoed(t *testing.T) {
	for name, hostile := range map[string]string{
		"terminal escape": "1.2\x1b[31mX",
		"line break":      "1.2\nFAKE",
		"carriage return": "1.2\rFAKE",
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(hostile)
			if err != nil {
				t.Fatalf("encoding the test input: %v", err)
			}

			_, err = Parse([]byte(`{"format_version": ` + string(encoded) + `, "resource_changes": []}`))
			if err == nil {
				t.Fatal("expected an unsupported version error")
			}
			if strings.ContainsAny(err.Error(), "\r\n\x1b") {
				t.Fatalf("the error echoed a control character: %q", err.Error())
			}
			if strings.Contains(err.Error(), "FAKE") || strings.Contains(err.Error(), "[31m") {
				t.Fatalf("the error echoed hostile content: %q", err.Error())
			}
		})
	}
}

// TestUnsupportedVersionReportsOnlyThatProblem keeps a rejected format from
// producing a cascade. Once the format is one this build cannot read, every
// further complaint about the document's contents is noise derived from a
// guess.
func TestUnsupportedVersionReportsOnlyThatProblem(t *testing.T) {
	raw := []byte(`{
	  "format_version": "2.0",
	  "terraform_version": 7,
	  "resource_changes": [{"address": "", "change": {"actions": []}}]
	}`)

	_, err := Parse(raw)
	if err == nil {
		t.Fatal("expected an unsupported version error")
	}
	if got := strings.Count(err.Error(), "terraformplan:"); got != 1 {
		t.Fatalf("expected exactly one problem to be reported, got %d:\n%v", got, err)
	}
	if !strings.Contains(err.Error(), "format_version") {
		t.Fatalf("the single reported problem should be the format version: %v", err)
	}
}

// TestDisagreeingMasksOverAnAbsentValueMarkBoth covers the one remaining place
// where a mask that marks something could be read as marking nothing. With no
// value at the node the masks supply its shape, so they cannot contradict the
// value — but they can contradict each other, and building the node from one
// of them would silently discard the other's claim.
func TestDisagreeingMasksOverAnAbsentValueMarkBoth(t *testing.T) {
	cases := map[string]struct{ unknown, sensitive string }{
		"unknown object, sensitive array": {`{"f": {"a": true}}`, `{"f": [true]}`},
		"unknown array, sensitive object": {`{"f": [true]}`, `{"f": {"a": true}}`},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			plan, _ := Parse(planWithMasks(`{}`, c.unknown, c.sensitive))

			f := plan.ResourceChanges[0].After.Field("f")
			if f.State() != StateRedacted {
				t.Fatalf("state = %q, want %q", f.State(), StateRedacted)
			}
			if !f.Unknown() {
				t.Fatal("the unknown claim was discarded")
			}
			if !f.Sensitive() {
				t.Fatal("the sensitive claim was discarded")
			}
		})
	}
}

// TestAgreeingMasksOverAnAbsentValueAreHonoured is the counterweight: two masks
// of the same shape describe the same structure and must still be merged rather
// than treated as a disagreement.
func TestAgreeingMasksOverAnAbsentValueAreHonoured(t *testing.T) {
	plan, err := Parse(planWithMasks(`{}`, `{"f": {"a": true}}`, `{"f": {"b": true}}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	f := plan.ResourceChanges[0].After.Field("f")
	if f.State() != StateKnown || f.Kind() != KindObject {
		t.Fatalf("f state = %q kind = %q, want a known object", f.State(), f.Kind())
	}
	if got := f.Field("a").State(); got != StateUnknown {
		t.Fatalf("f.a state = %q, want %q", got, StateUnknown)
	}
	if got := f.Field("b").State(); got != StateRedacted {
		t.Fatalf("f.b state = %q, want %q", got, StateRedacted)
	}
}

// TestShortUnknownMaskArrayFailsClosed is the unknown half of the tail rule.
// "Preserve unknown values as unknown" is the same instruction as the one
// covering sensitive values, and an undescribed element is not a known one.
func TestShortUnknownMaskArrayFailsClosed(t *testing.T) {
	plan, _ := Parse(planWithMasks(`{"list": ["first", "second"]}`, `{"list": [false]}`, `{}`))

	list := plan.ResourceChanges[0].After.Field("list")
	if got := list.At(0).Text(); got != "first" {
		t.Fatalf("the described element was altered: %q", got)
	}
	if got := list.At(1).State(); got != StateUnknown {
		t.Fatalf("the undescribed element state = %q, want %q", got, StateUnknown)
	}
}

// TestNonArrayMaskDoesNotTruncateAnArray keeps the tail rule scoped to array
// masks. A mask of false, or an object mask, describes nothing positionally, so
// it must not be read as an empty array that leaves every element undescribed.
func TestNonArrayMaskDoesNotTruncateAnArray(t *testing.T) {
	plan, err := Parse(planWithMasks(`{"list": ["first", "second"]}`, `{"list": false}`, `{"list": false}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	list := plan.ResourceChanges[0].After.Field("list")
	for i, want := range []string{"first", "second"} {
		if got := list.At(i).Text(); got != want {
			t.Fatalf("list[%d] = %q, want %q — a false mask marks nothing", i, got, want)
		}
	}
}

// TestSafeTokenBoundary pins the length limit itself rather than only its
// effect on obviously oversized input.
func TestSafeTokenBoundary(t *testing.T) {
	sixteen := "1234567890123456"
	seventeen := sixteen + "7"

	if got := safeToken(sixteen); got != `"`+sixteen+`"` {
		t.Fatalf("a sixteen-character token should be reported, got %s", got)
	}
	if got := safeToken(seventeen); got == `"`+seventeen+`"` {
		t.Fatalf("a seventeen-character token should not be reported, got %s", got)
	}
}

// TestDisagreementOnlyArbitratesWhenTheValueIsAbsent keeps the rule from
// over-marking. Where a value exists it settles the disagreement by itself:
// each mask is judged against the value, and only the one that cannot apply is
// marked. Treating the other as marked too would withhold a field the plan
// describes perfectly well.
func TestDisagreementOnlyArbitratesWhenTheValueIsAbsent(t *testing.T) {
	// The value is an object. The unknown mask is an object and fits it; the
	// sensitive mask is an array and does not.
	plan, _ := Parse(planWithMasks(
		`{"f": {"a": "visible"}}`,
		`{"f": {"b": true}}`,
		`{"f": [true]}`))

	f := plan.ResourceChanges[0].After.Field("f")
	if f.State() != StateRedacted {
		t.Fatalf("state = %q, want %q — the array mask cannot apply to an object", f.State(), StateRedacted)
	}
	if f.Unknown() {
		t.Fatal("the unknown mask fits the value and must not be marked by the disagreement")
	}
}
