package terraformplan

import (
	"encoding/json"
	"slices"
)

// State is what is known about a value. It is the distinction the whole package
// exists to preserve: a rule that cannot tell Absent from Known(false), or
// Unknown from Absent, can reach a confident wrong conclusion.
type State string

const (
	// StateAbsent means the plan did not mention this field at all. It is not a
	// provider default and must never be read as one.
	StateAbsent State = "ABSENT"
	// StateKnown means the plan supplied a definite value.
	StateKnown State = "KNOWN"
	// StateUnknown means Terraform will not know the value until apply.
	StateUnknown State = "UNKNOWN"
	// StateRedacted means Terraform marked the value sensitive, so this package
	// discarded it while reading.
	StateRedacted State = "REDACTED"
)

// Kind is the JSON shape of a readable value.
type Kind string

const (
	// KindAbsent is the kind of any value that is not readable — absent,
	// unknown, or redacted. There is no shape to report.
	KindAbsent Kind = "absent"
	// KindNull is an explicit JSON null, which is a known value.
	KindNull Kind = "null"
	// KindBool is a JSON boolean.
	KindBool Kind = "bool"
	// KindNumber is a JSON number, kept exact as text.
	KindNumber Kind = "number"
	// KindString is a JSON string.
	KindString Kind = "string"
	// KindArray is a JSON array.
	KindArray Kind = "array"
	// KindObject is a JSON object.
	KindObject Kind = "object"
)

// Value is one node of a parsed plan value, merged from the value Terraform
// emitted and its unknown and sensitive masks.
//
// The zero Value is Absent, which is the correct reading of a field the plan
// did not mention. Payload fields are populated only for a value that is
// present, known, and not sensitive, so a redacted node has nowhere to hold
// data and a redacted container holds no children at all.
type Value struct {
	present   bool
	unknown   bool
	sensitive bool

	kind    Kind
	boolean bool
	number  json.Number
	text    string
	array   []Value
	object  map[string]Value
}

// State reports what is known about the value. Sensitivity outranks
// unknown-ness because a redacted value is unreadable either way; Unknown
// remains separately available.
func (v Value) State() State {
	switch {
	case !v.present:
		return StateAbsent
	case v.sensitive:
		return StateRedacted
	case v.unknown:
		return StateUnknown
	default:
		return StateKnown
	}
}

// Unknown reports whether Terraform marked this value as not known until apply.
// It stays true for a value that is also sensitive.
func (v Value) Unknown() bool { return v.unknown }

// Sensitive reports whether Terraform marked this value sensitive.
func (v Value) Sensitive() bool { return v.sensitive }

// Kind reports the JSON shape of a readable value, and KindAbsent for anything
// that is not readable.
func (v Value) Kind() Kind {
	if v.State() != StateKnown {
		return KindAbsent
	}
	return v.kind
}

// Bool returns the boolean value, or false for anything that is not a readable
// boolean. Check Kind before trusting the result: false is also a real value.
func (v Value) Bool() bool {
	if v.Kind() != KindBool {
		return false
	}
	return v.boolean
}

// Number returns the numeric value exactly as the plan wrote it, or the empty
// json.Number for anything that is not a readable number.
func (v Value) Number() json.Number {
	if v.Kind() != KindNumber {
		return ""
	}
	return v.number
}

// Text returns the string value, or the empty string for anything that is not a
// readable string.
func (v Value) Text() string {
	if v.Kind() != KindString {
		return ""
	}
	return v.text
}

// Len returns the number of elements in a readable array or the number of keys
// in a readable object, and zero otherwise.
func (v Value) Len() int {
	switch v.Kind() {
	case KindArray:
		return len(v.array)
	case KindObject:
		return len(v.object)
	default:
		return 0
	}
}

// At returns the element at index i, or an Absent value when the index is out
// of range or the value is not a readable array.
func (v Value) At(i int) Value {
	if v.Kind() != KindArray || i < 0 || i >= len(v.array) {
		return Value{}
	}
	return v.array[i]
}

// Field returns the named field, or an Absent value when the key is not present
// or the value is not a readable object. Absent is a real answer here: it is
// how a caller learns the plan never mentioned the field.
func (v Value) Field(name string) Value {
	if v.Kind() != KindObject {
		return Value{}
	}
	return v.object[name]
}

// Keys returns the field names of a readable object in sorted order, so that
// iteration is deterministic, and nil for anything else.
func (v Value) Keys() []string {
	if v.Kind() != KindObject {
		return nil
	}
	keys := make([]string, 0, len(v.object))
	for key := range v.object {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return keys
}
