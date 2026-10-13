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
	// carried is set on a node of a planned value whose prior state holds the
	// same value at the same place. See Carried.
	carried bool
	// inPrior is set on an element of a list whose prior list, at the same
	// place, holds an equal element at any position. See InPrior.
	inPrior bool

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

// Carried reports, for a node of a change's planned value, that its prior
// state holds the same value at the same place: an update or no-op keeps it.
// An element of a list is compared with the element in the same position.
//
// It is decided from the plan's own before and after, before either is masked,
// so a value marked sensitive -- which this package withholds from every
// reading -- is compared like any other: a mark must not make a value the plan
// keeps look like one it moves. Only the answer is kept. A value not yet known
// is never carried, nor is one with no prior state at its place; and a node
// read through a value this run was not permitted to see has no place, so it
// is not carried either.
func (v Value) Carried() bool { return v.carried }

// InPrior reports, for a node of a change's planned value, that its prior
// state holds the same value: at the same place, as Carried does, or -- for an
// element of a list or a set -- as any element of the list at the same place.
// A legacy-SDK set is ordered by hash, and a provider that suppresses removing
// an element plans it beside the one written, so the update moves the list
// while the element is the one the object already had.
//
// It is decided as Carried is, from the raw values before any mark applies,
// and only the answer is kept. An element any part of which is not yet known
// is not in prior state.
func (v Value) InPrior() bool { return v.carried || v.inPrior }

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
	if withheld := v.withheld(); withheld != nil {
		return *withheld
	}
	if v.Kind() != KindArray || i < 0 || i >= len(v.array) {
		return Value{}
	}
	return v.array[i]
}

// Field returns the named field, or an Absent value when the key is not present
// or the value is not a readable object. Absent is a real answer here: it is
// how a caller learns the plan never mentioned the field.
//
// Except where the receiver itself was withheld. Nothing inside a value this
// run was not permitted to see is absent — it is unreadable for the same
// reason, and saying "absent" there is the answer that lets a caller conclude.
// A whole "after" marked sensitive made every attribute under it look like one
// the plan never mentioned.
func (v Value) Field(name string) Value {
	if withheld := v.withheld(); withheld != nil {
		return *withheld
	}
	if v.Kind() != KindObject {
		return Value{}
	}
	return v.object[name]
}

// withheld returns a value carrying the receiver's own unreadable state, or nil
// when the receiver was readable.
func (v Value) withheld() *Value {
	switch v.State() {
	case StateRedacted:
		return &Value{present: true, sensitive: true}
	case StateUnknown:
		return &Value{present: true, unknown: true}
	default:
		return nil
	}
}

// HoldsSensitive reports whether this value or anything inside it was marked
// sensitive.
//
// State answers for the node alone, which is the right answer for reading a
// value and the wrong one for locating it. A list whose elements are marked
// individually is itself readable, so a reference to the list reported that
// nothing was withheld while one of the things at that location was a secret.
func (v Value) HoldsSensitive() bool {
	if v.sensitive {
		return true
	}
	for _, element := range v.array {
		if element.HoldsSensitive() {
			return true
		}
	}
	for _, field := range v.object {
		if field.HoldsSensitive() {
			return true
		}
	}
	return false
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
