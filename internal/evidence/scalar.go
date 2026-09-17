package evidence

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"strconv"
)

// Scalar is a fact value. It is a closed set of JSON-safe kinds — boolean,
// string, and integer — chosen so that canonical output is byte-stable. Maps
// are excluded because Go iterates them in a random order; floating-point
// numbers are excluded because their shortest representation is not a stable
// contract. A Scalar is always constructed through Bool, String, or Int, so an
// absent value is a nil *Scalar rather than an empty value that could be
// mistaken for a real one.
type Scalar struct {
	kind    scalarKind
	boolean bool
	text    string
	number  int64
}

type scalarKind uint8

const (
	scalarInvalid scalarKind = iota
	scalarBool
	scalarString
	scalarInt
)

// Bool returns a boolean fact value.
func Bool(v bool) *Scalar { return &Scalar{kind: scalarBool, boolean: v} }

// String returns a string fact value.
func String(v string) *Scalar { return &Scalar{kind: scalarString, text: v} }

// Int returns an integer fact value.
func Int(v int64) *Scalar { return &Scalar{kind: scalarInt, number: v} }

// errUninitializedScalar reports a Scalar that was created as a zero value
// instead of through a constructor. It carries no payload, so it can never
// disclose a fact value.
var errUninitializedScalar = errors.New("evidence: uninitialized scalar value")

// Valid reports whether s was built through one of the Scalar constructors.
func (s *Scalar) Valid() bool {
	return s != nil && s.kind != scalarInvalid
}

// MarshalJSON renders the scalar as its underlying JSON primitive.
func (s *Scalar) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}
	switch s.kind {
	case scalarBool:
		return json.Marshal(s.boolean)
	case scalarString:
		return json.Marshal(s.text)
	case scalarInt:
		return json.Marshal(s.number)
	default:
		return nil, errUninitializedScalar
	}
}

// errUnsupportedScalarKind reports a JSON value outside the closed set. Like
// errUninitializedScalar it carries no payload: the rejected value may be a
// plan value, and an error message is output.
var errUnsupportedScalarKind = errors.New(
	"evidence: fact values must be a boolean, a string, or an integer")

// UnmarshalJSON reads a scalar back from its JSON primitive.
//
// A published format the package defining it cannot read is an output, not a
// format: every consumer that branches on a decision must decode a bundle
// first. The closed set stays closed in both directions — a float would round,
// an object would vanish, and either would break the total ordering the
// canonical form depends on, so both are refused rather than coerced.
func (s *Scalar) UnmarshalJSON(raw []byte) error {
	var decoded any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Numbers are read as text so that an integer outside int64 is refused
	// rather than silently rounded through float64.
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}

	switch value := decoded.(type) {
	case bool:
		*s = Scalar{kind: scalarBool, boolean: value}
	case string:
		*s = Scalar{kind: scalarString, text: value}
	case json.Number:
		number, err := strconv.ParseInt(value.String(), 10, 64)
		if err != nil {
			return errUnsupportedScalarKind
		}
		*s = Scalar{kind: scalarInt, number: number}
	default:
		// Objects, arrays, and null. A null reaches here only when decoded
		// into a non-pointer Scalar; an absent fact value is a nil *Scalar,
		// which encoding/json handles without calling this method.
		return errUnsupportedScalarKind
	}
	return nil
}

// Display renders the scalar for human-facing output. It returns an empty
// string for a nil or uninitialized scalar so that callers cannot accidentally
// print a placeholder that reads like a real value.
func (s *Scalar) Display() string {
	if s == nil {
		return ""
	}
	switch s.kind {
	case scalarBool:
		return strconv.FormatBool(s.boolean)
	case scalarString:
		return s.text
	case scalarInt:
		return strconv.FormatInt(s.number, 10)
	default:
		return ""
	}
}

// compareScalar orders two optional fact values. A missing value sorts before
// any present one, and values of different kinds are separated by kind, so the
// result is a total order over everything a Scalar can hold. Canonical ordering
// depends on it: without it, two findings that differ only in their observed
// value would compare equal and render in whatever order the producer used.
func compareScalar(a, b *Scalar) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	if c := cmp.Compare(a.kind, b.kind); c != 0 {
		return c
	}
	switch a.kind {
	case scalarBool:
		return compareBool(a.boolean, b.boolean)
	case scalarString:
		return cmp.Compare(a.text, b.text)
	case scalarInt:
		return cmp.Compare(a.number, b.number)
	default:
		return 0
	}
}
