package terraformplan

import (
	"encoding/json"
	"slices"
)

// mask is a parsed unknown or sensitive mask. Terraform emits each as a
// document mirroring the value it describes, with marked leaves replaced by
// true and unmarked leaves omitted, or as a bare false or true covering the
// whole value.
type mask struct {
	kind   maskKind
	flag   bool
	object map[string]mask
	array  []mask
}

type maskKind uint8

const (
	maskNone maskKind = iota
	maskFlag
	maskObject
	maskArray
)

// parseMask validates the shape of a mask document and converts it. A mask that
// is neither a boolean, an object, an array, nor absent is malformed input.
func parseMask(path string, raw any, present bool, errs *[]error) mask {
	if !present || raw == nil {
		return mask{}
	}
	switch typed := raw.(type) {
	case bool:
		return mask{kind: maskFlag, flag: typed}
	case map[string]any:
		out := mask{kind: maskObject, object: make(map[string]mask, len(typed))}
		for key, child := range typed {
			out.object[key] = parseMask(path+"."+key, child, true, errs)
		}
		return out
	case []any:
		out := mask{kind: maskArray, array: make([]mask, len(typed))}
		for i, child := range typed {
			out.array[i] = parseMask(path+indexPath(i), child, true, errs)
		}
		return out
	default:
		// The producer put something here, so something is marked; the shape
		// just cannot be read. Degrading to "no mask" would disclose exactly
		// the value the producer asked to have protected, so this covers the
		// whole subtree instead.
		*errs = append(*errs, invalid(path, "must be a boolean, an object, or an array"))
		return mask{kind: maskFlag, flag: true}
	}
}

// marks reports whether this node or any descendant marks something. It decides
// presence: a key that appears only in a mask still exists, but a mask that
// marks nothing does not conjure one.
func (m mask) marks() bool {
	switch m.kind {
	case maskFlag:
		return m.flag
	case maskObject:
		for _, child := range m.object {
			if child.marks() {
				return true
			}
		}
	case maskArray:
		for _, child := range m.array {
			if child.marks() {
				return true
			}
		}
	}
	return false
}

// isSet reports whether this exact node is marked, as opposed to a descendant.
// Only a literal true marks the node it sits on.
func (m mask) isSet() bool { return m.kind == maskFlag && m.flag }

// masksDisagree reports whether two masks describe incompatible container
// shapes. It only matters where the value is absent, because there the shape
// comes from the masks themselves and there is no third opinion to settle it.
//
// Whether either mask actually marks anything is deliberately not considered.
// The node's shape is taken from whichever mask is an object, and that choice
// is independent of which mask marks, so a mask that claims nothing could
// otherwise take the shape and leave a differently shaped marking mask with
// nowhere to apply. merge re-checks marks() per flag, so widening here cannot
// mark anything a mask did not claim.
func masksDisagree(unknown, sensitive mask) bool {
	if !unknown.isContainer() || !sensitive.isContainer() {
		return false
	}
	return unknown.kind != sensitive.kind
}

// isContainer reports whether the mask describes a structure rather than
// marking a node outright.
func (m mask) isContainer() bool {
	return m.kind == maskObject || m.kind == maskArray
}

// contradicts reports whether a mask claims something beneath a value that
// cannot hold it — an object mask over a string, say, or an array mask over a
// null.
//
// Terraform derives its masks by walking the value, so their shapes always
// agree and this never fires on real output. But plan JSON reaches this package
// from coding agents and third-party tooling too, and there are only two ways
// to read a contradiction: as "nothing is marked", which discloses the value
// the producer asked to have protected, or as "this is marked", which withholds
// a value that may have been safe. Only the second is safe to be wrong about.
func contradicts(raw any, rawPresent bool, m mask) bool {
	if m.isSet() || !m.marks() {
		return false
	}
	if !rawPresent {
		// With no value here, the mask supplies the shape and cannot disagree
		// with it.
		return false
	}
	switch m.kind {
	case maskObject:
		_, ok := raw.(map[string]any)
		return !ok
	case maskArray:
		_, ok := raw.([]any)
		return !ok
	default:
		return false
	}
}

func (m mask) field(name string) mask {
	if m.kind != maskObject {
		return mask{}
	}
	return m.object[name]
}

func (m mask) at(i int) mask {
	if m.kind != maskArray || i < 0 || i >= len(m.array) {
		return mask{}
	}
	return m.array[i]
}

func (m mask) len() int {
	if m.kind != maskArray {
		return 0
	}
	return len(m.array)
}

func (m mask) keys() []string {
	if m.kind != maskObject {
		return nil
	}
	keys := make([]string, 0, len(m.object))
	for key := range m.object {
		keys = append(keys, key)
	}
	return keys
}

// merge combines a decoded plan value with its unknown and sensitive masks into
// a single tree.
//
// Three rules carry the milestone:
//
//   - An object's key set is the union of the keys in the value and in both
//     masks. A key that appears only in the unknown mask is present and
//     unknown; a key in none of the three is genuinely absent.
//   - A mask set on a node covers the whole subtree beneath it. For a sensitive
//     subtree the walk stops there, so its contents are never read and cannot be
//     retained.
//   - Only a literal true marks the node it sits on. A mask that merely
//     contains a marked descendant makes the node present, not marked.
func merge(raw any, rawPresent bool, unknown, sensitive mask) Value {
	if !rawPresent && !unknown.marks() && !sensitive.marks() {
		return Value{}
	}

	// With no value at this node the masks supply its shape, so neither can
	// contradict the value — but they can contradict each other, and building
	// the node from one of them would discard the other's claim in silence.
	disagree := !rawPresent && masksDisagree(unknown, sensitive)

	value := Value{
		present:   true,
		unknown:   unknown.isSet() || contradicts(raw, rawPresent, unknown) || (disagree && unknown.marks()),
		sensitive: sensitive.isSet() || contradicts(raw, rawPresent, sensitive) || (disagree && sensitive.marks()),
	}
	if value.sensitive || value.unknown {
		// Nothing readable exists here, so there is nothing to descend into.
		return value
	}

	if rawPresent {
		return mergeRaw(value, raw, unknown, sensitive)
	}
	return mergeFromMasks(value, unknown, sensitive)
}

// mergeRaw builds a value whose shape comes from the plan itself.
func mergeRaw(value Value, raw any, unknown, sensitive mask) Value {
	switch typed := raw.(type) {
	case nil:
		value.kind = KindNull
	case bool:
		value.kind, value.boolean = KindBool, typed
	case json.Number:
		value.kind, value.number = KindNumber, typed
	case string:
		value.kind, value.text = KindString, typed
	case []any:
		value.kind = KindArray
		value.array = mergeArray(typed, unknown, sensitive)
	case map[string]any:
		value.kind = KindObject
		value.object = mergeObject(typed, unknown, sensitive)
	default:
		// encoding/json with UseNumber produces nothing else.
		value.kind = KindNull
	}
	return value
}

// mergeFromMasks builds a value whose shape is known only from its masks, which
// happens when Terraform omits an unknown field from the value document.
func mergeFromMasks(value Value, unknown, sensitive mask) Value {
	switch {
	case unknown.kind == maskObject || sensitive.kind == maskObject:
		value.kind = KindObject
		value.object = mergeObject(nil, unknown, sensitive)
	case unknown.kind == maskArray || sensitive.kind == maskArray:
		value.kind = KindArray
		value.array = mergeArray(nil, unknown, sensitive)
	default:
		value.kind = KindNull
	}
	return value
}

// elementMask returns the mask covering element i.
//
// Terraform preserves positions when it writes an array mask, padding unmarked
// elements with false, so a mask array shorter than the value array does not
// describe its tail at all. An undescribed element is treated as marked, for
// the same reason a contradiction is.
//
// An absent key in an object mask is different and stays unmarked: Terraform
// omits unmarked keys there by design.
func elementMask(m mask, i, length int) mask {
	if m.kind == maskArray && m.len() < length && i >= m.len() {
		return mask{kind: maskFlag, flag: true}
	}
	return m.at(i)
}

func mergeObject(raw map[string]any, unknown, sensitive mask) map[string]Value {
	names := make([]string, 0, len(raw))
	for name := range raw {
		names = append(names, name)
	}
	names = append(names, unknown.keys()...)
	names = append(names, sensitive.keys()...)
	slices.Sort(names)
	names = slices.Compact(names)

	out := make(map[string]Value, len(names))
	for _, name := range names {
		child, present := raw[name]
		merged := merge(child, present, unknown.field(name), sensitive.field(name))
		if merged.State() == StateAbsent {
			continue
		}
		out[name] = merged
	}
	return out
}

func mergeArray(raw []any, unknown, sensitive mask) []Value {
	length := max(len(raw), max(unknown.len(), sensitive.len()))

	out := make([]Value, 0, length)
	for i := range length {
		var (
			child   any
			present bool
		)
		if i < len(raw) {
			child, present = raw[i], true
		}
		out = append(out, merge(child, present, elementMask(unknown, i, length), elementMask(sensitive, i, length)))
	}
	return out
}
