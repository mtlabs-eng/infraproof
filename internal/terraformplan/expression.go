package terraformplan

import (
	"strconv"
	"strings"
)

// Evaluation is what this build can tell, offline, about the value an
// argument's recorded expression evaluates to.
//
// It exists because a name in the configuration's expressions proves the
// author wrote the argument and not that the author wrote a value: an argument
// written as null -- a literal, or the module idiom of a variable that defaults
// to null -- is treated by Terraform exactly as an omitted one, and the plan
// then carries the provider's default or the prior value for it.
type Evaluation int

const (
	// EvaluationDeferred means the expression draws on something only
	// Terraform evaluates -- a resource, a local, a function of them -- or
	// only on variables the plan records as set. It is a written value.
	EvaluationDeferred Evaluation = iota
	// EvaluationConstant means the expression is a constant that is not null.
	EvaluationConstant
	// EvaluationNull means the expression evaluates to null: a literal null,
	// or only variables the plan records as null.
	EvaluationNull
	// EvaluationUnresolved means the expression draws only on variables and
	// the plan does not record whether they are null: a root variable missing
	// from `variables`, a module variable set to null beside a default (the
	// plan does not record `nullable`), or variables that disagree.
	EvaluationUnresolved
)

// Expression is what the configuration records about the value of one
// argument the author wrote, as far as this build evaluates it offline.
//
// Nothing the expression holds is kept. A constant can be a password and a
// variable's value a secret, so the parse reads them, concludes, and keeps only
// the conclusion.
type Expression struct {
	// Evaluation is what the expression evaluates to.
	Evaluation Evaluation
	// Contradicted reports that the expression is a constant and the value the
	// plan carries at the argument's path is provably not that constant.
	//
	// Terraform's `lifecycle { ignore_changes }` keeps the prior value in
	// `after` whatever the configuration writes, and the plan's configuration
	// does not record the lifecycle block, so this is the one trace it leaves.
	// For a block written in block syntax (see Block), it reports that the
	// planned blocks are not, one for one, blocks holding the constants
	// written in them.
	//
	// The comparison follows Terraform's encoding of a constant: an attribute
	// written as blocks records every attribute, null where nothing was
	// written, and Terraform plans an attribute nobody wrote as an empty value,
	// so null -- and, in a block written in block syntax, an attribute not
	// written at all -- matches only null, an empty list, map or string, or
	// false. A list is compared as a set; a number, a string and a bool match
	// by their text, as Terraform converts a constant to the argument's type.
	// Nothing else is normalized: a provider that canonicalizes a constant (a
	// protocol's case, a protocol number) contradicts it.
	Contradicted bool
	// Undecided reports that the expression is a constant and the comparison
	// could not be completed: a planned value where it is compared is not yet
	// known, or is withheld as sensitive, or the path names no single value.
	// It is never set beside Contradicted.
	Undecided bool
	// elements are the keys of a constant written as a map, each compared on
	// its own with the planned value at that key; nil for any other
	// expression.
	elements map[string]Expression
}

// Element returns what the configuration records at one key of an argument
// written as a map: a verdict that reads one key rests on what was written
// there, not on the whole map. A key the constant does not write is written as
// nothing, which is null. An argument written other than as a constant map
// records nothing per key, and the answer is the argument's own.
func (e Expression) Element(key string) Expression {
	if e.elements == nil {
		return e
	}
	if element, found := e.elements[key]; found {
		return element
	}
	return Expression{Evaluation: EvaluationNull}
}

// Expression returns what the configuration records about the value of an
// argument, by the path Stated spells it. False when the configuration does
// not record one expression for it: the argument is unwritten, is a block, or
// is written in more than one block.
func (c ResourceChange) Expression(path string) (Expression, bool) {
	expression, found := c.Expressions[path]
	return expression, found
}

// Block returns what the configuration records about a block written in block
// syntax, by the path Stated spells it, read from every attribute written in
// it at every depth: a constant only where each of them is a constant or null.
// Contradicted then reports that the blocks the plan carries at the path are
// not, one for one, blocks holding the constants written. False when no block
// is written there in block syntax, or the block is inside a repeated block.
func (c ResourceChange) Block(path string) (Expression, bool) {
	expression, found := c.Blocks[path]
	return expression, found
}

// moduleScope is what a module call records about the variables of the module
// it calls.
type moduleScope struct {
	parent string
	// inputs are the call's argument expressions, by variable name.
	inputs map[string]any
	// variables are the called module's variable declarations, by name.
	variables map[string]any
}

// evaluator resolves variables against what the plan records, and only that.
type evaluator struct {
	// root holds the plan's top-level `variables`, by name.
	root   map[string]any
	scopes map[string]moduleScope
}

func newEvaluator(document map[string]any, scopes map[string]moduleScope) evaluator {
	root, _ := document["variables"].(map[string]any)
	return evaluator{root: root, scopes: scopes}
}

// maxScopeDepth bounds the walk through module calls, which a well-formed plan
// never approaches and a malformed one must not turn into a loop.
const maxScopeDepth = 64

// variableState is what this build knows about one variable's value.
type variableState struct {
	evaluation Evaluation
	// raw is the value, for a variable the plan records a constant for.
	raw any
}

// expressions evaluates every recorded expression of one resource against one
// instance's after value.
func (e evaluator) expressions(raw map[string]any, module string, after Value) map[string]Expression {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]Expression, len(raw))
	for path, entry := range raw {
		expression, ok := entry.(map[string]any)
		if !ok {
			// Written in more than one block.
			continue
		}
		state := e.evaluate(expression, module, 0)
		recorded := Expression{Evaluation: state.evaluation}
		if state.evaluation == EvaluationConstant {
			value, single := valueAtPath(after, path)
			recorded.record(compareIf(single, func() comparison { return compare(state.raw, value) }))
			if written, isMap := state.raw.(map[string]any); isMap {
				recorded.elements = make(map[string]Expression, len(written))
				for key, element := range written {
					recorded.elements[key] = elementExpression(element, single, value.Field(key))
				}
			}
		}
		out[path] = recorded
	}
	return out
}

// elementExpression is what a constant map records at one key.
func elementExpression(element any, single bool, value Value) Expression {
	if element == nil {
		return Expression{Evaluation: EvaluationNull}
	}
	recorded := Expression{Evaluation: EvaluationConstant}
	recorded.record(compareIf(single, func() comparison { return compare(element, value) }))
	return recorded
}

// blocks evaluates every block one resource writes in block syntax against one
// instance's after value.
func (e evaluator) blocks(raw map[string]any, module string, after Value) map[string]Expression {
	out := make(map[string]Expression, len(raw))
	for path, entry := range raw {
		elements, ok := entry.([]map[string]any)
		if !ok {
			// Inside a repeated block.
			continue
		}
		written, constant := e.blockConstants(elements, module)
		if !constant {
			out[path] = Expression{Evaluation: EvaluationDeferred}
			continue
		}
		recorded := Expression{Evaluation: EvaluationConstant}
		value, single := valueAtPath(after, path)
		recorded.record(compareIf(single, func() comparison { return compareBlocks(written, value) }))
		out[path] = recorded
	}
	return out
}

// writtenBlocks is the constants written in a block's bodies: each attribute's
// constant, nil for one written as null, and a nested block as writtenBlocks.
type writtenBlocks []map[string]any

// blockConstants reads the constants written in a block's bodies. False when
// anything written in them, at any depth, is not a constant or null.
func (e evaluator) blockConstants(elements []map[string]any, module string) (writtenBlocks, bool) {
	out := make(writtenBlocks, 0, len(elements))
	for _, body := range elements {
		written := make(map[string]any, len(body))
		for name, entry := range body {
			var nested []map[string]any
			switch typed := entry.(type) {
			case map[string]any:
				if !isExpression(typed) {
					nested = []map[string]any{typed}
					break
				}
				state := e.evaluate(typed, module, 0)
				switch state.evaluation {
				case EvaluationConstant:
					written[name] = state.raw
				case EvaluationNull:
					written[name] = nil
				default:
					return nil, false
				}
				continue
			case []any:
				for _, element := range typed {
					if block, ok := element.(map[string]any); ok {
						nested = append(nested, block)
					}
				}
			default:
				continue
			}
			inner, constant := e.blockConstants(nested, module)
			if !constant {
				return nil, false
			}
			written[name] = inner
		}
		out = append(out, written)
	}
	return out, true
}

// comparison is the answer to whether a planned value is the constant written.
// The order is the order of strength: a contradiction anywhere decides, and
// anything the plan does not show leaves the answer undecided.
type comparison int

const (
	matched comparison = iota
	undecided
	contradicted
)

func (e *Expression) record(answer comparison) {
	e.Contradicted = answer == contradicted
	e.Undecided = answer == undecided
}

// compareIf compares where the path names a single planned value, and is
// undecided where it does not.
func compareIf(single bool, compare func() comparison) comparison {
	if !single {
		return undecided
	}
	return compare()
}

// notShown reports what comparing with a value the plan does not show
// answers, and false for a value it shows. A value it does not know or
// withholds cannot be compared; one it does not mention matches only
// nothing written.
func notShown(written any, value Value) (comparison, bool) {
	switch value.State() {
	case StateUnknown, StateRedacted:
		return undecided, true
	case StateAbsent:
		if written == nil {
			return matched, true
		}
		return contradicted, true
	default:
		return matched, false
	}
}

// compare answers whether a planned value is the constant the configuration
// records.
func compare(constant any, value Value) comparison {
	if answer, decided := notShown(constant, value); decided {
		return answer
	}
	switch typed := constant.(type) {
	case nil:
		// Nothing written here: Terraform plans an empty value for it.
		if empty(value) {
			return matched
		}
		return contradicted
	case []any:
		if value.Kind() != KindArray || value.Len() != len(typed) {
			return contradicted
		}
		return matchSet(len(typed), value, func(i int, planned Value) comparison {
			return compare(typed[i], planned)
		})
	case map[string]any:
		if value.Kind() != KindObject {
			return contradicted
		}
		for _, key := range value.Keys() {
			if _, recorded := typed[key]; !recorded {
				return contradicted
			}
		}
		answer := matched
		for key, element := range typed {
			answer = max(answer, compare(element, value.Field(key)))
		}
		return answer
	default:
		text, ok := scalarText(constant)
		if !ok {
			return undecided
		}
		same := false
		switch value.Kind() {
		case KindString:
			same = text == value.Text()
		case KindNumber:
			same = text == string(value.Number())
		case KindBool:
			same = text == strconv.FormatBool(value.Bool())
		}
		if same {
			return matched
		}
		return contradicted
	}
}

// empty reports a value Terraform plans for an attribute nobody wrote.
func empty(value Value) bool {
	switch value.Kind() {
	case KindNull:
		return true
	case KindArray, KindObject:
		return value.Len() == 0
	case KindString:
		return value.Text() == ""
	case KindBool:
		return !value.Bool()
	default:
		return false
	}
}

// matchSet pairs each of count written elements with a distinct element of a
// planned list, greedily: a planned element that matches first, one the plan
// does not show otherwise. A written element left with neither contradicts;
// one paired with an element the plan does not show leaves the answer
// undecided. Greedy pairing can miss a pairing that exists, which reads as a
// contradiction, never as a match.
func matchSet(count int, value Value, compare func(i int, planned Value) comparison) comparison {
	used := make([]bool, value.Len())
	answer := matched
	for i := range count {
		best, at := contradicted, -1
		for j := range value.Len() {
			if used[j] {
				continue
			}
			if candidate := compare(i, value.At(j)); candidate < best {
				best, at = candidate, j
				if candidate == matched {
					break
				}
			}
		}
		if at < 0 {
			return contradicted
		}
		used[at] = true
		answer = max(answer, best)
	}
	return answer
}

// compareBlocks answers whether the blocks a value holds are, one for one, the
// blocks written. A planned block carries every attribute of its schema, and
// Terraform plans the ones nobody wrote as empty values, so an attribute the
// written block does not hold is compared as written as nothing.
func compareBlocks(written writtenBlocks, value Value) comparison {
	if answer, decided := notShown(written, value); decided {
		return answer
	}
	if value.Kind() == KindObject {
		// A block of nesting_mode single.
		if len(written) != 1 {
			return contradicted
		}
		return compareBody(written[0], value)
	}
	if value.Kind() != KindArray || value.Len() != len(written) {
		return contradicted
	}
	return matchSet(len(written), value, func(i int, planned Value) comparison {
		return compareBody(written[i], planned)
	})
}

func compareBody(body map[string]any, value Value) comparison {
	if answer, decided := notShown(body, value); decided {
		return answer
	}
	if value.Kind() != KindObject {
		return contradicted
	}
	answer := matched
	for name, written := range body {
		field := value.Field(name)
		if nested, ok := written.(writtenBlocks); ok {
			answer = max(answer, compareBlocks(nested, field))
			continue
		}
		answer = max(answer, compare(written, field))
	}
	for _, name := range value.Keys() {
		if _, written := body[name]; !written {
			answer = max(answer, compare(nil, value.Field(name)))
		}
	}
	return answer
}

// evaluate reads one expression in a module's scope.
func (e evaluator) evaluate(expression map[string]any, module string, depth int) variableState {
	references, _ := expression["references"].([]any)
	if len(references) == 0 {
		constant, present := expression["constant_value"]
		switch {
		case !present:
			return variableState{evaluation: EvaluationDeferred}
		case constant == nil:
			return variableState{evaluation: EvaluationNull}
		default:
			return variableState{evaluation: EvaluationConstant, raw: constant}
		}
	}

	names := make([]string, 0, len(references))
	for _, reference := range references {
		text, ok := reference.(string)
		if !ok || !strings.HasPrefix(text, "var.") {
			// Something only Terraform evaluates takes part.
			return variableState{evaluation: EvaluationDeferred}
		}
		names = append(names, text)
	}

	nulls, values := 0, 0
	for _, reference := range mostSpecific(names) {
		switch e.reference(reference, module, depth).evaluation {
		case EvaluationNull:
			nulls++
		case EvaluationUnresolved:
			return variableState{evaluation: EvaluationUnresolved}
		default:
			values++
		}
	}
	switch {
	case values == 0:
		return variableState{evaluation: EvaluationNull}
	case nulls == 0:
		return variableState{evaluation: EvaluationDeferred}
	default:
		// Some null and some not: what the expression makes of them is
		// Terraform's to evaluate.
		return variableState{evaluation: EvaluationUnresolved}
	}
}

// mostSpecific drops each reference another one extends. Terraform lists the
// bare variable beside every attribute of it the expression reads, and the
// bare one says nothing the longer one does not.
func mostSpecific(references []string) []string {
	out := make([]string, 0, len(references))
	for _, candidate := range references {
		extended := false
		for _, other := range references {
			if len(other) > len(candidate) && strings.HasPrefix(other, candidate) &&
				(other[len(candidate)] == '.' || other[len(candidate)] == '[') {
				extended = true
				break
			}
		}
		if !extended {
			out = append(out, candidate)
		}
	}
	return out
}

// reference resolves `var.name` or `var.name.attribute...` in a module's
// scope.
func (e evaluator) reference(reference, module string, depth int) variableState {
	rest := strings.TrimPrefix(reference, "var.")
	name, traversal, _ := strings.Cut(rest, ".")
	if strings.Contains(name, "[") {
		// An index: which element is Terraform's to say.
		return variableState{evaluation: EvaluationUnresolved}
	}
	state := e.variable(name, module, depth)
	if traversal == "" || state.evaluation != EvaluationConstant {
		if traversal != "" && state.evaluation == EvaluationNull {
			// An attribute of null is an error Terraform would have raised
			// unless something guards it, and what the guard yields is not
			// recorded.
			return variableState{evaluation: EvaluationUnresolved}
		}
		return state
	}
	value := state.raw
	for _, attribute := range strings.Split(traversal, ".") {
		object, ok := value.(map[string]any)
		if !ok || strings.Contains(attribute, "[") {
			return variableState{evaluation: EvaluationUnresolved}
		}
		value, ok = object[attribute]
		if !ok {
			return variableState{evaluation: EvaluationUnresolved}
		}
	}
	if value == nil {
		return variableState{evaluation: EvaluationNull}
	}
	return variableState{evaluation: EvaluationConstant, raw: value}
}

// variable resolves one variable's value in a module's scope.
func (e evaluator) variable(name, module string, depth int) variableState {
	if depth > maxScopeDepth {
		return variableState{evaluation: EvaluationUnresolved}
	}
	if module == "" {
		entry, ok := e.root[name].(map[string]any)
		if !ok {
			return variableState{evaluation: EvaluationUnresolved}
		}
		value, present := entry["value"]
		switch {
		case !present:
			return variableState{evaluation: EvaluationUnresolved}
		case value == nil:
			return variableState{evaluation: EvaluationNull}
		default:
			return variableState{evaluation: EvaluationConstant, raw: value}
		}
	}

	scope, ok := e.scopes[module]
	if !ok {
		return variableState{evaluation: EvaluationUnresolved}
	}
	declaration, declared := scope.variables[name].(map[string]any)
	if !declared {
		return variableState{evaluation: EvaluationUnresolved}
	}
	defaultValue, hasDefault := declaration["default"]

	if input, set := scope.inputs[name].(map[string]any); set {
		state := e.evaluate(input, scope.parent, depth+1)
		if state.evaluation == EvaluationNull && hasDefault && defaultValue != nil {
			// Null for a nullable variable, the default for one declared
			// `nullable = false`, and the plan does not record which.
			return variableState{evaluation: EvaluationUnresolved}
		}
		return state
	}
	switch {
	case !hasDefault:
		return variableState{evaluation: EvaluationUnresolved}
	case defaultValue == nil:
		return variableState{evaluation: EvaluationNull}
	default:
		return variableState{evaluation: EvaluationConstant, raw: defaultValue}
	}
}

// valueAtPath walks a value along a configuration path, taking the one element
// of each block the path passes through. False when a block on the way holds
// other than one element, so the path names no single value.
func valueAtPath(value Value, path string) (Value, bool) {
	segments := strings.Split(path, ".")
	for i, segment := range segments {
		if i > 0 && value.Kind() == KindArray {
			if value.Len() != 1 {
				return Value{}, false
			}
			value = value.At(0)
		}
		value = value.Field(segment)
	}
	return value, true
}

func scalarText(constant any) (string, bool) {
	switch typed := constant.(type) {
	case string:
		return typed, true
	case bool:
		return strconv.FormatBool(typed), true
	case interface{ String() string }:
		return typed.String(), true
	default:
		return "", false
	}
}
