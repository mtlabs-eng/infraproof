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
	// plan carries at the argument's path is not that constant.
	//
	// Terraform's `lifecycle { ignore_changes }` keeps the prior value in
	// `after` whatever the configuration writes, and the plan's configuration
	// does not record the lifecycle block, so this is the one trace it leaves.
	// The comparison follows Terraform's encoding of a constant: an attribute
	// written as blocks records every attribute, null where nothing was
	// written, so a null matches anything; a list is compared as a set; a
	// number, a string and a bool match by their text, as Terraform converts a
	// constant to the argument's type. An unknown or withheld value is
	// never contradicted -- there is nothing to compare with.
	Contradicted bool
}

// Expression returns what the configuration records about the value of an
// argument, by the path Stated spells it. False when the configuration does
// not record one expression for it: the argument is unwritten, is a block, or
// is written in more than one block.
func (c ResourceChange) Expression(path string) (Expression, bool) {
	expression, found := c.Expressions[path]
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
			if value, single := valueAtPath(after, path); single {
				recorded.Contradicted = !constantMatches(state.raw, value)
			}
		}
		out[path] = recorded
	}
	return out
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

// constantMatches reports whether a value could be the constant the
// configuration records. It answers true wherever it cannot compare: the
// question it serves is whether the value is provably not the one written.
func constantMatches(constant any, value Value) bool {
	if value.State() != StateKnown {
		return true
	}
	switch typed := constant.(type) {
	case nil:
		// Nothing written here: an attribute written as blocks records every
		// attribute, null where the author wrote none.
		return true
	case []any:
		if value.Kind() != KindArray || value.Len() != len(typed) {
			return false
		}
		used := make([]bool, value.Len())
		for _, element := range typed {
			found := false
			for i := range value.Len() {
				if !used[i] && constantMatches(element, value.At(i)) {
					used[i], found = true, true
					break
				}
			}
			if !found {
				return false
			}
		}
		return true
	case map[string]any:
		if value.Kind() != KindObject {
			return false
		}
		for _, key := range value.Keys() {
			if _, recorded := typed[key]; !recorded {
				return false
			}
		}
		for key, element := range typed {
			field := value.Field(key)
			if element != nil && field.State() == StateAbsent {
				return false
			}
			if !constantMatches(element, field) {
				return false
			}
		}
		return true
	default:
		text, ok := scalarText(constant)
		if !ok {
			return true
		}
		switch value.Kind() {
		case KindString:
			return text == value.Text()
		case KindNumber:
			return text == string(value.Number())
		case KindBool:
			return text == strconv.FormatBool(value.Bool())
		default:
			return false
		}
	}
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
