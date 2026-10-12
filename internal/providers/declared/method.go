package declared

import (
	"slices"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Argument is one argument a mapper reads a value for, described by what the
// method of that value depends on and the plan cannot say.
//
// The method of a KNOWN value follows what the configuration records about
// writing the argument, never the value alone: a provider writes its default
// into the plan as a known value, Terraform carries an unwritten value over
// from prior state -- and under lifecycle { ignore_changes } a written one too,
// in a plan whose configuration does not record the lifecycle block -- and each
// looks exactly like a value somebody wrote. Only the configuration, compared
// with the prior state, separates them, and only where it records anything.
type Argument struct {
	// Path is the argument as the configuration nests it: dotted, without
	// indexes, as ResourceChange.Stated spells it. Every segment before the last
	// is a block.
	Path string
	// Block reports that the argument itself can be written in block syntax:
	// a nested block, or an attribute a provider lets be written as blocks,
	// such as aws_security_group's ingress. A dynamic block can write one, and
	// Terraform's configuration does not record a dynamic block, so the
	// absence of a block proves nothing about whether it was written.
	Block bool
	// Computed reports that the provider may compute a value nobody wrote: an
	// Optional and Computed argument, or a Computed-only one. It matters only
	// to MethodFor, where a value that is not the default would otherwise be
	// one the plan cannot have produced; whether a value was carried from
	// state is decided by comparing the state with the plan, not by the schema.
	Computed bool
	// Required reports that the provider's schema requires the argument.
	// Terraform refuses a body that omits one, and no dynamic block writes an
	// attribute, so wherever the body holding it is recorded the argument is
	// written -- including by a configuration entry with no expressions, and
	// by a hand-written plan whose configuration lists only the references.
	Required bool
}

// Writing is what the configuration records about one argument.
type Writing int

const (
	// WritingUnrecorded means the plan does not record whether the author
	// wrote it.
	WritingUnrecorded Writing = iota
	// WritingWritten means the configuration writes it.
	WritingWritten
	// WritingUnwritten means the configuration records the place the argument
	// would be written, and it is not there.
	WritingUnwritten
)

// Writing reports what the configuration records about this argument.
//
// Written only on a positive record, which is the one reliable direction:
// block syntax and attribute syntax cannot both name one argument, so a name in
// the configuration is a name the author wrote. Unwritten only where an absence
// is itself a record: a top-level attribute of a declared resource, which no
// dynamic block can produce, or an attribute inside a block the configuration
// records. Everything else -- no configuration, a resource it omits, a block
// that may be dynamic, an attribute inside one -- is unrecorded.
func (a Argument) Writing(change terraformplan.ResourceChange) Writing {
	if !change.Declared && !change.Configured {
		return WritingUnrecorded
	}
	if change.Configured && change.States(a.Path) {
		return WritingWritten
	}
	if a.Block {
		return WritingUnrecorded
	}
	if parent, nested := cutLast(a.Path); nested && !(change.Configured && change.States(parent)) {
		// The block holding it is not recorded, and may be dynamic.
		return WritingUnrecorded
	}
	if a.Required {
		return WritingWritten
	}
	return WritingUnwritten
}

// Method returns how a KNOWN value the plan carries for this argument was
// established.
//
//   - Unrecorded: configuration-unrecorded, rather than reading as stated -- a
//     fallback of "stated" is exactly the defect this method exists to remove.
//     So is an argument written only from variables the plan does not resolve,
//     since one of them may be null.
//   - Written with a value: stated, unless the change keeps an existing object,
//     the plan carries the prior value, and the configuration records a
//     constant that is not it -- ignore_changes kept the state, and the value is
//     prior-state.
//   - Unwritten, or written as an expression that evaluates to null, which
//     Terraform treats exactly as unwritten: prior-state where the change keeps
//     an existing object and the plan carries its prior value; otherwise the
//     provider's default, on a new object or where the plan moves the value.
func (a Argument) Method(change terraformplan.ResourceChange) model.Method {
	return a.decide(change, nil)
}

// MethodFor is Method for a value the caller has compared with the provider's
// documented default -- null, for an argument that has none.
//
// A value the configuration does not record as written is never stated. An
// argument nobody wrote that the provider does not compute, holding a value
// that is not its default and not carried from state, is a shape no real plan
// has shown -- a hand-written plan whose configuration lists only the
// references makes it -- and the plan then does not record who wrote that
// value: configuration-unrecorded, not a default the value is not.
func (a Argument) MethodFor(change terraformplan.ResourceChange, isDefault bool) model.Method {
	return a.decide(change, &isDefault)
}

func (a Argument) decide(change terraformplan.ResourceChange, isDefault *bool) model.Method {
	writing := a.Writing(change)
	expression, recorded := change.Expression(a.Path)
	if writing == WritingWritten && recorded {
		switch expression.Evaluation {
		case terraformplan.EvaluationNull:
			writing = WritingUnwritten
		case terraformplan.EvaluationUnresolved:
			writing = WritingUnrecorded
		}
	}

	carried := Updates(change) && Carried(change, a.Path)
	switch writing {
	case WritingWritten:
		if carried && recorded && expression.Contradicted {
			return model.MethodPriorState
		}
		return model.MethodStated
	case WritingUnwritten:
		switch {
		case carried:
			return model.MethodPriorState
		case isDefault != nil && !*isDefault && !a.Computed:
			return model.MethodConfigurationUnrecorded
		}
		return model.MethodProviderDefault
	default:
		return model.MethodConfigurationUnrecorded
	}
}

// Carried reports that the plan keeps the value the object had at a path: the
// prior state and the planned value are both known there and equal. A block
// the path passes through is followed into its one element; where it holds
// other than one, the whole block is compared.
func Carried(change terraformplan.ResourceChange, path string) bool {
	before, after := change.Before, change.After
	for i, segment := range strings.Split(path, ".") {
		if i > 0 && (before.Kind() == terraformplan.KindArray || after.Kind() == terraformplan.KindArray) {
			if before.Len() != 1 || after.Len() != 1 {
				break
			}
			before, after = before.At(0), after.At(0)
		}
		before, after = before.Field(segment), after.Field(segment)
	}
	return equal(before, after)
}

// equal reports that two values are both known, wholly, and the same.
func equal(a, b terraformplan.Value) bool {
	if a.State() != terraformplan.StateKnown || b.State() != terraformplan.StateKnown || a.Kind() != b.Kind() {
		return false
	}
	switch a.Kind() {
	case terraformplan.KindNull:
		return true
	case terraformplan.KindBool:
		return a.Bool() == b.Bool()
	case terraformplan.KindNumber:
		return a.Number() == b.Number()
	case terraformplan.KindString:
		return a.Text() == b.Text()
	case terraformplan.KindArray:
		if a.Len() != b.Len() {
			return false
		}
		for i := range a.Len() {
			if !equal(a.At(i), b.At(i)) {
				return false
			}
		}
		return true
	case terraformplan.KindObject:
		keys := a.Keys()
		if !slices.Equal(keys, b.Keys()) {
			return false
		}
		for _, key := range keys {
			if !equal(a.Field(key), b.Field(key)) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// Updates reports that the change keeps an existing object: it has a prior
// state and creates nothing. A replacement creates a new object, and a new
// object carries nothing over.
func Updates(change terraformplan.ResourceChange) bool {
	if change.Before.Kind() != terraformplan.KindObject {
		return false
	}
	for _, action := range change.Actions {
		if action == terraformplan.ActionCreate || action == terraformplan.ActionDelete {
			return false
		}
	}
	return true
}

// Weakest returns the method of the least established of several inputs one
// fact rests on.
//
// The order is fixed and documented, because the method is a public format:
// configuration-unrecorded, then prior-state, then provider-default, then any
// method this build derived (an interpreted document, a table, a reference),
// then plan-stated-value. The configuration's ways of not knowing come first:
// a value the plan cannot attribute to anyone is weaker than one it carried
// from state, which nobody under review wrote, and that is weaker than a
// documented default the author accepted by writing nothing.
//
// A method outside the closed set, the empty one included, is ranked nowhere:
// the result is then empty, which fails validation at the bundle boundary
// rather than hiding a mapper that forgot to say how it knows.
//
// Where a fact rests on an interpreted policy document, the mappers keep the
// document's method rather than calling this: the document is what the finding
// cites, and the product decision recorded in milestone 10 is that a defaulted
// gate beside it does not show.
func Weakest(methods ...model.Method) model.Method {
	return rank(methods, func(candidate, current int) bool { return candidate < current })
}

// Strongest returns the method of the best of several proofs, any one of which
// settles a fact on its own. A disjunctive grant needs only one, and the finding
// can cite the one that is best established; the order is Weakest's, and so is
// the answer to a method outside the closed set.
func Strongest(methods ...model.Method) model.Method {
	return rank(methods, func(candidate, current int) bool { return candidate > current })
}

func rank(methods []model.Method, better func(candidate, current int) bool) model.Method {
	if len(methods) == 0 {
		// Nothing to rest on is not a stated value; the zero method fails
		// validation, so a caller that forgot its inputs fails closed.
		return ""
	}
	chosen := methods[0]
	for _, method := range methods {
		if strength(method) < 0 {
			return ""
		}
		if better(strength(method), strength(chosen)) {
			chosen = method
		}
	}
	return chosen
}

// strength ranks the methods a mapper assigns, and -1 for anything else.
func strength(method model.Method) int {
	switch method {
	case model.MethodConfigurationUnrecorded:
		return 0
	case model.MethodPriorState:
		return 1
	case model.MethodProviderDefault:
		return 2
	case model.MethodPolicyDocument, model.MethodDocumentedTable, model.MethodReferenceResolved:
		return 3
	case model.MethodStated:
		return 4
	default:
		return -1
	}
}

func cutLast(path string) (string, bool) {
	cut := strings.LastIndex(path, ".")
	if cut < 0 {
		return "", false
	}
	return path[:cut], true
}
