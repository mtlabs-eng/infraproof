package declared

import (
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
	// Required reports that the provider's schema requires the argument.
	// Terraform refuses a body that omits one, and no dynamic block writes an
	// attribute, so wherever the body holding it is recorded the argument is
	// written -- including by a configuration entry with no expressions, and
	// by a hand-written plan whose configuration lists only the references.
	Required bool
	// Key is the key of a map argument the verdict reads, such as the
	// environment in tags, or empty where the verdict reads the argument
	// whole. The method is then decided at the key: what was written there,
	// and whether the plan keeps the value there. Under
	// ignore_changes = [tags["environment"]] the state keeps one key while
	// the configuration moves another, and the map as a whole is neither the
	// configuration's nor the state's.
	Key string
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
// established, decided at the place the verdict reads: the argument, or its Key.
//
//   - Unrecorded: configuration-unrecorded, rather than reading as stated -- a
//     fallback of "stated" is exactly the defect this method exists to remove.
//     So is an argument written only from variables the plan does not resolve,
//     since one of them may be null.
//   - Written with a value, on a new object: stated.
//   - Written as a constant the plan's value is provably not, on an update or
//     no-op: prior-state, whether or not the plan moves the value. Under
//     ignore_changes the state's value stands where the configuration wrote
//     another, and the plan's configuration does not record the lifecycle
//     block; a provider that canonicalizes a constant reads the same way, which
//     understates it.
//   - Written with a value, where the plan moves the value: stated.
//     ignore_changes keeps the prior value, so a value the plan moves is the
//     one the configuration evaluates to.
//   - Written with a value, where the change keeps an existing object and the
//     plan keeps the value it had: stated only where the configuration records
//     a constant -- in block syntax, every attribute written in the block, and
//     nothing the block does not write holding a value -- that the plan's
//     value is shown to be. Anything else -- a reference, a variable, a
//     function, an attribute written in several blocks, a write the
//     configuration records no expression for, a comparison with a value the
//     plan withholds or does not know -- is configuration-unrecorded: a write
//     that evaluates to what the object already had is unrecorded too, which
//     is the cost of the decision recorded in milestone 10.
//   - Unwritten, or written as an expression that evaluates to null, which
//     Terraform treats exactly as unwritten: prior-state where the change keeps
//     an existing object and the plan keeps its prior value; otherwise the
//     provider's default, on a new object or where the plan moves the value.
func (a Argument) Method(change terraformplan.ResourceChange) model.Method {
	return a.decide(change, nil)
}

// MethodFor is Method for a value the caller has compared with the provider's
// documented default -- null, for an argument that has none.
//
// It is for an argument the provider does not compute, which is every caller
// here. A value the configuration does not record as written is never stated:
// an unwritten argument holding a value that is not its default and not carried
// from state is a shape no real plan has shown -- a hand-written plan whose
// configuration lists only the references makes it -- and the plan then does
// not record who wrote that value: configuration-unrecorded, not a default the
// value is not.
func (a Argument) MethodFor(change terraformplan.ResourceChange, isDefault bool) model.Method {
	return a.decide(change, &isDefault)
}

func (a Argument) decide(change terraformplan.ResourceChange, isDefault *bool) model.Method {
	writing := a.Writing(change)
	expression, recorded := change.Expression(a.Path)
	if !recorded {
		// Block syntax: what is written inside the block.
		expression, recorded = change.Block(a.Path)
	}
	path := a.Path
	if a.Key != "" {
		path += "." + a.Key
		expression = expression.Element(a.Key)
	}
	if writing == WritingWritten && recorded {
		switch expression.Evaluation {
		case terraformplan.EvaluationNull:
			writing = WritingUnwritten
		case terraformplan.EvaluationUnresolved:
			writing = WritingUnrecorded
		}
	}

	updates := Updates(change)
	carried := updates && Carried(change, path)
	switch writing {
	case WritingWritten:
		constant := expression.Evaluation == terraformplan.EvaluationConstant
		switch {
		case !updates:
			return model.MethodStated
		case constant && expression.Contradicted:
			return model.MethodPriorState
		case !carried:
			return model.MethodStated
		case !constant || expression.Undecided:
			// The plan records no value for the write to be shown to be the
			// one the update keeps. A write the configuration records no
			// expression for is the zero Expression, which is deferred.
			return model.MethodConfigurationUnrecorded
		}
		return model.MethodStated
	case WritingUnwritten:
		switch {
		case carried:
			return model.MethodPriorState
		case isDefault != nil && !*isDefault:
			return model.MethodConfigurationUnrecorded
		}
		return model.MethodProviderDefault
	default:
		return model.MethodConfigurationUnrecorded
	}
}

// Carried reports that the plan keeps the value the object had at a path:
// the prior state holds the same value there, compared as the plan wrote both
// before any sensitive mark was applied (terraformplan.Value.Carried). A block
// the path passes through is followed into its one element; where either side
// holds other than one, the answer is the whole block's.
func Carried(change terraformplan.ResourceChange, path string) bool {
	before, after := change.Before, change.After
	for i, segment := range strings.Split(path, ".") {
		if i > 0 && after.Kind() == terraformplan.KindArray {
			if before.Len() != 1 || after.Len() != 1 {
				return after.Carried()
			}
			before, after = before.At(0), after.At(0)
		}
		before, after = before.Field(segment), after.Field(segment)
	}
	return after.Carried()
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
