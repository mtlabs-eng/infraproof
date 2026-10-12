package declared

import (
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Argument is one argument a mapper reads a value for, described by the two
// things the method of that value depends on and the plan cannot say.
//
// The method of a KNOWN value follows what the configuration records about
// writing the argument, never the value itself: a provider writes its default
// into the plan as a known value, and Terraform carries an unwritten Computed
// value over from prior state, and both look exactly like a value somebody
// wrote. Only the configuration separates them, and only where it records
// anything at all.
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
	// Computed reports that the provider keeps an unwritten value across an
	// update rather than planning it back to a default: an Optional and
	// Computed argument, or a Computed-only one.
	Computed bool
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
	parent, nested := cutLast(a.Path)
	if !nested {
		return WritingUnwritten
	}
	if change.Configured && change.States(parent) {
		return WritingUnwritten
	}
	return WritingUnrecorded
}

// Method returns how a KNOWN value the plan carries for this argument was
// established.
//
// A written argument is stated. An unwritten one is the provider's default,
// unless the change updates an object that already exists and the provider
// keeps the argument's value across an update: then the value is the one
// Terraform carried from prior state, which nobody wrote and which need not be
// the default. An unrecorded one says so, rather than reading as stated -- a
// fallback of "stated" is exactly the defect this method exists to remove.
func (a Argument) Method(change terraformplan.ResourceChange) model.Method {
	switch a.Writing(change) {
	case WritingWritten:
		return model.MethodStated
	case WritingUnwritten:
		if a.Computed && Updates(change) {
			return model.MethodPriorState
		}
		return model.MethodProviderDefault
	default:
		return model.MethodConfigurationUnrecorded
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
// Where a fact rests on an interpreted policy document, the mappers keep the
// document's method rather than calling this: the document is what the finding
// cites, and the product decision recorded in milestone 10 is that a defaulted
// gate beside it does not show.
func Weakest(methods ...model.Method) model.Method {
	weakest := model.MethodStated
	for _, method := range methods {
		if strength(method) < strength(weakest) {
			weakest = method
		}
	}
	return weakest
}

func strength(method model.Method) int {
	switch method {
	case model.MethodConfigurationUnrecorded:
		return 0
	case model.MethodPriorState:
		return 1
	case model.MethodProviderDefault:
		return 2
	case model.MethodStated:
		return 4
	default:
		return 3
	}
}

func cutLast(path string) (string, bool) {
	cut := strings.LastIndex(path, ".")
	if cut < 0 {
		return "", false
	}
	return path[:cut], true
}
