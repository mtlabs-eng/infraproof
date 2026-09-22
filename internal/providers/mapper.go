package providers

import (
	"slices"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Mapper interprets one provider's resources.
//
// Implementations live in subpackages and depend only on the model and the
// plan types, never on this package, so the registry below can assemble them
// without a cycle.
type Mapper interface {
	// Cloud is the cloud this mapper interprets.
	Cloud() model.Cloud
	// Interprets reports whether the mapper understands a resource type at all,
	// including the control resources it folds into a subject.
	Interprets(resourceType string) bool
	// IsSubject reports whether a resource type is one this mapper normalizes
	// in its own right, as opposed to a control over another resource.
	IsSubject(resourceType string) bool
	// Map normalizes a subject.
	//
	// related holds the changes joined to the subject by a configuration
	// reference, in either direction.
	// scope holds every change in the plan, because some controls — an
	// account-wide block, for instance — refer to nothing and still decide the
	// answer.
	Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource
}

// Governor is implemented by a mapper whose resources govern subjects the
// configuration does not connect them to by reference.
//
// The default is reference-based, which is right for a control naming the
// bucket it applies to. It is wrong for a control that applies by something
// else: an account-wide block governs every bucket in its provider instance and
// names none of them, and a storage account governs the containers that name
// it rather than the other way round. In both cases the mapper is the only
// thing that knows, so the mapper is asked.
type Governor interface {
	// Governs returns the addresses of the subjects this resource's meaning
	// belongs to, beyond those the configuration connects it to.
	Governs(resource terraformplan.ResourceChange, scope []terraformplan.ResourceChange) []string
}

// Normalize builds the graph. Every change in the plan appears in it: a subject
// with its capabilities, a control resource marked as understood, and anything
// no mapper claimed as an opaque entry.
func Normalize(plan terraformplan.Plan, mappers []Mapper) model.Graph {
	scope := plan.ResourceChanges
	edges, unresolved := relate(scope, mappers)

	graph := model.Graph{Resources: make([]model.NormalizedResource, 0, len(scope))}
	for _, change := range scope {
		resource := normalizeOne(change, edges, scope, mappers)
		if unresolved[change.Address] && resource.ObjectStorage != nil {
			// Saying only "undetermined" would leave a reader with nowhere to
			// go. Naming the reason lets them fix it: an argument that names
			// the instance outright — b["a"] rather than b[each.key] — is
			// resolvable, and this says so.
			resource.ObjectStorage.Unresolved = append(resource.ObjectStorage.Unresolved, model.MissingControl{
				CheckID: "CORRELATION_UNRESOLVED",
				Reason: "A resource repeated alongside this one refers to it without naming an instance, " +
					"so the plan does not record which of them applies here.",
				Cloud: resource.Cloud,
			})
		}
		graph.Resources = append(graph.Resources, resource)
	}
	return graph
}

func normalizeOne(change terraformplan.ResourceChange, edges map[string][]terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange, mappers []Mapper) model.NormalizedResource {

	for _, mapper := range mappers {
		if !mapper.Interprets(change.Type) {
			continue
		}
		if !mapper.IsSubject(change.Type) {
			// A control resource is understood, but its meaning belongs to the
			// subject it controls rather than to itself. Which subject is
			// recorded, because "it was judged through its subject" is a claim
			// nothing downstream can check without it — and a control whose
			// subject is managed elsewhere defers to nobody.
			return model.NormalizedResource{
				Address:     change.Address,
				Provider:    change.ProviderName,
				Cloud:       mapper.Cloud(),
				Family:      model.FamilyObjectStorage,
				Destructive: change.IsDestructive(),
				Interpreted: true,
				DefersTo:    defersTo(change, edges[change.Address], scope, mapper),
			}
		}
		resource := mapper.Map(change, edges[change.Address], scope)
		resource.Interpreted = true
		if resource.ObjectStorage == nil {
			// A subject that reached no verdict of its own has deferred to
			// something. An Azure account with a container in the plan is the
			// case: the container carries the verdict and the account defers.
			resource.DefersTo = defersTo(change, edges[change.Address], scope, mapper)
		}
		return resource
	}

	return model.NormalizedResource{
		Address:     change.Address,
		Provider:    change.ProviderName,
		Cloud:       model.CloudUnknown,
		Family:      model.FamilyUnknown,
		Destructive: change.IsDestructive(),
	}
}

// defersTo returns the addresses whose judgement answers for this resource.
//
// A control resource's meaning belongs to the subject it governs, and so does a
// subject's when it reaches no verdict of its own. Recording which is what
// makes "it was judged through something else" a claim that can be checked
// rather than believed — and a resource governing something that is not in this
// plan defers to nobody.
func defersTo(change terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange,
	mapper Mapper) []string {

	var subjects []string
	for _, candidate := range related {
		// A control is not a subject. Two controls correlated through the
		// bucket they both name would otherwise vouch for each other, and the
		// question of whether anything judged them would never be answered.
		if mapper.IsSubject(candidate.Type) && candidate.Address != change.Address {
			subjects = append(subjects, candidate.Address)
		}
	}

	if governor, ok := mapper.(Governor); ok {
		for _, address := range governor.Governs(change, scope) {
			if address != change.Address {
				subjects = append(subjects, address)
			}
		}
	}

	slices.Sort(subjects)
	return slices.Compact(subjects)
}

// relate groups changes joined by a configuration reference, in both
// directions and instance by instance.
//
// Direction is not a property of the relationship, only of how a particular
// provider happens to write it. An S3 public access block names its bucket,
// while an Azure container names the storage account that gates it — the same
// control relationship, pointing opposite ways.
//
// Instances matter just as much. A reference targets a configuration address,
// which every instance of a repeated resource shares, so matching on it alone
// hands one bucket's public access block to its sibling. Two resources are
// related only when their instance keys agree as far as both have them.
func relate(changes []terraformplan.ResourceChange, mappers []Mapper) (map[string][]terraformplan.ResourceChange, map[string]bool) {
	byConfigAddress := map[string][]terraformplan.ResourceChange{}
	for _, change := range changes {
		address := change.ConfigAddress()
		byConfigAddress[address] = append(byConfigAddress[address], change)
	}

	edges := map[string][]terraformplan.ResourceChange{}
	unresolved := map[string]bool{}
	for _, change := range changes {
		for _, reference := range change.References {
			if !governs(change, reference, mappers) {
				continue
			}
			candidates := byConfigAddress[reference.Target]
			for _, target := range candidates {
				switch relates(change, target, reference, len(candidates)) {
				case relationUndecidable:
					// The reference reaches this target but cannot say which
					// instance of it. Recording that is what keeps the
					// resulting UNKNOWN actionable: the reader has something
					// to change.
					unresolved[change.Address] = true
					unresolved[target.Address] = true
				case relationBinds:
					edges[change.Address] = append(edges[change.Address], target)
					edges[target.Address] = append(edges[target.Address], change)
				}
			}
		}
	}

	for address, list := range edges {
		slices.SortStableFunc(list, func(a, b terraformplan.ResourceChange) int {
			return strings.Compare(a.Address, b.Address)
		})
		edges[address] = slices.CompactFunc(list, func(a, b terraformplan.ResourceChange) bool {
			return a.Address == b.Address
		})
	}
	return edges, unresolved
}

// orderingAttribute is the meta-argument Terraform writes an explicit ordering
// dependency under.
const orderingAttribute = "depends_on"

// governs reports whether a reference is a claim about what controls what,
// rather than merely a mention of one resource by another.
//
// Two references are not: an ordering dependency, which Terraform documents as
// sequencing alone and which says nothing about governance; and a reference in
// an argument that is not the one binding a control to its subject — a policy
// document interpolating a bucket's ARN mentions that bucket without being
// applied to it.
//
// Reading either as a correlation let a public-access block that names some
// other bucket by a literal string answer for this one, and turned a proven
// public bucket into a PASS. A correlation the configuration does not declare
// is not a correlation.
// Both halves are checked, and both are needed: the ordering rule holds for a
// type no mapper describes, and the binding rule holds for one that is.
func governs(change terraformplan.ResourceChange, reference terraformplan.ExpressionReference,
	mappers []Mapper) bool {

	if reference.Attribute == orderingAttribute {
		return false
	}

	binding, described := bindingAttributes(change.Type, mappers)
	switch {
	case !described:
		// No mapper describes this type. Every argument is admitted, because
		// narrowing what is not understood would drop correlations this build
		// cannot reason about either way.
		return true
	case len(binding) == 0:
		// A mapper describes it and says it binds by no argument: a subject in
		// its own right, or a control scoped to something that is not a
		// resource. Such a type makes no governance claims, so nothing it
		// writes is one.
		//
		// Keeping this apart from the case above is the whole point. Storing
		// both as "nothing is known" let a bucket's own tag reference stand as
		// a governance claim, and the same block that could no longer arrive
		// through depends_on walked back in from the other end of the edge —
		// an unstated fact matching another unstated fact.
		return false
	case isMetaArgument(reference.Attribute):
		// A control repeated over the resources it governs names them only
		// here: its own arguments refer to each.value, which names nothing.
		// The meta-argument carries the binding rather than replacing it, and
		// dropping it loses the only link there is.
		return true
	default:
		return slices.Contains(binding, reference.Attribute)
	}
}

// isMetaArgument reports the arguments Terraform uses to repeat a resource,
// which internal/terraformplan records references under for that reason.
func isMetaArgument(attribute string) bool {
	return attribute == "for_each" || attribute == "count"
}

// bindingAttributes returns the arguments that bind a control to the subject it
// governs, and whether any mapper describes the type at all.
//
// The two answers are separate because they license different behaviour: an
// undescribed type admits every argument, and a described one that binds by
// none makes no governance claims.
func bindingAttributes(resourceType string, mappers []Mapper) ([]string, bool) {
	for _, mapper := range mappers {
		if !mapper.Interprets(resourceType) {
			continue
		}
		binder, ok := mapper.(Binder)
		if !ok {
			// The mapper understands the type but has not said how it binds.
			// Its references are admitted, as before.
			return nil, false
		}
		return binder.BindingAttributes(resourceType), true
	}
	return nil, false
}

// Binder is implemented by a mapper that knows which argument binds one of its
// resource types to the subject it governs.
//
// The alternative is to admit every reference, which cannot distinguish a
// control applied to a bucket from one that merely names it. Only the provider
// knows which argument carries the application, so only the provider can say.
type Binder interface {
	// BindingAttributes returns the arguments binding this resource type to its
	// subject. A provider may accept more than one — an id or a name.
	//
	// Returning none is a statement, not a silence: this type binds to no
	// subject by reference, so nothing it writes is a claim about what governs
	// what. A subject in its own right returns none, and so does a control
	// scoped to something that is not a resource.
	BindingAttributes(resourceType string) []string
}

// relation is what a reference establishes about one candidate target. Not
// reaching a target and reaching it without being able to say which instance
// was meant are different facts, and only the second is worth reporting: the
// first is the configuration answering, the second is the configuration
// declining to.
type relation int

const (
	// relationNone: the reference does not reach this target at all.
	relationNone relation = iota
	// relationBinds: the configuration says this target is the one meant.
	relationBinds
	// relationUndecidable: the reference reaches this target, but which
	// instance of it cannot be derived from the plan.
	relationUndecidable
)

// relates reports whether a reference actually joins these two changes.
//
// The rule is exact where the plan is exact, and declines to guess where it is
// not. A reference naming an instance — aws_s3_bucket.b["a"] — joins that
// instance and no other. A bare reference joins by position, but only where
// position means something: either the target has a single instance, so there
// is nothing to choose between, or the referring resource is repeated at least
// as deeply as its target and the two were written to pair up, which is what
// "for_each = aws_s3_bucket.b" says.
//
// Pairing repeated resources by position is not decidable from a plan, so it is
// not attempted.
//
// The configuration block records which values take part in an expression,
// never how they are combined, and a string literal is not a value that takes
// part. So "b[each.key]" and "b[each.key == \"a\" ? \"z\" : \"a\"]" emit an
// identical reference list, as do "for_each = aws_s3_bucket.b" and a
// comprehension over it that permutes the keys. One pairs instance to instance
// and the other pairs every control with its sibling's bucket, and nothing in
// the plan tells them apart.
//
// What remains is what the plan does state: a reference that names an instance
// outright, a target with a single instance, and the module keys two resources
// share by sitting in the same module instance. Everything else is a question
// the plan leaves open, and CLAUDE.md is explicit about what to do with those.
func relates(from, to terraformplan.ResourceChange, reference terraformplan.ExpressionReference, candidates int) relation {
	if !sameInstance(from, to) {
		return relationNone
	}
	if len(reference.TargetKeys) > 0 {
		// A reference that names an instance has answered, both about the
		// instance it names and about the ones it excludes.
		if namesInstance(to, reference.TargetKeys) {
			return relationBinds
		}
		return relationNone
	}
	if candidates == 1 && !to.DeclaredRepeated {
		// One instance and one declared, so there is nothing to choose
		// between. A repeated resource with a single instance in the plan is
		// not the same thing: the reference may have meant one that is absent.
		return relationBinds
	}
	if len(from.InstanceKeys()) < len(to.InstanceKeys()) {
		// The target is repeated more deeply than the resource referring to
		// it, so the reference cannot carry enough keys to reach one instance.
		return relationUndecidable
	}
	// A target repeated in its own right needs the reference to say which
	// instance is meant. Repetition that comes only from an enclosing module is
	// different: those keys are shared by everything in the module instance and
	// cannot disagree.
	if hasOwnKey(to) {
		return relationUndecidable
	}
	return relationBinds
}

// hasOwnKey reports whether a resource is repeated in its own right, as opposed
// to sitting inside a repeated module. Only the first needs a reference to say
// which instance is meant: module keys are shared by everything in the module
// instance, so they cannot disagree.
func hasOwnKey(change terraformplan.ResourceChange) bool {
	return len(change.InstanceKeys()) > len(change.ModuleKeys())
}

// sameInstance reports whether two changes sit in the same repetition of their
// enclosing modules and, where both are repeated, the same repetition of
// themselves.
//
// Keys are compared as far as both have them, so an unrepeated control still
// pairs with a repeated bucket — a real shape — while two instances of one
// module never see into each other.
func sameInstance(a, b terraformplan.ResourceChange) bool {
	left, right := a.InstanceKeys(), b.InstanceKeys()
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// namesInstance reports whether a change is the instance a keyed reference
// names. The reference is written inside some module, so its keys describe the
// end of the address rather than the whole of it.
func namesInstance(change terraformplan.ResourceChange, keys []string) bool {
	actual := change.InstanceKeys()
	if len(actual) < len(keys) {
		return false
	}
	trailing := actual[len(actual)-len(keys):]
	for i := range keys {
		if trailing[i] != keys[i] {
			return false
		}
	}
	return true
}
