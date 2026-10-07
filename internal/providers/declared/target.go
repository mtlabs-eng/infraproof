package declared

import (
	"slices"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Correlation describes how well a plan pins down the resource an attribute
// names.
//
// The zero value is CorrelationUndecidable, for the reason ReachUnreadable is
// Reach's: a correlation nobody managed to decide must never be mistaken for one
// that was decided. Absent is a decision -- it lets a caller fall back to the
// attribute's own value -- and undecidable is not.
type Correlation uint8

const (
	// CorrelationUndecidable means the plan names a resource and not which
	// instance of it, or names more than one.
	CorrelationUndecidable Correlation = iota
	// CorrelationNamed means the plan pins down one instance.
	CorrelationNamed
	// CorrelationAbsent means the attribute refers to no resource of that type,
	// so there is nothing to correlate and the caller may read the value.
	CorrelationAbsent
)

// String names a correlation for a diagnostic.
func (c Correlation) String() string {
	switch c {
	case CorrelationNamed:
		return "one instance"
	case CorrelationAbsent:
		return "no reference"
	default:
		return "undecidable"
	}
}

// Target names the resource instance an attribute refers to.
//
// It exists because an attribute holding another resource's identifier is
// unknown until apply, so correlating two resources through it has to go through
// the references the configuration records. That much the storage path has done
// since milestone 04. What a hand-rolled version in one mapper missed is the
// third answer: a reference carries the target's address with its count and
// for_each keys stripped, and the keys are the only thing separating one instance
// from its sibling.
//
// The consequence of missing it, measured on a real plan: a deny firewall on
// google_compute_network.vpc["b"] was read as applying to a firewall on
// vpc["a"], and used to prove a grant of SSH from 0.0.0.0/0 closed.
//
// More than one reference on the attribute is undecidable rather than the first
// one found -- a conditional names both branches and the plan does not say which
// it resolves to. A reference naming no instance of a target the plan declares as
// repeated is undecidable for the same reason: count.index produces no key.
func Target(change terraformplan.ResourceChange, attribute, targetType string,
	scope []terraformplan.ResourceChange) (string, Correlation) {

	var found []terraformplan.ExpressionReference
	for _, reference := range change.References {
		if reference.Attribute != attribute {
			continue
		}
		if !namesType(reference.Target, targetType) {
			// Another type on the same attribute answers a different question.
			continue
		}
		found = append(found, reference)
	}

	switch len(found) {
	case 0:
		return "", CorrelationAbsent
	case 1:
	default:
		// Two targets on one attribute. Picking either would be deciding a
		// conditional the plan deliberately left open.
		if !oneTarget(found) {
			return "", CorrelationUndecidable
		}
	}

	reference := found[0]
	if len(reference.TargetKeys) > 0 {
		// A reference that names an instance has answered.
		return keyed(reference.Target, reference.TargetKeys), CorrelationNamed
	}
	if repeatedInPlan(reference.Target, scope) {
		// The reference names the resource as a whole and the resource is
		// repeated, so it cannot reach one instance. A target the plan does not
		// contain is not repeated as far as anything here can tell, and the
		// reference reaches it.
		return "", CorrelationUndecidable
	}
	return reference.Target, CorrelationNamed
}

// namesType reports that an address is of a resource type, at the root or inside
// a module. Written once because Target and Targets must agree about it.
func namesType(target, resourceType string) bool {
	return strings.HasPrefix(target, resourceType+".") ||
		strings.Contains(target, "."+resourceType+".")
}

// oneTarget reports that several references all name the same instance, which
// Terraform produces when one argument reads two attributes of one resource.
func oneTarget(references []terraformplan.ExpressionReference) bool {
	first := keyed(references[0].Target, references[0].TargetKeys)
	for _, reference := range references[1:] {
		if keyed(reference.Target, reference.TargetKeys) != first {
			return false
		}
	}
	return true
}

// keyed writes an instance identity the way a plan address spells it, so two
// references to one instance produce one string.
func keyed(target string, keys []string) string {
	identity := target
	for _, key := range keys {
		identity += `["` + key + `"]`
	}
	return identity
}

// repeatedInPlan reports that the plan declares the target with count or
// for_each, whether or not every instance reached the plan.
//
// DeclaredRepeated rather than counting instances: a repeated resource with one
// instance in the plan is not the same as a resource declared once, because the
// reference may have meant an instance that is absent.
func repeatedInPlan(target string, scope []terraformplan.ResourceChange) bool {
	for _, change := range scope {
		if change.ConfigAddress() != target {
			continue
		}
		if change.DeclaredRepeated || change.HasIndex {
			return true
		}
	}
	return false
}

// Targets names every resource instance a list-valued attribute refers to.
//
// Target's plural. The difference is the attribute's arity, which the caller
// knows and this cannot: two references on `network` are a conditional the plan
// left open, and two on `vpc_security_group_ids` are two security groups that
// both gate the database. Reading a list through Target reported every database
// with more than one group as undecidable.
//
// Undecidable if *any* reference cannot be placed, because a partial allow list
// is not an allow list: a gate nobody can name could be the one that admits
// everything, so the set stays open rather than being answered from the part of
// it that was readable.
//
// That refusal covers a reference naming no instance of a repeated target. It
// cannot cover a reference the configuration dropped before this saw it -- a
// variable, a local, a module output -- because those are not references by the
// time they arrive. `ResourceChange.Opaque` records that loss and the caller asks
// about it; this function only ever sees resources.
//
// A conditional inside a list element names both of its branches on the
// attribute, and a list literal naming two resources does the same. The
// configuration does not distinguish them, so both are returned: a gate can only
// open the question, never close it, so taking both over-reports rather than
// hiding anything. A caller presenting the set as exact is the thing that would
// be wrong, which is why the AWS mapper bounds it.
//
// Sorted, so a plan's reference order -- which is JSON order -- cannot change a
// bundle.
func Targets(change terraformplan.ResourceChange, attribute, targetType string,
	scope []terraformplan.ResourceChange) ([]string, Correlation) {

	var named []string
	var found bool
	for _, reference := range change.References {
		if reference.Attribute != attribute || !namesType(reference.Target, targetType) {
			continue
		}
		found = true
		if len(reference.TargetKeys) > 0 {
			named = append(named, keyed(reference.Target, reference.TargetKeys))
			continue
		}
		if repeatedInPlan(reference.Target, scope) {
			// A splat over a repeated target reaches no one instance.
			return nil, CorrelationUndecidable
		}
		named = append(named, reference.Target)
	}
	if !found {
		return nil, CorrelationAbsent
	}

	slices.Sort(named)
	return slices.Compact(named), CorrelationNamed
}

// Resolve turns a reference identity into the address the plan spells it with.
//
// A reference names a resource the way the configuration does and the graph holds
// it the way the plan does, and the two differ in two ways that both produced
// wrong answers. A module instance key is in the plan address and not in the
// reference target, so a database written as a module per database lost its gate
// and the evidence cited an address appearing nowhere in the plan. And a `count`
// index is bare in a plan address while an identity quotes every key, so
// `counted[0]` was looked up as `counted["0"]` and never found.
//
// Resolving against the plan's own changes settles both, because the plan is what
// spells them. The match is the configuration address, the caller's own module
// instance, and the identity's own keys -- which is the discipline the storage
// path's correlation already follows, here applied to the other end of it.
//
// Not found means the plan does not contain the resource: a security group
// managed in another plan, which a caller reports as a gate it cannot read rather
// than as an absence. More than one match is also not found, because picking
// either would gate a database by a resource chosen at random.
func Resolve(subject terraformplan.ResourceChange, identity string,
	scope []terraformplan.ResourceChange) (string, bool) {

	target, keys := splitKeys(identity)

	var found string
	var matches int
	for _, candidate := range scope {
		if candidate.ConfigAddress() != target {
			continue
		}
		if !slices.Equal(candidate.ModuleKeys(), subject.ModuleKeys()) {
			// A sibling module instance. Each has its own, and taking the wrong
			// one gates the wrong database.
			continue
		}
		if !matchesKeys(candidate, subject, keys) {
			continue
		}
		found = candidate.Address
		matches++
	}
	// Exactly one. Zero is a resource the plan does not contain -- a security
	// group managed elsewhere -- which a caller reports as a gate it cannot
	// read. More than one cannot happen, because a configuration address, a
	// module instance and an instance key together are a plan address and a plan
	// holds each once; the guard is there so that if that ever stops being true,
	// nothing picks a resource at random.
	if matches != 1 {
		return "", false
	}
	return found, true
}

// matchesKeys reports that a candidate is the instance an identity names.
//
// The identity's keys are the ones the reference carried beyond the module's, so
// they are compared against the candidate's instance keys past the module's. A
// reference naming no key reaches a candidate that has none of its own.
func matchesKeys(candidate, subject terraformplan.ResourceChange, keys []string) bool {
	own := candidate.InstanceKeys()
	if shared := len(subject.ModuleKeys()); shared <= len(own) {
		own = own[shared:]
	}
	if len(keys) == 0 {
		return len(own) == 0
	}
	return slices.Equal(own, keys)
}

// splitKeys takes an identity apart into the address the configuration uses and
// the keys the reference added, which keyed put there.
func splitKeys(identity string) (string, []string) {
	var keys []string
	for {
		open := strings.LastIndex(identity, `["`)
		if open < 0 || !strings.HasSuffix(identity, `"]`) {
			return identity, keys
		}
		keys = append([]string{identity[open+2 : len(identity)-2]}, keys...)
		identity = identity[:open]
	}
}
