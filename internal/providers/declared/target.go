package declared

import (
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
		if !strings.HasPrefix(reference.Target, targetType+".") &&
			!strings.Contains(reference.Target, "."+targetType+".") {
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
