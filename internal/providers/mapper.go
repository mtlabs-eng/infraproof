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

// Normalize builds the graph. Every change in the plan appears in it: a subject
// with its capabilities, a control resource marked as understood, and anything
// no mapper claimed as an opaque entry.
func Normalize(plan terraformplan.Plan, mappers []Mapper) model.Graph {
	scope := plan.ResourceChanges
	edges := relate(scope)

	graph := model.Graph{Resources: make([]model.NormalizedResource, 0, len(scope))}
	for _, change := range scope {
		graph.Resources = append(graph.Resources, normalizeOne(change, edges, scope, mappers))
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
			// subject it controls rather than to itself.
			return model.NormalizedResource{
				Address:     change.Address,
				Provider:    change.ProviderName,
				Cloud:       mapper.Cloud(),
				Family:      model.FamilyObjectStorage,
				Destructive: change.IsDestructive(),
				Interpreted: true,
			}
		}
		resource := mapper.Map(change, edges[change.Address], scope)
		resource.Interpreted = true
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
func relate(changes []terraformplan.ResourceChange) map[string][]terraformplan.ResourceChange {
	byConfigAddress := map[string][]terraformplan.ResourceChange{}
	for _, change := range changes {
		address := change.ConfigAddress()
		byConfigAddress[address] = append(byConfigAddress[address], change)
	}

	edges := map[string][]terraformplan.ResourceChange{}
	for _, change := range changes {
		for _, reference := range change.References {
			for _, target := range byConfigAddress[reference.Target] {
				if !relates(change, target, reference) {
					continue
				}
				edges[change.Address] = append(edges[change.Address], target)
				edges[target.Address] = append(edges[target.Address], change)
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
	return edges
}

// relates reports whether a reference actually joins these two changes.
//
// The rule is exact where the plan is exact. A reference that names an instance
// — aws_s3_bucket.b["a"] — joins that instance and no other, however few keys
// the referring resource has of its own. Only a reference that names the
// resource as a whole falls back to pairing by position, which is what a
// meta-argument like "for_each = aws_s3_bucket.b" means.
//
// Reading a bare reference as "every instance" was the first defect here;
// reading a keyed one that way was the second. Both came from treating absent
// information as permission.
func relates(from, to terraformplan.ResourceChange, reference terraformplan.ExpressionReference) bool {
	if !sameInstance(from, to) {
		return false
	}
	if len(reference.TargetKeys) == 0 {
		return true
	}
	return namesInstance(to, reference.TargetKeys)
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
