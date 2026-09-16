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
	join := func(from, to terraformplan.ResourceChange) {
		if !sameInstance(from, to) {
			return
		}
		edges[from.Address] = append(edges[from.Address], to)
		edges[to.Address] = append(edges[to.Address], from)
	}

	for _, change := range changes {
		for _, reference := range change.References {
			for _, target := range byConfigAddress[reference.Target] {
				join(change, target)
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

// sameInstance reports whether two changes belong to the same repetition of
// their configuration.
//
// Keys are compared as far as both resources have them, so an unrepeated bucket
// still relates to controls created with for_each — a real and common shape —
// while two instances of one bucket never relate to each other's controls.
func sameInstance(a, b terraformplan.ResourceChange) bool {
	left, right := a.InstanceKeys(), b.InstanceKeys()
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
