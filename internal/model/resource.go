package model

// Family groups resources whose semantics a rule can reason about together.
type Family string

const (
	// FamilyObjectStorage covers buckets, containers and the controls over
	// them.
	FamilyObjectStorage Family = "object_storage"
	// FamilyUnknown covers every resource no mapper claimed. Such a resource is
	// retained rather than dropped, and must never read as one that was
	// examined and found safe.
	FamilyUnknown Family = "unknown"
)

// NormalizedResource is one resource as the rules see it.
type NormalizedResource struct {
	// Address is the resource address from the plan, unchanged.
	Address string
	// Provider is the provider source address.
	Provider string
	// Cloud and Family say how much of the resource was understood.
	Cloud  Cloud
	Family Family
	// Destructive reports that the change destroys the existing object, which
	// covers a plain delete and both replace orderings.
	Destructive bool
	// Interpreted reports that a mapper understood this resource type. A
	// control resource is interpreted but carries no capabilities of its own,
	// because its meaning belongs to the resource it controls. The distinction
	// matters: "understood, and folded into something else" is not the same
	// claim as "no mapper recognized this".
	Interpreted bool
	// Environment is the environment the resource declares it belongs to,
	// normalized from whatever the provider calls it: an AWS or Azure tag, a
	// GCP label.
	//
	// Only an explicit declaration counts. A module named "staging" or a file
	// called staging.tfplan is a guess about a name, and
	// docs/INTENT-CONTRACT.md is explicit that guessing is not sufficient
	// evidence for blocking. An absent declaration is Absent, never the
	// contract's own environment: a resource that did not say where it belongs
	// has not agreed with anything.
	Environment Fact[string]
	// ObjectStorage holds the normalized capabilities, and is nil for an opaque
	// resource. Nil means "not interpreted", never "nothing to worry about".
	ObjectStorage *ObjectStorageCapabilities
}

// ObjectStorageCapabilities is the cloud-neutral view of an object store.
//
// Only public access is normalized. docs/ARCHITECTURE.md reserves encryption
// and deletion protection as product concepts, which is not an instruction to
// model them before a rule needs them.
type ObjectStorageCapabilities struct {
	// PublicAccess reports whether the change grants public access.
	//
	// Known(true) means the change grants it. Known(false) means the plan
	// proves it is prevented. Unknown means a control the answer depends on is
	// not in the plan — which, for AWS and GCP, is the common case rather than
	// an edge one.
	PublicAccess Fact[bool]
	// Unresolved names controls that could change the answer but are not in the
	// plan: an account-level block, an organization policy. They are recorded
	// even when PublicAccess is known, because they bound how far the evidence
	// reaches.
	Unresolved []MissingControl
}

// MissingControl is a control the plan does not contain.
type MissingControl struct {
	// CheckID is a stable identifier, suitable for an Evidence Bundle unknown.
	CheckID string
	// Reason explains the gap in one safe line, carrying no plan value.
	Reason string
	// Cloud is the cloud whose control is missing.
	Cloud Cloud
}

// Graph is the normalized view of a whole plan.
type Graph struct {
	// Resources holds every resource in the plan, in deterministic order.
	// Nothing is filtered: a resource no mapper understood is present as an
	// opaque entry.
	Resources []NormalizedResource
}

// At returns the resource at an address.
func (g Graph) At(address string) (NormalizedResource, bool) {
	for _, resource := range g.Resources {
		if resource.Address == address {
			return resource, true
		}
	}
	return NormalizedResource{}, false
}

// OfFamily returns every resource in a family, preserving graph order.
func (g Graph) OfFamily(family Family) []NormalizedResource {
	var out []NormalizedResource
	for _, resource := range g.Resources {
		if resource.Family == family {
			out = append(out, resource)
		}
	}
	return out
}
