package model

// Family groups resources whose semantics a rule can reason about together.
type Family string

const (
	// FamilyObjectStorage covers buckets, containers and the controls over
	// them.
	FamilyObjectStorage Family = "object_storage"
	// FamilyNetwork covers the ingress rule sets that decide who can reach a
	// resource: security groups, network security groups, firewalls, and the
	// rule resources that belong to them.
	FamilyNetwork Family = "network"
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
	// ReadOnly reports that the entry describes a data source: something the
	// plan reads rather than changes.
	//
	// A verdict is about a change. A data source of a type a mapper
	// understands would otherwise be normalized as a subject and judged, so
	// reading an existing production bucket became an environment mismatch,
	// and reading one became a required unknown asking a read to prove its
	// exposure. It is kept in the graph, because a plan's contents are not
	// filtered, and it decides nothing.
	ReadOnly bool
	// UnrecognizedAction reports that the change names an operation this build
	// does not know.
	//
	// Destructive is read from the actions, so an unfamiliar verb would make a
	// change look like one that destroys nothing. A rule must decline to
	// conclude rather than treat it as safe.
	UnrecognizedAction bool
	// GovernsWithheld reports that every subject this control governs is one
	// the verdict may not read — a data source. Its meaning went somewhere,
	// and nowhere admissible.
	GovernsWithheld bool
	// DefersTo names the subjects a control resource's meaning belongs to, by
	// address, in deterministic order.
	//
	// It is empty for a subject, and it is empty for a control whose subject is
	// not in this plan — a policy attached to a bucket managed elsewhere. That
	// second case is why the field exists: a control is understood, and a rule
	// reaching no verdict about it is correct only when something else reached
	// one about the thing it governs. Without the link recorded here, "its
	// meaning belongs to the subject" is a claim nothing can check.
	DefersTo []string
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
	// ObjectStorage and Network hold the normalized capabilities of their
	// family, and are nil for a resource of another family or for an opaque one.
	// Nil means "not interpreted", never "nothing to worry about".
	ObjectStorage *ObjectStorageCapabilities
	Network       *NetworkCapabilities
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
	// Withdrawn reports that PublicAccess was determined and then unset,
	// because the answer was reached by choosing between a source this build
	// may use and one it may not.
	//
	// The state alone cannot carry this. "The plan never determined it" is
	// bounded by what the contract asked to be proved, and rightly so: an
	// author who declared nothing is not waiting on evidence of privacy.
	// "Something was determined and this build declined to use it" is a
	// different fact, and collapsing the two let a plan that provably grants
	// public access report that it is consistent with the contract in every
	// supported check.
	Withdrawn bool
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
	//
	// No plan value means no resource address either. An address holds a
	// for_each key, an author writes that key, and a free-text field is
	// rendered as prose — which turned a key into a live image reference in a
	// report this build exists to keep offline. What a reader needs is the
	// location, and Sources is the field that carries one.
	Reason string
	// Sources locates the resources this control concerns, when there are any
	// to point at. A gap that is an absence has none: nothing is there to
	// locate.
	Sources []Provenance
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
