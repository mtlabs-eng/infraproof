package model

// DatabaseCapabilities is the cloud-neutral view of a managed database's
// reachability.
//
// Reachability is the conjunction of two independent facts, and this keeps them
// apart rather than collapsing them into one verdict. A database has an endpoint
// outside the private network, or it does not; something admits every address to
// that endpoint, or nothing does. Neither alone is a finding -- an endpoint
// nobody is admitted to is not reachable, and an allow list in front of no
// endpoint reaches nothing -- and a reader whose plan holds one half has to be
// told which half is missing.
//
// They are also read from different places. The switch is an attribute of the
// database. The allow list may be part of it (GCP's authorized networks), a
// control resource joined to it (Azure's firewall rules), or a security group
// that is a subject in its own right, already judged by the network family
// (AWS). Only the last needs GatedBy.
type DatabaseCapabilities struct {
	// PublicEndpoint reports whether the change gives this database an endpoint
	// outside the private network.
	//
	// Known(true) means the change gives it one. Known(false) means the plan
	// proves it has none. Unknown means the deciding attribute is not in the
	// plan, or was written from something the plan cannot resolve.
	PublicEndpoint Fact[bool]
	// AdmitsAnyAddress reports whether the allow list admits every address.
	//
	// Answered here only where the allow list belongs to the database or to its
	// own control resources. Where it belongs to another subject, this is
	// Unknown and GatedBy names where the answer is.
	AdmitsAnyAddress Fact[bool]
	// GatedBy names the resources whose network capabilities answer
	// AdmitsAnyAddress instead of this field.
	//
	// Addresses rather than capabilities, so a mapper never depends on another
	// mapper and the model stays a description. The rule resolves them against
	// the graph, which is what the policy layer already does with DefersTo.
	//
	// An address not in the graph is a security group managed elsewhere, and
	// settles nothing.
	GatedBy []string
	// Port is the port this database listens on.
	//
	// Known only where the engine names it, because the port attribute itself is
	// Optional and Computed on every provider measured and comes back unknown on
	// every create. Unknown means the allow list cannot be compared against a
	// port, so any address admitted at all is reported as possibly reaching it --
	// wider than reality, and recorded as such.
	Port Fact[int]
	// Withdrawn reports that a determination was reached and then unset, because
	// it rested on a source this build may not use. ObjectStorageCapabilities
	// carries this for the same reason, and the reason is in its comment.
	Withdrawn bool
	// Unresolved names controls that could change the answer and are not in the
	// plan. They are recorded even when both facts are known, because they bound
	// how far the evidence reaches.
	Unresolved []MissingControl
}
