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
	// Read from the plan where the plan states it, and otherwise from whatever
	// names the engine: a table of documented defaults on AWS and GCP, and the
	// resource type itself on Azure, where there is no engine attribute and no
	// port attribute either. PortInferred below says which.
	//
	// Unknown means the allow list cannot be compared against a port, so any
	// address admitted at all is reported as possibly reaching it -- wider than
	// reality, recorded as such, and reported as a required unknown rather than
	// as a finding, because a BLOCK may not rest on an approximation.
	//
	// This comment used to say the attribute is Optional and Computed on every
	// provider measured. Three ways wrong: AWS reads a stated port, Azure has no
	// engine to infer from, and two of the three providers have no such
	// attribute.
	Port Fact[int]
	// PortInferred reports that Port was read from a documented default rather
	// than stated by the plan.
	//
	// It exists because one disclosure turns on it. A database that reads as
	// unreachable *because* of its port carries DATABASE_PORT_INFERRED, so a
	// reader of a PASS learns the verdict rests on a table this build keeps
	// rather than on the change. When the plan states the port, the exclusion is
	// exact and that sentence is untrue -- and raising it anyway cost the
	// disclosure its meaning, because a reader could no longer tell the two
	// cases apart.
	//
	// The rule cannot ask where the port came from itself: it names no cloud, no
	// resource type and no attribute, and the answer lives in a provenance path.
	// So the mapper that read the port says.
	//
	// False is the safe default here, unusually: it suppresses a disclosure
	// rather than a verdict, and a mapper that does not set it is claiming its
	// port is a fact from the plan -- which is what a mapper reading only the
	// plan would be doing.
	PortInferred bool
	// Withdrawn reports that a determination was reached and then unset, because
	// it rested on a source this build may not use. ObjectStorageCapabilities
	// carries this for the same reason, and the reason is in its comment.
	Withdrawn bool
	// Unresolved names controls that could change the answer and are not in the
	// plan. They are recorded even when both facts are known, because they bound
	// how far the evidence reaches.
	Unresolved []MissingControl
}
