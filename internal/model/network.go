package model

// Protocol is a transport protocol, normalized across the three clouds.
//
// The set is closed and carries an explicit unrecognized member, because
// CLAUDE.md requires an unsupported semantic to be represented rather than
// forced into the common model: a spelling this build does not know is a fact
// about what it could not read, and collapsing it into "every protocol" would
// invent a grant while collapsing it into TCP would hide one.
//
// The zero value is ProtocolUnrecognized, so a protocol nobody set cannot read as
// one that was read and understood.
type Protocol string

const (
	// ProtocolUnrecognized is a spelling this build does not interpret.
	ProtocolUnrecognized Protocol = ""
	// ProtocolTCP, ProtocolUDP and ProtocolICMP are themselves.
	ProtocolTCP  Protocol = "tcp"
	ProtocolUDP  Protocol = "udp"
	ProtocolICMP Protocol = "icmp"
	// ProtocolEvery is every protocol: AWS writes "-1", Azure "*", GCP "all".
	ProtocolEvery Protocol = "every"
)

// HasPorts reports whether a port constrains this protocol at all.
//
// It is the distinction the network rule turns on. A contract declares ports, so
// it can neither permit nor forbid a protocol that has none: ICMP from any
// address is a thing the contract cannot describe, and this is how the rule knows
// to say so rather than to decide.
func (p Protocol) HasPorts() bool {
	switch p {
	case ProtocolTCP, ProtocolUDP, ProtocolEvery:
		return true
	default:
		return false
	}
}

// PortRange is an inclusive range of ports.
//
// It lives here rather than in intent or policy because a port range is
// arithmetic rather than a cloud fact or a contract grammar, and the comparison
// the rule makes -- is every port this change opens inside a port the contract
// declared -- has to be one comparison. Two spellings of a range would be two
// chances to disagree about what 8000-8100 covers.
type PortRange struct {
	// From and To are inclusive, and 0-65535 is every port.
	From, To int
}

// EveryPort is the range a rule opens when it names no port at all.
func EveryPort() PortRange { return PortRange{From: 0, To: 65535} }

// Contains reports whether this range covers all of another.
//
// Partial overlap is not permission: a contract declaring 8000-8100 has not
// declared 7999, so a change opening 7999-8050 exceeds what was declared even
// though most of it was allowed. Reading an overlap as permission is how a
// declaration comes to cover a port nobody wrote down.
func (r PortRange) Contains(other PortRange) bool {
	return r.From <= other.From && other.To <= r.To
}

// OpenRange is one protocol and port range a change makes reachable from any
// address, with the provider attributes it was read from.
type OpenRange struct {
	Protocol Protocol
	// Ports is meaningful only when the protocol has ports. For ICMP and for a
	// protocol this build does not recognize it is the zero range and nothing
	// reads it.
	Ports PortRange
	// Sources name the provider attributes this range came from, which is what
	// lets a finding say where it was read rather than only what it concluded.
	Sources []Provenance
}

// NetworkCapabilities is the cloud-neutral view of an ingress rule set.
//
// The question is the one public storage asks -- reachable by whom -- and the
// three clouds answer it with different machinery: AWS rules are an allow-only
// union, Azure and GCP have priorities and deny rules, so in two of the three no
// single rule decides anything. Resolving that ordering is the mapper's work; by
// the time a rule reads this, the answer is about the set.
type NetworkCapabilities struct {
	// PublicIngress reports whether the change permits ingress from any address.
	//
	// Known(true) means the change permits it. Known(false) means the plan
	// proves the set permits none. Unknown means the plan does not contain the
	// set in full -- a rule declared in a module this plan does not include, or
	// a security group whose rules are separate resources, of which the plan has
	// some.
	//
	// That asymmetry is the whole design: a grant can be proven from part of a
	// set, and closure cannot.
	PublicIngress Fact[bool]
	// OpenToAnyAddress are the ranges the change makes reachable from any
	// address. It is non-empty only when PublicIngress is Known(true), and it is
	// what the contract's declared ports are compared against.
	OpenToAnyAddress []OpenRange
	// Withdrawn reports that PublicIngress was determined and then unset,
	// because the answer was reached by choosing between a source this build may
	// use and one it may not. ObjectStorageCapabilities carries this for the
	// same reason, and the reason is in its comment.
	Withdrawn bool
	// Unresolved names controls that could change the answer and are not in the
	// plan: the attachment that decides what the set applies to, a rule resource
	// declared elsewhere. They are recorded even when PublicIngress is known,
	// because they bound how far the evidence reaches.
	Unresolved []MissingControl
}
