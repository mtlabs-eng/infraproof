package declared

import "net/netip"

// Reach describes how much of the internet an address expression covers.
//
// The zero value is ReachUnreadable, and that is the point: an expression nobody
// managed to read must not be mistaken for one that was read and found narrow. A
// narrow reach is the answer that produces no finding, so the safe default has to
// be the one that produces an unknown.
type Reach uint8

const (
	// ReachUnreadable is an expression this build could not interpret.
	ReachUnreadable Reach = iota
	// ReachAnyAddress is an expression covering every address.
	ReachAnyAddress
	// ReachNarrower is an expression covering some addresses and not all.
	ReachNarrower
)

// String names a reach for a diagnostic.
func (r Reach) String() string {
	switch r {
	case ReachAnyAddress:
		return "any address"
	case ReachNarrower:
		return "narrower than any address"
	default:
		return "unreadable"
	}
}

// AddressReach reads a CIDR prefix or a bare address and says how far it reaches.
//
// "Any address" is a prefix that constrains no bits, which the standard library
// answers for IPv4 and IPv6 at once. The alternative -- comparing against the
// strings "0.0.0.0/0" and "::/0" -- is a hand-written model of somebody else's
// grammar, which is the defect class this repository keeps finding: it would be
// right about the two spellings somebody thought of and wrong about every other
// legal one.
//
// A bare address is a single host and reaches narrower, which is what a provider
// field accepting either form means by it. Anything else is unreadable, including
// a provider's own wildcards: "*" means any address to Azure and nothing at all to
// the other two, so what it means is the mapper's to say and not this function's.
func AddressReach(text string) Reach {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		if prefix.Bits() == 0 {
			return ReachAnyAddress
		}
		return ReachNarrower
	}
	if _, err := netip.ParseAddr(text); err == nil {
		return ReachNarrower
	}
	return ReachUnreadable
}
