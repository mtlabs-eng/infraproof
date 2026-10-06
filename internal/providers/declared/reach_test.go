package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
)

// TestAddressReachIsComputedNotMatched covers the one piece of this family's
// grammar that is identical in all three clouds, and the reason it is not a string
// comparison.
//
// "Any address" is a prefix that constrains no bits. Asking the standard library
// answers it for IPv4 and IPv6 at once and for every legal spelling; matching the
// two strings "0.0.0.0/0" and "::/0" would be a hand-written model of someone
// else's grammar, which is the defect this repository keeps finding.
func TestAddressReachIsComputedNotMatched(t *testing.T) {
	cases := map[string]declared.Reach{
		"0.0.0.0/0":      declared.ReachAnyAddress,
		"::/0":           declared.ReachAnyAddress,
		"0000:0000::/0":  declared.ReachAnyAddress,
		"::ffff:0:0/0":   declared.ReachAnyAddress,
		"10.0.0.0/8":     declared.ReachNarrower,
		"0.0.0.0/1":      declared.ReachNarrower,
		"0.0.0.0/32":     declared.ReachNarrower,
		"2001:db8::/32":  declared.ReachNarrower,
		"::1/128":        declared.ReachNarrower,
		"10.0.0.1":       declared.ReachNarrower,
		"2001:db8::1":    declared.ReachNarrower,
		"":               declared.ReachUnreadable,
		" ":              declared.ReachUnreadable,
		"0.0.0.0/":       declared.ReachUnreadable,
		"0.0.0.0/0/0":    declared.ReachUnreadable,
		"not an address": declared.ReachUnreadable,
		"0.0.0.0/-1":     declared.ReachUnreadable,
		"0.0.0.0/33":     declared.ReachUnreadable,
		"::/129":         declared.ReachUnreadable,
		"256.0.0.0/0":    declared.ReachUnreadable,
		"10.0.0.0/8 ":    declared.ReachUnreadable,
		"*":              declared.ReachUnreadable,
	}
	for text, want := range cases {
		t.Run(text, func(t *testing.T) {
			if got := declared.AddressReach(text); got != want {
				t.Fatalf("AddressReach(%q) = %v, want %v", text, got, want)
			}
		})
	}
}

// TestUnreadableIsTheZeroReach keeps the safe answer the default. A Reach nobody
// set must not read as one that was computed and found narrow, because a narrow
// reach is the one that produces no finding.
func TestUnreadableIsTheZeroReach(t *testing.T) {
	var unset declared.Reach

	if unset != declared.ReachUnreadable {
		t.Fatalf("the zero Reach is %v, want ReachUnreadable", unset)
	}
}
