package declared_test

import (
	"math/rand"
	"net/netip"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
)

// FuzzSetReachAgreesWithAPartitionOfTheSpace checks the arithmetic against an
// oracle that does not share its implementation.
//
// A random binary split of the whole address space covers it by construction --
// every leaf of the tree, and nothing missing. So SetReach has to answer
// ReachAnyAddress for the leaves in any order, and ReachNarrower as soon as one
// leaf is removed. No prefix arithmetic is needed to know the right answer,
// which is what makes it an oracle rather than a second copy of the code.
func FuzzSetReachAgreesWithAPartitionOfTheSpace(f *testing.F) {
	f.Add(int64(1), uint8(3), false)
	f.Add(int64(7), uint8(8), true)
	f.Add(int64(99), uint8(1), false)
	f.Add(int64(1234), uint8(16), true)

	f.Fuzz(func(t *testing.T, seed int64, splits uint8, sixes bool) {
		base := netip.MustParsePrefix("0.0.0.0/0")
		if sixes {
			base = netip.MustParsePrefix("::/0")
		}
		// Bounded: a partition of the IPv6 space can be split 128 deep, and the
		// test is about the arithmetic rather than about size.
		leaves := partition(base, int(splits)%24, rand.New(rand.NewSource(seed)))

		texts := make([]string, 0, len(leaves))
		for _, leaf := range leaves {
			texts = append(texts, leaf.String())
		}
		if got := declared.SetReach(texts); got != declared.ReachAnyAddress {
			t.Fatalf("a partition of the whole space reads as %v, from %d leaves: %v",
				got, len(texts), texts)
		}

		// The order the list happens to be in cannot change what it covers.
		shuffled := append([]string(nil), texts...)
		rand.New(rand.NewSource(seed+1)).Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		if got := declared.SetReach(shuffled); got != declared.ReachAnyAddress {
			t.Fatalf("the same partition shuffled reads as %v", got)
		}

		if len(texts) < 2 {
			return
		}
		// Removing any one leaf leaves a gap exactly that leaf's size, and a set
		// with a gap is not every address. This is the direction that matters:
		// the failure found in review was a cover reported as narrow, and this
		// is its mirror.
		drop := int(seed%int64(len(texts))+int64(len(texts))) % len(texts)
		short := append(append([]string(nil), texts[:drop]...), texts[drop+1:]...)
		if got := declared.SetReach(short); got != declared.ReachNarrower {
			t.Fatalf("a partition missing %q reads as %v", texts[drop], got)
		}
	})
}

// partition splits a prefix into a random binary tree of the given depth and
// returns its leaves, which cover the prefix exactly.
func partition(prefix netip.Prefix, depth int, random *rand.Rand) []netip.Prefix {
	if depth <= 0 || prefix.Bits() >= prefix.Addr().BitLen() {
		return []netip.Prefix{prefix}
	}
	low, high, ok := halves(prefix)
	if !ok {
		return []netip.Prefix{prefix}
	}
	// Each side splits to its own depth, so the leaves come out at mixed prefix
	// lengths: a cover made of equal-sized pieces would not exercise two
	// prefixes of different lengths meeting exactly.
	return append(partition(low, random.Intn(depth), random),
		partition(high, random.Intn(depth), random)...)
}

// halves splits a prefix into its two children by setting the next bit.
func halves(prefix netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	bits := prefix.Bits() + 1
	low := netip.PrefixFrom(prefix.Addr(), bits)
	if !low.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, false
	}

	raw := prefix.Addr().As16()
	offset := 16 - prefix.Addr().BitLen()/8
	index := offset + (bits-1)/8
	raw[index] |= 1 << (7 - uint((bits-1)%8))
	address, ok := netip.AddrFromSlice(raw[offset:])
	if !ok {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	return low.Masked(), netip.PrefixFrom(address, bits).Masked(), true
}
