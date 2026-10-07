package declared_test

// A property test for RangeReach against an independent oracle. Coverage is
// decided here by merging sorted intervals and summing the union, which is a
// different algorithm from the frontier sweep RangeReach uses -- an oracle that
// shares the implementation proves nothing.
//
// Written by an independent review of this layer and committed as it stood,
// because the five hand-written agreement cases it replaces checked five prefix
// lengths and this checks every one in both families, and because the randomized
// half reaches covers and near-covers densely enough to matter.

import (
	"math/big"
	"math/rand"
	"net/netip"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
)

type interval struct{ lo, hi *big.Int }

// unionCoversAll merges sorted intervals and sums the union. Deliberately not
// the sweep RangeReach uses, and deliberately not slices.SortFunc.
func unionCoversAll(ranges []interval, bits int) bool {
	if len(ranges) == 0 {
		return false
	}
	for i := 1; i < len(ranges); i++ {
		for j := i; j > 0 && ranges[j].lo.Cmp(ranges[j-1].lo) < 0; j-- {
			ranges[j], ranges[j-1] = ranges[j-1], ranges[j]
		}
	}
	total := new(big.Int)
	add := func(lo, hi *big.Int) {
		n := new(big.Int).Sub(hi, lo)
		total.Add(total, n.Add(n, big.NewInt(1)))
	}
	lo := new(big.Int).Set(ranges[0].lo)
	hi := new(big.Int).Set(ranges[0].hi)
	for _, r := range ranges[1:] {
		if r.lo.Cmp(new(big.Int).Add(hi, big.NewInt(1))) > 0 {
			add(lo, hi)
			lo, hi = new(big.Int).Set(r.lo), new(big.Int).Set(r.hi)
			continue
		}
		if r.hi.Cmp(hi) > 0 {
			hi = new(big.Int).Set(r.hi)
		}
	}
	add(lo, hi)
	return total.Cmp(new(big.Int).Lsh(big.NewInt(1), uint(bits))) == 0
}

func addrInt(a netip.Addr) *big.Int {
	if a.Is4() {
		b := a.As4()
		return new(big.Int).SetBytes(b[:])
	}
	b := a.As16()
	return new(big.Int).SetBytes(b[:])
}

func intAddr(n *big.Int, bits int) netip.Addr {
	if bits == 32 {
		var b [4]byte
		n.FillBytes(b[:])
		return netip.AddrFrom4(b)
	}
	var b [16]byte
	n.FillBytes(b[:])
	return netip.AddrFrom16(b)
}

func oracle(pairs [][2]netip.Addr) declared.Reach {
	byFamily := map[int][]interval{}
	for _, p := range pairs {
		if p[0].BitLen() != p[1].BitLen() || p[1].Less(p[0]) {
			return declared.ReachUnreadable
		}
		byFamily[p[0].BitLen()] = append(byFamily[p[0].BitLen()],
			interval{addrInt(p[0]), addrInt(p[1])})
	}
	for bits, group := range byFamily {
		if unionCoversAll(group, bits) {
			return declared.ReachAnyAddress
		}
	}
	return declared.ReachNarrower
}

func TestRangeReachAgreesWithAnIndependentOracle(t *testing.T) {
	r := rand.New(rand.NewSource(20260914))
	const runs = 300000
	for i := 0; i < runs; i++ {
		bits := 32
		if r.Intn(3) == 0 {
			bits = 128
		}
		space := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		n := 1 + r.Intn(4)
		var pairs [][2]netip.Addr
		var spans []declared.AddressRange
		emit := func(lo, hi *big.Int) {
			a0, a1 := intAddr(lo, bits), intAddr(hi, bits)
			pairs = append(pairs, [2]netip.Addr{a0, a1})
			spans = append(spans, declared.AddressRange{Start: a0.String(), End: a1.String()})
		}
		if r.Intn(2) == 0 {
			// A partition of the whole space, sometimes one address short, so a
			// cover and a near-cover both occur often.
			cuts := []*big.Int{big.NewInt(0)}
			for k := 0; k < n; k++ {
				cuts = append(cuts, new(big.Int).Rand(r, space))
			}
			cuts = append(cuts, space)
			for a := 1; a < len(cuts); a++ {
				for b := a; b > 0 && cuts[b].Cmp(cuts[b-1]) < 0; b-- {
					cuts[b], cuts[b-1] = cuts[b-1], cuts[b]
				}
			}
			for k := 0; k+1 < len(cuts); k++ {
				lo := new(big.Int).Set(cuts[k])
				hi := new(big.Int).Sub(cuts[k+1], big.NewInt(1))
				if r.Intn(8) == 0 {
					hi.Sub(hi, big.NewInt(1))
				}
				if hi.Cmp(lo) < 0 {
					continue
				}
				emit(lo, hi)
			}
		} else {
			for k := 0; k < n; k++ {
				emit(new(big.Int).Rand(r, space), new(big.Int).Rand(r, space))
			}
		}
		if len(spans) == 0 {
			continue
		}
		if got, want := declared.RangeReach(spans), oracle(pairs); got != want {
			t.Fatalf("run %d: RangeReach = %v, oracle = %v\n%v", i, got, want, spans)
		}
	}
}

func TestRangeAndPrefixAgreeOnEveryPrefix(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for _, bits := range []int{32, 128} {
		space := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		for length := 0; length <= bits; length++ {
			for trial := 0; trial < 40; trial++ {
				base := intAddr(new(big.Int).Rand(r, space), bits)
				p, err := base.Prefix(length)
				if err != nil {
					t.Fatalf("Prefix(%d): %v", length, err)
				}
				lo := addrInt(p.Addr())
				hi := new(big.Int).Add(lo, new(big.Int).Lsh(big.NewInt(1), uint(bits-length)))
				hi.Sub(hi, big.NewInt(1))
				byPrefix := declared.SetReach([]string{p.String()})
				byRange := declared.RangeReach([]declared.AddressRange{
					{Start: intAddr(lo, bits).String(), End: intAddr(hi, bits).String()}})
				if byPrefix != byRange {
					t.Fatalf("%s = %v but the same span as a range = %v", p, byPrefix, byRange)
				}
			}
		}
	}
}
