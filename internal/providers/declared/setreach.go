package declared

import (
	"math/big"
	"net/netip"
	"slices"

	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// SetReach describes how much of the internet a list of address expressions
// covers, taken together.
//
// A source field holds a list, and what the rule admits is the union of its
// entries -- not any one of them. Asking AddressReach per entry reported
// `0.0.0.0/1, 128.0.0.0/1` as two narrow sources and the rule as proven closed,
// a deterministic Known(false) on a set admitting every address in IPv4. A rule
// written as a pair of halves is a rule open to the internet, and nothing about
// that spelling is exotic.
//
// ReachAnyAddress when the union covers the whole address space of either
// family, because a rule admitting all of IPv4 is reachable from any address
// whatever it says about IPv6. ReachUnreadable when any entry is unreadable,
// including beside an entry that already covers everything: a set that was not
// fully read is reported as unread rather than as a reassurance.
//
// A one-element list answers exactly what AddressReach answers for that element,
// which is pinned by a test -- two paths disagreeing about the same question
// would make the verdict depend on which one a mapper happened to call.
func SetReach(texts []string) Reach {
	// Covering the space is a question per family: the two are separate spaces
	// and a prefix in one says nothing about the other.
	spans := map[int][]span{}
	for _, text := range texts {
		prefix, ok := asPrefix(text)
		if !ok {
			return ReachUnreadable
		}
		bits := prefix.Addr().BitLen()
		spans[bits] = append(spans[bits], spanOf(prefix))
	}
	for bits, group := range spans {
		if covers(group, bits) {
			return ReachAnyAddress
		}
	}
	return ReachNarrower
}

// asPrefix reads an entry as a prefix, treating a bare address as the single
// host it is -- which is what a provider field accepting either form means by it.
func asPrefix(text string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		// Masked, because a prefix may carry host bits: netip accepts
		// "1.2.3.4/0", and the addresses it admits are the whole space rather
		// than the ones above 1.2.3.4.
		return prefix.Masked(), true
	}
	if address, err := netip.ParseAddr(text); err == nil {
		return netip.PrefixFrom(address, address.BitLen()), true
	}
	return netip.Prefix{}, false
}

// span is the closed interval of addresses a prefix admits, as integers, so
// coverage is arithmetic rather than a comparison of prefix lengths. Two
// prefixes of different lengths can meet exactly, and lengths alone cannot say
// whether they do.
type span struct {
	low, high *big.Int
}

func spanOf(prefix netip.Prefix) span {
	address := prefix.Addr().As16()
	bytes := address[:]
	if prefix.Addr().Is4() {
		four := prefix.Addr().As4()
		bytes = four[:]
	}
	low := new(big.Int).SetBytes(bytes)

	// The high end is the low end with every host bit set.
	width := prefix.Addr().BitLen() - prefix.Bits()
	size := new(big.Int).Lsh(big.NewInt(1), uint(width))
	high := new(big.Int).Add(low, size)
	high.Sub(high, big.NewInt(1))
	return span{low: low, high: high}
}

// covers reports whether the spans, taken together, admit every address of a
// space that many bits wide.
//
// A sweep in ascending order: the cover has to start at zero and never leave a
// gap before the end. Overlap is not a gap, and a prefix contained in another
// changes nothing, so the frontier only ever moves forward.
func covers(spans []span, bits int) bool {
	if len(spans) == 0 {
		return false
	}
	slices.SortFunc(spans, func(a, b span) int { return a.low.Cmp(b.low) })

	last := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	last.Sub(last, big.NewInt(1))

	// frontier is the lowest address not yet known to be covered.
	frontier := big.NewInt(0)
	for _, s := range spans {
		if s.low.Cmp(frontier) > 0 {
			return false
		}
		if next := new(big.Int).Add(s.high, big.NewInt(1)); next.Cmp(frontier) > 0 {
			frontier = next
		}
	}
	return frontier.Cmp(last) > 0
}

// ListReach reads a list-valued address field and reports what it covers.
//
// An element the plan has not determined makes the whole field unreadable: it
// could be the entry that opens everything, or the one that completes a cover.
// An absent field names nobody, which is narrower rather than unread.
//
// It exists so that the three mappers ask the set question the same way. They
// each had their own element loop returning on the first entry reaching any
// address, which is what made a split of the space read as narrow in all three.
func ListReach(field terraformplan.Value) Reach {
	switch field.State() {
	case terraformplan.StateAbsent:
		return ReachNarrower
	case terraformplan.StateKnown:
	default:
		return ReachUnreadable
	}

	// A known value that is not a list is a boundary, and this build validates
	// them everywhere else. Value.Len() is 0 for anything that is not an array,
	// so a scalar where a set belongs produced SetReach(nil) -- narrower, no
	// grant, a proven closure. An empty list is a list and names nobody.
	if field.Kind() != terraformplan.KindArray && field.Kind() != terraformplan.KindNull {
		return ReachUnreadable
	}

	texts := make([]string, 0, field.Len())
	for i := range field.Len() {
		element := field.At(i)
		if element.State() != terraformplan.StateKnown {
			return ReachUnreadable
		}
		texts = append(texts, element.Text())
	}
	return SetReach(texts)
}

// AddressRange is an allow-list entry written as two addresses rather than as a
// prefix, which is the only form Azure's database firewall rules have.
type AddressRange struct {
	Start, End string
}

// RangeReach describes how much of the internet a list of address ranges covers,
// taken together.
//
// The same question SetReach answers in the other grammar, and the same
// arithmetic: coverage was already computed over intervals, so a range is the
// shape the sweep wanted in the first place. A test pins that a range and the
// prefix covering the same addresses read identically, because two entry points
// that disagree about one question make the verdict depend on which one a mapper
// happened to call.
//
// Unreadable when any entry is: a start or end nobody could read, a range running
// backwards -- this build does not know which end was meant -- or a start and end
// in different address families, which is not a span of anything.
//
// The entry to be careful with is `0.0.0.0`-`0.0.0.0`, which is how Azure says
// "services inside Azure". It is one address and reads as narrower, which it is;
// treating its start as a zero-bit prefix would make the most common benign rule
// in the cloud mean every address.
func RangeReach(ranges []AddressRange) Reach {
	spans := map[int][]span{}
	for _, entry := range ranges {
		start, err := netip.ParseAddr(entry.Start)
		if err != nil {
			return ReachUnreadable
		}
		end, err := netip.ParseAddr(entry.End)
		if err != nil {
			return ReachUnreadable
		}
		if start.BitLen() != end.BitLen() {
			return ReachUnreadable
		}
		if end.Less(start) {
			return ReachUnreadable
		}
		spans[start.BitLen()] = append(spans[start.BitLen()], span{
			low:  value(start),
			high: value(end),
		})
	}
	for bits, group := range spans {
		if covers(group, bits) {
			return ReachAnyAddress
		}
	}
	return ReachNarrower
}

// value reads an address as the integer the sweep compares.
//
// The same conversion spanOf does for a prefix, which is why both grammars reach
// one implementation of coverage rather than two.
func value(address netip.Addr) *big.Int {
	if address.Is4() {
		four := address.As4()
		return new(big.Int).SetBytes(four[:])
	}
	sixteen := address.As16()
	return new(big.Int).SetBytes(sixteen[:])
}
