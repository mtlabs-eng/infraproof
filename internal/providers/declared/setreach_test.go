package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
)

// A source field holds a list, and the question is what the list covers taken
// together. Asking it one prefix at a time reported `0.0.0.0/1, 128.0.0.0/1` as
// two narrow sources and the set as proven closed -- a deterministic Known(false)
// on a rule admitting every address in IPv4.
//
// Nothing about that is exotic: it is what any split of the space looks like, and
// a rule written as a pair of halves is a rule open to the internet.
func TestWhatAListOfAddressesCoversIsAskedOfTheWholeList(t *testing.T) {
	cases := map[string]struct {
		texts []string
		want  declared.Reach
		why   string
	}{
		"a single zero-bit prefix": {
			[]string{"0.0.0.0/0"}, declared.ReachAnyAddress,
			"the ordinary spelling, and it has to keep answering the same way"},
		"two halves of IPv4": {
			[]string{"0.0.0.0/1", "128.0.0.0/1"}, declared.ReachAnyAddress,
			"the union is every IPv4 address"},
		"four quarters out of order": {
			[]string{"192.0.0.0/2", "0.0.0.0/2", "128.0.0.0/2", "64.0.0.0/2"},
			declared.ReachAnyAddress,
			"order is the list's, not the arithmetic's"},
		"halves of IPv6": {
			[]string{"::/1", "8000::/1"}, declared.ReachAnyAddress,
			"the same question in the other family"},
		"every address of one family among narrow ranges of the other": {
			[]string{"10.0.0.0/8", "::/0"}, declared.ReachAnyAddress,
			"a rule admitting all of IPv6 is reachable from any address"},
		"halves with a gap": {
			[]string{"0.0.0.0/1", "192.0.0.0/2"}, declared.ReachNarrower,
			"a quarter of the space is missing, so this is not every address"},
		"one address short": {
			[]string{"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4",
				"240.0.0.0/5", "248.0.0.0/6", "252.0.0.0/7", "254.0.0.0/8",
				"255.0.0.0/9", "255.128.0.0/10"},
			declared.ReachNarrower,
			"a set that nearly covers the space does not cover it"},
		"overlapping prefixes that still cover": {
			[]string{"0.0.0.0/1", "64.0.0.0/2", "128.0.0.0/1"},
			declared.ReachAnyAddress,
			"overlap is not a gap"},
		"contained prefixes that cover": {
			[]string{"0.0.0.0/0", "10.0.0.0/8"}, declared.ReachAnyAddress,
			"a prefix inside another changes nothing"},
		"private ranges only": {
			[]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			declared.ReachNarrower,
			"the common closed case, which must stay settled"},
		"empty": {
			nil, declared.ReachNarrower,
			"a list naming nobody admits nobody"},
		// One unreadable entry is the whole set unreadable: it could have been
		// the entry that completed the cover.
		"an unreadable entry": {
			[]string{"0.0.0.0/1", "not-an-address"}, declared.ReachUnreadable,
			"an entry nobody read could be the one that opens everything"},
		"an unreadable entry beside a zero-bit prefix": {
			[]string{"0.0.0.0/0", "not-an-address"}, declared.ReachUnreadable,
			"the set is still not fully read, and a reader is told so rather than reassured"},
		// A bare address is a legal entry in these fields and covers exactly
		// itself.
		"bare addresses": {
			[]string{"1.2.3.4", "::1"}, declared.ReachNarrower,
			"a single host is not every address"},
		"a bare address completing a cover": {
			[]string{"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"},
			declared.ReachAnyAddress,
			"three prefixes meeting exactly"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := declared.SetReach(c.texts); got != c.want {
				t.Fatalf("SetReach = %v, want %v: %s", got, c.want, c.why)
			}
		})
	}
}

// Every prefix a single entry reads as any address must read the same way as a
// one-element set, or the two paths disagree about the same question and which
// one a mapper happens to call decides the verdict.
func TestOneEntryAgreesWithTheSingleAddressReading(t *testing.T) {
	for _, text := range []string{
		"0.0.0.0/0", "::/0", "1.2.3.4/0", "10.0.0.0/8", "1.2.3.4", "::1",
		"not-an-address", "", "0.0.0.0/33", "10.0.0.0/8 ",
	} {
		t.Run(text, func(t *testing.T) {
			if got, want := declared.SetReach([]string{text}), declared.AddressReach(text); got != want {
				t.Fatalf("SetReach([%q]) = %v, AddressReach(%q) = %v", text, got, text, want)
			}
		})
	}
}
