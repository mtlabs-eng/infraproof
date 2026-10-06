package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
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

// A list field holding something that is not a list is a boundary this build
// validates everywhere else: destinationPorts, targetsOf, blocksOf and
// protocolOf all check the kind, and this -- the one function all three mappers
// route their source reading through -- did not.
//
// Value.Len() is 0 for anything that is not an array, so a known scalar where a
// set belongs produced SetReach(nil), which is ReachNarrower: no grant, and a
// proven closure. Terraform will not emit it for a set-typed attribute, so it is
// not reachable from a real plan; it is the shape a hand-edited or
// differently-generated document has, and the answer must be unreadable.
func TestAListFieldHoldingSomethingElseIsUnreadable(t *testing.T) {
	cases := map[string]string{
		"a string where a set belongs": `"0.0.0.0/0"`,
		"a number":                     `42`,
		"a bool":                       `true`,
		"an object":                    `{"cidr": "10.0.0.0/8"}`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := reachOfField(t, body); got != declared.ReachUnreadable {
				t.Fatalf("reach = %v, want %v", got, declared.ReachUnreadable)
			}
		})
	}

	// The shapes that are lists still read, or the kind check has turned every
	// source into an unknown.
	if got := reachOfField(t, `["0.0.0.0/0"]`); got != declared.ReachAnyAddress {
		t.Errorf("a list of one open prefix reads as %v", got)
	}
	if got := reachOfField(t, `["10.0.0.0/8"]`); got != declared.ReachNarrower {
		t.Errorf("a list of one narrow prefix reads as %v", got)
	}
	if got := reachOfField(t, `[]`); got != declared.ReachNarrower {
		t.Errorf("an empty list reads as %v; it names nobody", got)
	}
	if got := reachOfField(t, `null`); got != declared.ReachNarrower {
		t.Errorf("an absent field reads as %v; it names nobody", got)
	}
}

// reachOfField parses a plan whose source field holds the given JSON and reports
// what the list reads as.
func reachOfField(t *testing.T, body string) declared.Reach {
	t.Helper()
	plan, err := terraformplan.Parse([]byte(`{
	  "format_version": "1.2",
	  "resource_changes": [
	    {
	      "address": "google_compute_firewall.web", "mode": "managed",
	      "type": "google_compute_firewall", "name": "web", "provider_name": "p",
	      "change": {"actions": ["create"], "before": null,
	                 "after": {"source_ranges": ` + body + `}}
	    }
	  ]
	}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return declared.ListReach(plan.ResourceChanges[0].After.Field("source_ranges"))
}

// TestASetCoveringEveryAddressButTheLastIsNarrower pins the top of the space.
//
// The sweep ends with a comparison against the highest address, and relaxing it
// by one reported a set covering 0.0.0.0 through 255.255.255.254 as every
// address. The direction over-reports openness, which is the safe one, but a
// boundary nothing tests is a boundary that can move either way.
func TestASetCoveringEveryAddressButTheLastIsNarrower(t *testing.T) {
	// Every address except 255.255.255.255, as a chain of prefixes.
	chain := []string{
		"0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/3", "224.0.0.0/4", "240.0.0.0/5",
		"248.0.0.0/6", "252.0.0.0/7", "254.0.0.0/8", "255.0.0.0/9", "255.128.0.0/10",
		"255.192.0.0/11", "255.224.0.0/12", "255.240.0.0/13", "255.248.0.0/14",
		"255.252.0.0/15", "255.254.0.0/16", "255.255.0.0/17", "255.255.128.0/18",
		"255.255.192.0/19", "255.255.224.0/20", "255.255.240.0/21", "255.255.248.0/22",
		"255.255.252.0/23", "255.255.254.0/24", "255.255.255.0/25", "255.255.255.128/26",
		"255.255.255.192/27", "255.255.255.224/28", "255.255.255.240/29",
		"255.255.255.248/30", "255.255.255.252/31", "255.255.255.254",
	}

	if got := declared.SetReach(chain); got != declared.ReachNarrower {
		t.Fatalf("a set missing 255.255.255.255 reads as %v", got)
	}
	// And adding the last address closes it.
	if got := declared.SetReach(append(chain, "255.255.255.255")); got != declared.ReachAnyAddress {
		t.Fatalf("the same set with the last address reads as %v", got)
	}
}
