package intent

import (
	"fmt"
	"testing"
)

// FuzzParsePortRange holds the port grammar to three properties a reader of a
// contract depends on, against an oracle that does not share the parser.
//
// It never panics, which a contract loader reached from a file must not. What it
// accepts is a real range: inside the ports that exist, and the right way round.
// And the range it returns round-trips through its own canonical spelling, which
// is the property that catches a parser that read "8000-8100" as something else
// and happened to produce a plausible answer.
func FuzzParsePortRange(f *testing.F) {
	for _, seed := range []string{
		"443", "0", "65535", "8000-8100", "0-65535", "443-443",
		"  443  ", "8000 - 8100", "", " ", "-", "--", "-1", "+443",
		"65536", "8100-8000", "1-2-3", "8000-", "-8000", "80 00",
		"0x1bb", "443\n", "٤٤٣", "4_43", "443.0", "1e3", "٠", "4294967296",
		"18446744073709551616", "00443", "0-0",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, declared string) {
		parsed, err := parsePortRange(declared)
		if err != nil {
			return
		}

		if parsed.From < 0 || parsed.To > lastPort || parsed.From > parsed.To {
			t.Fatalf("parsePortRange(%q) accepted %v, which is not a range of ports", declared, parsed)
		}

		// Its own canonical spelling must read back as the same range. A parser
		// that reached this range by misreading the text would have to misread
		// the unambiguous form the same way.
		canonical := fmt.Sprintf("%d-%d", parsed.From, parsed.To)
		again, err := parsePortRange(canonical)
		if err != nil {
			t.Fatalf("parsePortRange(%q) produced %v, whose own spelling %q it then refused: %v",
				declared, parsed, canonical, err)
		}
		if again != parsed {
			t.Fatalf("parsePortRange(%q) = %v, and %q = %v", declared, parsed, canonical, again)
		}
	})
}
