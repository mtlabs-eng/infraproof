package intent_test

import (
	"fmt"
	"strings"
	"testing"
	"unicode"

	"github.com/mtlabs-eng/infraproof/internal/intent"
)

// TestEveryFoldTheDecoderMakesIsRefused sweeps the relation rather than
// sampling it.
//
// The previous form of this guard restated encoding/json's folding as
// strings.ToLower. The two agree almost everywhere, and "almost" is the whole
// problem: the long s folds with s for the decoder and not for ToLower, so a
// contract could name one field twice and be read as saying the second thing.
//
// This does not restate anything. For every rune that folds onto an ASCII
// letter appearing in a field name, it builds a contract spelling that field
// both ways with disagreeing values, and requires the contract to be refused.
// A future Go release that widens the relation widens this test with it.
func TestEveryFoldTheDecoderMakesIsRefused(t *testing.T) {
	// The fields a contract carries, and a second value for each that a reader
	// would notice being preferred.
	type field struct{ name, first, second string }
	fields := []field{
		{"exposure", `"private"`, `"public"`},
		{"destructive_changes", `"forbidden"`, `"allowed_with_warning"`},
		{"environment", `"staging"`, `"production"`},
	}

	var swept int
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r < utf8Max && r >= 0x80 {
			// Fine.
		}
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded > unicode.MaxASCII || !isLetter(byte(folded)) {
				continue
			}
			if r <= unicode.MaxASCII {
				// Ordinary case, covered by the table test beside this one.
				continue
			}

			for _, f := range fields {
				lower := byte(unicode.ToLower(folded))
				if !strings.ContainsRune(f.name, rune(lower)) {
					continue
				}
				swept++

				variant := strings.Replace(f.name, string(rune(lower)), string(r), 1)
				raw := contractNaming(f.name, f.first, variant, f.second)

				if _, err := intent.Parse([]byte(raw), "contract.json"); err == nil {
					t.Errorf("a contract naming %q as both %q and %q was accepted",
						f.name, f.name, variant)
				}
			}
		}
	}

	if swept == 0 {
		t.Fatal("the sweep found no folds outside ASCII; it is not sweeping anything")
	}
	t.Logf("swept %d non-ASCII folds onto contract field names", swept)
}

const utf8Max = 0x10FFFF

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// contractNaming builds a contract that spells one field twice.
func contractNaming(name, first, variant, second string) string {
	const shell = `{
	  "schema_version": "1.0",
	  "change_id": "c",
	  "environment": "staging",
	  "allowed_clouds": ["aws"],
	  "destructive_changes": "forbidden",
	  "resources": [{"family": "object_storage", "exposure": "private"}]
	}`

	if name == "exposure" {
		return strings.Replace(shell, `"exposure": "private"`,
			fmt.Sprintf(`%q: %s, %q: %s`, name, first, variant, second), 1)
	}
	return strings.Replace(shell, fmt.Sprintf(`%q: %s,`, name, first),
		fmt.Sprintf(`%q: %s, %q: %s,`, name, first, variant, second), 1)
}
