package evidence

import (
	"encoding/json"
	"testing"
)

func TestScalarMarshalling(t *testing.T) {
	cases := map[string]struct {
		scalar *Scalar
		json   string
		text   string
	}{
		"bool":   {Bool(true), "true", "true"},
		"string": {String("private"), `"private"`, "private"},
		"int":    {Int(-7), "-7", "-7"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(c.scalar)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if string(raw) != c.json {
				t.Fatalf("JSON = %s, want %s", raw, c.json)
			}
			if c.scalar.Display() != c.text {
				t.Fatalf("Display = %q, want %q", c.scalar.Display(), c.text)
			}
		})
	}
}

// TestUninitializedScalarIsRefused stops a zero-value Scalar from silently
// rendering as a value that was never observed.
func TestUninitializedScalarIsRefused(t *testing.T) {
	var s Scalar

	if s.Valid() {
		t.Fatal("a zero-value Scalar must not report itself valid")
	}
	if _, err := json.Marshal(&s); err == nil {
		t.Fatal("marshalling a zero-value Scalar must fail rather than emit a value")
	}
	if s.Display() != "" {
		t.Fatalf("Display of a zero-value Scalar = %q, want empty", s.Display())
	}
}

func TestNilScalarIsSafe(t *testing.T) {
	var s *Scalar

	if s.Valid() {
		t.Fatal("a nil Scalar must not report itself valid")
	}
	if s.Display() != "" {
		t.Fatalf("Display of a nil Scalar = %q, want empty", s.Display())
	}
}
