package evidence

import (
	"encoding/json"
	"strings"
	"testing"
)

// located returns a bundle whose finding and evidence reference both carry
// a location.
func located() Bundle {
	bundle := blockBundle()
	bundle.Findings[0].Resource.Location = &Location{File: "main.tf", Line: 6}
	bundle.Findings[0].Evidence[0].Location = &Location{File: "modules/storage/main.tf", Line: 25}
	return bundle
}

// TestLocationIsOptional covers the compatibility the contract promises within a
// major version. A bundle without locations is what every version before 1.2
// produced, and it stays valid.
func TestLocationIsOptional(t *testing.T) {
	bundle := blockBundle()

	if err := bundle.Validate(); err != nil {
		t.Fatalf("a bundle without locations is invalid: %v", err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(raw), "location") {
		t.Fatalf("a bundle with no location emitted the field: %s", raw)
	}
}

// TestLocationIsCarried covers the ordinary case: a location survives a round
// trip through the contract's own encoding.
func TestLocationIsCarried(t *testing.T) {
	raw, err := json.Marshal(located())
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var back Bundle
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if err := back.Validate(); err != nil {
		t.Fatalf("a located bundle is invalid: %v", err)
	}

	resource := back.Findings[0].Resource.Location
	if resource == nil || resource.File != "main.tf" || resource.Line != 6 {
		t.Fatalf("resource location = %+v", resource)
	}
	reference := back.Findings[0].Evidence[0].Location
	if reference == nil || reference.File != "modules/storage/main.tf" || reference.Line != 25 {
		t.Fatalf("evidence location = %+v", reference)
	}
}

// TestLocationCarriesNoText covers the milestone's rule that no configuration
// content reaches output. It is enforced by the shape of the contract rather
// than by a producer remembering: a location is a path and a line, and there is
// nowhere for a line of a .tf file to be put.
func TestLocationCarriesNoText(t *testing.T) {
	raw, err := json.Marshal(Location{File: "main.tf", Line: 6})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if len(fields) != 2 {
		t.Fatalf("a location has %d fields: %v", len(fields), fields)
	}
	for _, name := range []string{"file", "line"} {
		if _, present := fields[name]; !present {
			t.Fatalf("a location has no %q: %v", name, fields)
		}
	}
}

// TestInvalidLocationsAreRefused covers what a location may hold. Every case is
// a path that says something about a filesystem the report's reader is not
// looking at, or a line that locates nothing.
func TestInvalidLocationsAreRefused(t *testing.T) {
	cases := map[string]Location{
		"empty file":        {File: "", Line: 1},
		"absolute path":     {File: "/home/someone/main.tf", Line: 1},
		"windows path":      {File: `C:\infra\main.tf`, Line: 1},
		"climbing path":     {File: "../outside/main.tf", Line: 1},
		"climbing inside":   {File: "modules/../../outside/main.tf", Line: 1},
		"line zero":         {File: "main.tf", Line: 0},
		"negative line":     {File: "main.tf", Line: -3},
		"control character": {File: "ma\nin.tf", Line: 1},
	}
	for name, location := range cases {
		t.Run(name, func(t *testing.T) {
			bundle := blockBundle()
			bundle.Findings[0].Resource.Location = &location
			if err := bundle.Validate(); err == nil {
				t.Fatalf("accepted %+v", location)
			}

			reference := blockBundle()
			reference.Findings[0].Evidence[0].Location = &location
			if err := reference.Validate(); err == nil {
				t.Fatalf("accepted %+v on an evidence reference", location)
			}
		})
	}
}

// TestLocationPathIsReportedWhenInvalid keeps a refusal actionable: the field
// that is wrong is named, as every other violation in this contract names it.
func TestLocationPathIsReportedWhenInvalid(t *testing.T) {
	bundle := blockBundle()
	bundle.Findings[0].Evidence[0].Location = &Location{File: "/etc/passwd", Line: 1}

	err := bundle.Validate()
	if err == nil {
		t.Fatal("an absolute path was accepted")
	}
	if !strings.Contains(err.Error(), "findings[0].evidence[0].location.file") {
		t.Fatalf("error %q does not name the field", err)
	}
}

// TestCanonicalCopiesLocations covers the sharing a canonical copy must not
// leave behind. Canonical returns a bundle a caller may change without changing
// the one it was given, and a pointer copied rather than cloned breaks that
// quietly.
func TestCanonicalCopiesLocations(t *testing.T) {
	original := located()
	canonical := Canonical(original)

	if canonical.Findings[0].Resource.Location == original.Findings[0].Resource.Location {
		t.Fatal("the canonical copy shares the resource location")
	}
	if canonical.Findings[0].Evidence[0].Location == original.Findings[0].Evidence[0].Location {
		t.Fatal("the canonical copy shares the evidence location")
	}

	canonical.Findings[0].Resource.Location.Line = 999
	canonical.Findings[0].Evidence[0].Location.Line = 999
	if original.Findings[0].Resource.Location.Line != 6 {
		t.Fatal("changing the copy changed the original resource location")
	}
	if original.Findings[0].Evidence[0].Location.Line != 25 {
		t.Fatal("changing the copy changed the original evidence location")
	}
}

// TestCanonicalKeepsTwoReferencesThatDifferOnlyByLocation covers the ordering
// this addition must not disturb. Two references alike but for where they are
// written are two references, and a canonical form that collapsed them would
// drop evidence.
func TestCanonicalKeepsTwoReferencesThatDifferOnlyByLocation(t *testing.T) {
	bundle := blockBundle()
	first := bundle.Findings[0].Evidence[0]
	second := first
	first.Location = &Location{File: "main.tf", Line: 1}
	second.Location = &Location{File: "main.tf", Line: 2}
	bundle.Findings[0].Evidence = []EvidenceRef{first, second}

	canonical := Canonical(bundle)

	if len(canonical.Findings[0].Evidence) != 2 {
		t.Fatalf("evidence = %+v, want both references", canonical.Findings[0].Evidence)
	}
}
