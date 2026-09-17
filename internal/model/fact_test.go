package model

import (
	"reflect"
	"testing"
)

func aws(address, attribute string) Provenance {
	return Provenance{ResourceAddress: address, AttributePath: attribute, Cloud: CloudAWS}
}

// TestFactStatesAreDistinguishable carries milestone 02's guarantee into the
// normalized layer. A mapper that cannot say "absent" separately from "false"
// hands the rule the same confident wrong answer the parser was built to avoid.
func TestFactStatesAreDistinguishable(t *testing.T) {
	source := aws("aws_s3_bucket_public_access_block.assets", "block_public_policy")

	cases := map[string]struct {
		fact  Fact[bool]
		state FactState
		value bool
	}{
		"known true":  {Known(true, source), FactKnown, true},
		"known false": {Known(false, source), FactKnown, false},
		"unknown":     {Unknown[bool](source), FactUnknown, false},
		"absent":      {Absent[bool](source), FactAbsent, false},
		"redacted":    {Redacted[bool](source), FactRedacted, false},
	}

	seen := map[FactState]bool{}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.fact.State != c.state {
				t.Fatalf("state = %q, want %q", c.fact.State, c.state)
			}
			if got := c.fact.Get(); got != c.value {
				t.Fatalf("value = %v, want %v", got, c.value)
			}
			seen[c.fact.State] = true
		})
	}
	if len(seen) != 4 {
		t.Fatalf("expected four distinct states, got %v", seen)
	}
}

// TestOnlyAKnownFactCarriesAValue keeps the state gate that milestone 01 made
// structural for the Evidence Bundle.
func TestOnlyAKnownFactCarriesAValue(t *testing.T) {
	for _, fact := range []Fact[bool]{
		Unknown[bool](aws("a.b", "x")),
		Absent[bool](aws("a.b", "x")),
		Redacted[bool](aws("a.b", "x")),
	} {
		if fact.Get() {
			t.Fatalf("a %s fact reported a true value", fact.State)
		}
		if fact.IsKnown() {
			t.Fatalf("a %s fact reported itself known", fact.State)
		}
	}
	if !Known(true, aws("a.b", "x")).IsKnown() {
		t.Fatal("a known fact should report itself known")
	}
}

// TestEveryFactRecordsItsProvenance is an acceptance criterion in its own
// right: a finding has to be traceable to the provider attribute it came from,
// and three clouds reach the same normalized fact through different ones.
func TestEveryFactRecordsItsProvenance(t *testing.T) {
	first := aws("aws_s3_bucket_public_access_block.assets", "block_public_policy")
	second := aws("aws_s3_bucket_policy.assets", "policy")

	fact := Known(true, first, second)
	if !reflect.DeepEqual(fact.Sources, []Provenance{first, second}) {
		t.Fatalf("sources = %v", fact.Sources)
	}
	if len(Known(true).Sources) != 0 {
		t.Fatal("a fact with no stated source must not invent one")
	}
}

// TestProvenanceOrdersDeterministically keeps evidence stable across runs, for
// the same reason the Evidence Bundle sorts its collections.
func TestProvenanceOrdersDeterministically(t *testing.T) {
	late := aws("aws_s3_bucket_policy.assets", "policy")
	early := aws("aws_s3_bucket_acl.assets", "acl")

	forward := Known(true, late, early).Canonical()
	reversed := Known(true, early, late).Canonical()

	if !reflect.DeepEqual(forward.Sources, reversed.Sources) {
		t.Fatalf("provenance order depends on input: %v vs %v", forward.Sources, reversed.Sources)
	}
	if forward.Sources[0].ResourceAddress != "aws_s3_bucket_acl.assets" {
		t.Fatalf("sources are not sorted: %v", forward.Sources)
	}
}

func TestDuplicateProvenanceIsCollapsed(t *testing.T) {
	source := aws("aws_s3_bucket.assets", "bucket")

	if got := Known(true, source, source).Canonical().Sources; len(got) != 1 {
		t.Fatalf("sources = %v, want one", got)
	}
}
