package model

import (
	"cmp"
	"slices"
)

// Cloud identifies the cloud a resource belongs to.
type Cloud string

const (
	// CloudAWS identifies Amazon Web Services.
	CloudAWS Cloud = "aws"
	// CloudAzure identifies Microsoft Azure.
	CloudAzure Cloud = "azure"
	// CloudGCP identifies Google Cloud Platform.
	CloudGCP Cloud = "gcp"
	// CloudUnknown identifies a resource no mapper claimed.
	CloudUnknown Cloud = "unknown"
)

// FactState is what is known about a normalized value. It carries milestone
// 02's distinction into this layer unchanged: a rule that cannot tell Absent
// from Known(false) can reach a confident wrong conclusion.
type FactState string

const (
	// FactKnown means a mapper determined the value from the plan.
	FactKnown FactState = "KNOWN"
	// FactUnknown means the plan does not determine the value.
	FactUnknown FactState = "UNKNOWN"
	// FactAbsent means the plan does not mention the field at all. It is not a
	// provider default.
	FactAbsent FactState = "ABSENT"
	// FactRedacted means the source value was marked sensitive and discarded.
	FactRedacted FactState = "REDACTED"
)

// Provenance locates where a normalized fact came from. Three clouds reach the
// same fact through entirely different attributes, so the normalized value on
// its own would not be explainable.
type Provenance struct {
	// ResourceAddress is the provider resource the value was read from.
	ResourceAddress string
	// AttributePath is the provider attribute within it.
	AttributePath string
	// Cloud is the cloud whose semantics were interpreted.
	Cloud Cloud
	// Withheld reports that this particular value could not be read — the plan
	// marked it sensitive, or had not determined it yet.
	//
	// It belongs to the source rather than to the fact. A fact is redacted if
	// any one of its sources was, and reporting every source of such a fact as
	// withheld told a reader that values the mapper had plainly read were
	// secret — which is the same lie as the one it replaced, told the other
	// way round.
	Withheld bool
}

// Fact is a normalized value together with what is known about it and where it
// came from. The value is meaningful only when the state is FactKnown.
type Fact[T any] struct {
	State   FactState
	value   T
	Sources []Provenance
}

// Known returns a fact a mapper determined, attributed to the given sources.
func Known[T any](value T, sources ...Provenance) Fact[T] {
	return Fact[T]{State: FactKnown, value: value, Sources: sources}
}

// Unknown returns a fact the plan does not determine.
func Unknown[T any](sources ...Provenance) Fact[T] {
	return Fact[T]{State: FactUnknown, Sources: sources}
}

// Absent returns a fact for a field the plan never mentions.
func Absent[T any](sources ...Provenance) Fact[T] {
	return Fact[T]{State: FactAbsent, Sources: sources}
}

// Redacted returns a fact whose source value was sensitive and discarded.
func Redacted[T any](sources ...Provenance) Fact[T] {
	return Fact[T]{State: FactRedacted, Sources: sources}
}

// IsKnown reports whether the fact carries a determined value.
func (f Fact[T]) IsKnown() bool { return f.State == FactKnown }

// Get returns the value, or the zero value for any state but FactKnown. Check
// IsKnown before trusting it: for a boolean capability, false is also a real
// answer.
func (f Fact[T]) Get() T {
	if f.State != FactKnown {
		var zero T
		return zero
	}
	return f.value
}

// Canonical returns the fact with its provenance sorted and deduplicated, so
// that evidence derived from it is stable across runs.
func (f Fact[T]) Canonical() Fact[T] {
	out := f
	out.Sources = slices.Clone(f.Sources)
	slices.SortStableFunc(out.Sources, compareProvenance)
	out.Sources = slices.Compact(out.Sources)
	return out
}

func compareProvenance(a, b Provenance) int {
	if c := cmp.Compare(a.ResourceAddress, b.ResourceAddress); c != 0 {
		return c
	}
	if c := cmp.Compare(a.AttributePath, b.AttributePath); c != 0 {
		return c
	}
	return cmp.Compare(string(a.Cloud), string(b.Cloud))
}
