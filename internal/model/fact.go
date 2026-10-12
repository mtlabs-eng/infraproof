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
	// FactKnown means a mapper determined the value; Method says how.
	FactKnown FactState = "KNOWN"
	// FactUnknown means the plan does not determine the value.
	FactUnknown FactState = "UNKNOWN"
	// FactAbsent means the plan does not mention the field at all. It is not a
	// provider default.
	FactAbsent FactState = "ABSENT"
	// FactRedacted means the source value was marked sensitive and discarded.
	FactRedacted FactState = "REDACTED"
)

// Method is how a mapper established a KNOWN fact's value. Only a KNOWN fact has
// one; the other states established nothing.
//
// The zero value is not a method. A fact nobody gave one reaches the bundle as
// an unrecognized method and fails validation, rather than reading as stated --
// a default of "stated" would present every defaulted, inferred or interpreted
// value as one the plan wrote, which is the defect milestone 10 removes.
type Method string

const (
	// MethodStated means the plan's configuration records that the author
	// wrote the argument with a value, and the plan carries that value.
	MethodStated Method = "plan-stated-value"
	// MethodProviderDefault means the configuration records the argument as
	// unwritten, or written as null, and the value is not carried from prior
	// state: the provider's documented default.
	MethodProviderDefault Method = "provider-default"
	// MethodPolicyDocument means the value is this build's reading of a JSON
	// policy document.
	MethodPolicyDocument Method = "policy-document-interpreted"
	// MethodReferenceResolved means the value is obtainable only by resolving a
	// reference, such as the security groups a database reaches through
	// vpc_security_group_ids. A join that only locates a grant written on its
	// own resource is not one.
	MethodReferenceResolved Method = "reference-resolved"
	// MethodDocumentedTable means the value comes from a closed, documented table
	// in this build.
	MethodDocumentedTable Method = "documented-table"
	// MethodPriorState means the change keeps an existing object, the plan
	// carries the value it had, and the configuration does not record the
	// author writing it -- unwritten, written as null, or written as a constant
	// the carried value contradicts, as lifecycle { ignore_changes } leaves it.
	MethodPriorState Method = "prior-state"
	// MethodConfigurationUnrecorded means the plan does not record whether the
	// author wrote the argument.
	MethodConfigurationUnrecorded Method = "configuration-unrecorded"
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
	method  Method
	Sources []Provenance
}

// Known returns a fact a mapper determined, how it determined it, and the
// sources it is attributed to. There is no constructor without a method, so
// every site that establishes a value has to say how.
func Known[T any](value T, method Method, sources ...Provenance) Fact[T] {
	return Fact[T]{State: FactKnown, value: value, method: method, Sources: sources}
}

// Method returns how the value was established, or "" for any state but
// FactKnown.
func (f Fact[T]) Method() Method {
	if f.State != FactKnown {
		return ""
	}
	return f.method
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
