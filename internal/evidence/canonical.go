package evidence

import (
	"cmp"
	"slices"
)

// Canonical returns a deep copy of b whose collections are sorted into the
// documented canonical order. The caller's bundle is never modified, so a
// bundle can be rendered more than once without observable side effects.
//
// Verification entries keep the order the producer chose: they describe
// coverage in a meaningful sequence rather than a sortable set.
func Canonical(b Bundle) Bundle {
	out := b

	out.Verification = nonNilVerification(slices.Clone(b.Verification))

	out.Findings = nonNilFindings(slices.Clone(b.Findings))
	for i := range out.Findings {
		out.Findings[i].Resource = cloneResource(out.Findings[i].Resource)
		out.Findings[i].Expected = cloneExpected(out.Findings[i].Expected)
		out.Findings[i].Observed = cloneObserved(out.Findings[i].Observed)
		out.Findings[i].Evidence = canonicalEvidence(out.Findings[i].Evidence)
	}
	slices.SortStableFunc(out.Findings, compareFindings)

	out.Unknowns = nonNilUnknowns(slices.Clone(b.Unknowns))
	for i := range out.Unknowns {
		out.Unknowns[i].ResourceAddress = cloneString(out.Unknowns[i].ResourceAddress)
		out.Unknowns[i].Evidence = canonicalEvidence(out.Unknowns[i].Evidence)
	}
	slices.SortStableFunc(out.Unknowns, compareUnknowns)

	return out
}

// compareFindings orders findings by descending severity, then ascending rule
// identifier, resource address, and claim — the keys a reader scans by. The
// remaining fields follow as tiebreaks so that the chain is total over
// everything a finding can hold: two findings that differ in any field at all
// compare unequal, and canonical output therefore depends only on content,
// never on the order the producer appended them in.
func compareFindings(a, b Finding) int {
	if c := cmp.Compare(b.Severity.rank(), a.Severity.rank()); c != 0 {
		return c
	}
	if c := cmp.Compare(a.RuleID, b.RuleID); c != 0 {
		return c
	}
	if c := cmp.Compare(resourceAddress(a.Resource), resourceAddress(b.Resource)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Claim, b.Claim); c != 0 {
		return c
	}
	if c := cmp.Compare(string(a.Disposition), string(b.Disposition)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Remediation, b.Remediation); c != 0 {
		return c
	}
	if c := compareResource(a.Resource, b.Resource); c != 0 {
		return c
	}
	if c := compareExpected(a.Expected, b.Expected); c != 0 {
		return c
	}
	if c := compareObserved(a.Observed, b.Observed); c != 0 {
		return c
	}
	return compareEvidenceSlice(a.Evidence, b.Evidence)
}

// compareUnknowns orders unknowns by check identifier, then resource address,
// then reason, then the remaining fields. Like compareFindings the chain is
// total. The required flag is compared explicitly: it is the field that decides
// whether a PASS is possible, so two otherwise identical unknowns must not be
// left to sort by input position.
func compareUnknowns(a, b Unknown) int {
	if c := cmp.Compare(a.CheckID, b.CheckID); c != 0 {
		return c
	}
	if c := cmp.Compare(derefString(a.ResourceAddress), derefString(b.ResourceAddress)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Reason, b.Reason); c != 0 {
		return c
	}
	if c := compareBool(a.Required, b.Required); c != 0 {
		return c
	}
	return compareEvidenceSlice(a.Evidence, b.Evidence)
}

// compareResource orders optional resources. A finding without a resource sorts
// before any finding with one.
func compareResource(a, b *Resource) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	if c := cmp.Compare(a.Address, b.Address); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Provider, b.Provider); c != 0 {
		return c
	}
	return cmp.Compare(string(a.Cloud), string(b.Cloud))
}

// compareExpected orders optional expectations.
func compareExpected(a, b *ExpectedFact) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	if c := cmp.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	return compareScalar(a.Value, b.Value)
}

// compareObserved orders optional observations by path, then state, then value.
func compareObserved(a, b *ObservedFact) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	if c := cmp.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	if c := cmp.Compare(string(a.State), string(b.State)); c != 0 {
		return c
	}
	return compareScalar(a.Value, b.Value)
}

// compareEvidenceSlice orders two already-sorted evidence lists element by
// element, shorter list first when one is a prefix of the other.
func compareEvidenceSlice(a, b []EvidenceRef) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := compareEvidence(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(a), len(b))
}

// compareEvidence orders one pair of evidence references.
func compareEvidence(a, b EvidenceRef) int {
	if c := cmp.Compare(a.Source, b.Source); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ResourceAddress, b.ResourceAddress); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Path, b.Path); c != 0 {
		return c
	}
	return compareBool(a.Redacted, b.Redacted)
}

// nonNilVerification, nonNilFindings, and nonNilUnknowns replace a nil slice
// with an empty one so that canonical JSON always renders [] rather than null.
// An empty collection and an absent collection mean the same thing in the
// contract, and consumers should not have to handle both spellings.
func nonNilVerification(s []Verification) []Verification {
	if s == nil {
		return []Verification{}
	}
	return s
}

func nonNilFindings(s []Finding) []Finding {
	if s == nil {
		return []Finding{}
	}
	return s
}

func nonNilUnknowns(s []Unknown) []Unknown {
	if s == nil {
		return []Unknown{}
	}
	return s
}

// canonicalEvidence returns a sorted copy of refs, normalizing nil to an empty
// slice so that canonical JSON renders [] rather than null.
func canonicalEvidence(refs []EvidenceRef) []EvidenceRef {
	out := slices.Clone(refs)
	if out == nil {
		out = []EvidenceRef{}
	}
	slices.SortStableFunc(out, compareEvidence)
	return out
}

// compareBool orders false before true.
func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case !a:
		return -1
	default:
		return 1
	}
}

// resourceAddress returns the address of r, or the empty string when the
// finding has no resource.
func resourceAddress(r *Resource) string {
	if r == nil {
		return ""
	}
	return r.Address
}

// derefString returns the pointed-to string, or the empty string for nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func cloneString(s *string) *string {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}

func cloneResource(r *Resource) *Resource {
	if r == nil {
		return nil
	}
	v := *r
	return &v
}

func cloneExpected(f *ExpectedFact) *ExpectedFact {
	if f == nil {
		return nil
	}
	v := *f
	v.Value = cloneScalar(f.Value)
	return &v
}

func cloneObserved(f *ObservedFact) *ObservedFact {
	if f == nil {
		return nil
	}
	v := *f
	v.Value = cloneScalar(f.Value)
	return &v
}

func cloneScalar(s *Scalar) *Scalar {
	if s == nil {
		return nil
	}
	v := *s
	return &v
}
