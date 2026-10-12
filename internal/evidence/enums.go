package evidence

// Decision is the overall verdict of a verification.
type Decision string

const (
	// DecisionPass means every required check ran and nothing material remains.
	DecisionPass Decision = "PASS"
	// DecisionWarn means the change is understood but needs a human decision.
	DecisionWarn Decision = "WARN"
	// DecisionBlock means deterministic evidence proves a blocking violation.
	DecisionBlock Decision = "BLOCK"
	// DecisionUnknown means evidence required for a safe conclusion is absent.
	DecisionUnknown Decision = "UNKNOWN"
)

// Valid reports whether d is a member of the Version 1 decision enumeration.
func (d Decision) Valid() bool {
	switch d {
	case DecisionPass, DecisionWarn, DecisionBlock, DecisionUnknown:
		return true
	}
	return false
}

// Severity communicates the impact of a finding. It never decides enforcement;
// see Disposition.
type Severity string

const (
	// SeverityInfo records an observation with no impact.
	SeverityInfo Severity = "INFO"
	// SeverityLow records minor impact.
	SeverityLow Severity = "LOW"
	// SeverityMedium records moderate impact.
	SeverityMedium Severity = "MEDIUM"
	// SeverityHigh records significant impact.
	SeverityHigh Severity = "HIGH"
	// SeverityCritical records the highest impact.
	SeverityCritical Severity = "CRITICAL"
)

// Valid reports whether s is a member of the Version 1 severity enumeration.
func (s Severity) Valid() bool {
	_, ok := severityRanks[s]
	return ok
}

// severityRanks orders severities from least to most impactful. Canonical
// output sorts findings by descending rank.
var severityRanks = map[Severity]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// rank returns the sort rank of s. An unrecognized severity ranks below INFO so
// that ordering stays total even for a bundle that has not been validated.
func (s Severity) rank() int {
	if r, ok := severityRanks[s]; ok {
		return r
	}
	return -1
}

// Disposition communicates the enforcement effect of a finding, independently
// of its severity.
type Disposition string

const (
	// DispositionInfo does not affect the decision.
	DispositionInfo Disposition = "INFO"
	// DispositionWarn requires an explicit human decision.
	DispositionWarn Disposition = "WARN"
	// DispositionBlock prevents the change from proceeding.
	DispositionBlock Disposition = "BLOCK"
)

// Valid reports whether d is a member of the Version 1 disposition enumeration.
func (d Disposition) Valid() bool {
	switch d {
	case DispositionInfo, DispositionWarn, DispositionBlock:
		return true
	}
	return false
}

// FactState records what is known about an observed value. It is deliberately
// separate from the value itself so that an absent or sensitive field can never
// be mistaken for a safe default.
type FactState string

const (
	// FactKnown means the source supplied a definite value.
	FactKnown FactState = "KNOWN"
	// FactUnknown means the source marked the value as not yet known.
	FactUnknown FactState = "UNKNOWN"
	// FactAbsent means the source field was not present. It is not a default.
	FactAbsent FactState = "ABSENT"
	// FactRedacted means the source marked the value as sensitive.
	FactRedacted FactState = "REDACTED"
)

// Valid reports whether s is a member of the Version 1 fact-state enumeration.
func (s FactState) Valid() bool {
	switch s {
	case FactKnown, FactUnknown, FactAbsent, FactRedacted:
		return true
	}
	return false
}

// VerificationStatus records how completely a named check could be performed.
type VerificationStatus string

const (
	// VerificationVerified means the check ran against sufficient evidence.
	VerificationVerified VerificationStatus = "VERIFIED"
	// VerificationPartial means the check ran against incomplete evidence.
	VerificationPartial VerificationStatus = "PARTIAL"
	// VerificationNotAvailable means the evidence source was not supplied.
	VerificationNotAvailable VerificationStatus = "NOT_AVAILABLE"
	// VerificationFailed means the check could not complete.
	VerificationFailed VerificationStatus = "FAILED"
)

// Valid reports whether s is a member of the Version 1 verification-status
// enumeration.
func (s VerificationStatus) Valid() bool {
	switch s {
	case VerificationVerified, VerificationPartial, VerificationNotAvailable, VerificationFailed:
		return true
	}
	return false
}

// Cloud identifies the cloud a resource belongs to.
type Cloud string

const (
	// CloudAWS identifies Amazon Web Services.
	CloudAWS Cloud = "aws"
	// CloudAzure identifies Microsoft Azure.
	CloudAzure Cloud = "azure"
	// CloudGCP identifies Google Cloud Platform.
	CloudGCP Cloud = "gcp"
	// CloudUnknown identifies a resource whose cloud could not be determined.
	CloudUnknown Cloud = "unknown"
)

// Valid reports whether c is a member of the Version 1 cloud enumeration.
func (c Cloud) Valid() bool {
	switch c {
	case CloudAWS, CloudAzure, CloudGCP, CloudUnknown:
		return true
	}
	return false
}

// VerificationMethod is how one fact a finding rests on was established. It is
// provenance, not technique: a reader is told whether the verdict rests on what
// the plan states, on a provider default, or on something this build inferred.
//
// It is never load-bearing. No decision, disposition or exit code depends on it.
type VerificationMethod string

const (
	// MethodPlanStatedValue means the plan's configuration records that the
	// author wrote the argument with a value, and the plan carries that value.
	// The policy also assigns it to resource.cloud, which it reads from a
	// change's provider_name through this build's provider-name table.
	MethodPlanStatedValue VerificationMethod = "plan-stated-value"
	// MethodProviderDefault means the configuration records the argument as
	// unwritten, or written as null, and the value is not one carried from
	// prior state: the provider's documented default, on a new object or where
	// the plan moves the value to it.
	MethodProviderDefault VerificationMethod = "provider-default"
	// MethodPolicyDocumentInterpreted means the value results from this build's
	// reading of a JSON policy document.
	MethodPolicyDocumentInterpreted VerificationMethod = "policy-document-interpreted"
	// MethodReferenceResolved means the value is obtainable only by resolving a
	// reference: the security groups a database reaches through
	// vpc_security_group_ids. A grant written on its own resource and joined to
	// what it applies to by a reference is stated; the join only locates it.
	MethodReferenceResolved VerificationMethod = "reference-resolved"
	// MethodDocumentedTable means the value comes from a closed, documented table
	// in this build.
	MethodDocumentedTable VerificationMethod = "documented-table"
	// MethodPlanAction means the value is the classification of the plan's
	// actions.
	MethodPlanAction VerificationMethod = "plan-action"
	// MethodIntentComparison means the fact is the comparison with the intent
	// contract.
	MethodIntentComparison VerificationMethod = "intent-comparison"
	// MethodPriorState means the change keeps an existing object, the plan
	// carries the value the object had, and the configuration does not record
	// the author writing it: unwritten, written as null, or written as a
	// constant the carried value contradicts, which is what
	// lifecycle { ignore_changes } leaves. Neither written by the author nor
	// the provider's default.
	MethodPriorState VerificationMethod = "prior-state"
	// MethodConfigurationUnrecorded means the plan does not record whether the
	// author wrote the argument, so its absence from the configuration proves
	// nothing either way.
	MethodConfigurationUnrecorded VerificationMethod = "configuration-unrecorded"
)

// Valid reports whether m is a member of the closed method set.
func (m VerificationMethod) Valid() bool {
	switch m {
	case MethodPlanStatedValue, MethodProviderDefault, MethodPolicyDocumentInterpreted,
		MethodReferenceResolved, MethodDocumentedTable, MethodPlanAction, MethodIntentComparison,
		MethodPriorState, MethodConfigurationUnrecorded:
		return true
	}
	return false
}
