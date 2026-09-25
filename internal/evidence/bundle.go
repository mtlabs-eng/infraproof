package evidence

// Bundle is the Version 1 Evidence Bundle. Field order matches the documented
// key order, so encoding/json emits canonical output without a custom
// marshaller.
type Bundle struct {
	// SchemaVersion is the contract version of this bundle, such as "1.0".
	SchemaVersion string `json:"schema_version"`
	// Decision is the overall verdict.
	Decision Decision `json:"decision"`
	// Summary states the conclusion in one safe, human-readable sentence.
	Summary string `json:"summary"`
	// Subject identifies the inputs the verdict was reached from.
	Subject Subject `json:"subject"`
	// Verification records which checks ran and how completely.
	Verification []Verification `json:"verification"`
	// Findings are the evaluated rule outcomes.
	Findings []Finding `json:"findings"`
	// Unknowns are first-class records of evidence that was not available.
	Unknowns []Unknown `json:"unknowns"`
}

// Subject identifies the verification inputs without embedding them.
type Subject struct {
	// IntentSource names the intent contract the change was compared against.
	IntentSource string `json:"intent_source"`
	// IntentDigest is a "sha256:"-prefixed digest of the exact contract bytes.
	//
	// A path names where a contract was read from and not which contract it
	// was: a file edited between runs, a symlink, a checkout on another branch.
	// Without this the plan was identifiable and the thing it was compared
	// against was not.
	IntentDigest string `json:"intent_digest"`
	// PlanFormatVersion is the format version of the supplied plan.
	PlanFormatVersion string `json:"plan_format_version"`
	// PlanDigest is a "sha256:"-prefixed digest of the exact plan bytes. It
	// allows correlation with the input without copying the plan into output.
	PlanDigest string `json:"plan_digest"`
}

// Verification records the coverage of one named check.
type Verification struct {
	// Name is the stable identifier of the check, such as "terraform_plan".
	Name string `json:"name"`
	// Status is how completely the check could be performed.
	Status VerificationStatus `json:"status"`
	// Method names the technique used, or "none" when the check did not run.
	Method string `json:"method"`
}

// Finding is one evaluated rule outcome, traceable to its source data.
type Finding struct {
	// RuleID is the stable identifier of the rule that produced the finding.
	RuleID string `json:"rule_id"`
	// Severity communicates impact.
	Severity Severity `json:"severity"`
	// Disposition communicates enforcement.
	Disposition Disposition `json:"disposition"`
	// Claim states the finding in one concise sentence.
	Claim string `json:"claim"`
	// Resource is the affected resource, when the finding has one.
	Resource *Resource `json:"resource,omitempty"`
	// Expected is the declared expectation, when the rule has one.
	Expected *ExpectedFact `json:"expected,omitempty"`
	// Observed is what the evidence showed, when the rule inspected a field.
	Observed *ObservedFact `json:"observed,omitempty"`
	// Evidence locates the source data supporting the claim.
	Evidence []EvidenceRef `json:"evidence"`
	// Remediation describes the fix, or explains why none is available.
	Remediation string `json:"remediation"`
}

// Resource identifies the infrastructure resource a finding concerns.
type Resource struct {
	// Address is the resource address, such as "aws_s3_bucket.assets".
	Address string `json:"address"`
	// Provider is the fully qualified provider source address.
	Provider string `json:"provider"`
	// Cloud is the cloud the resource belongs to.
	Cloud Cloud `json:"cloud"`
}

// ExpectedFact is a value the intent or policy required at a normalized path.
type ExpectedFact struct {
	// Path is the normalized capability path, such as
	// "object_storage.public_access".
	Path string `json:"path"`
	// Value is the required value.
	Value *Scalar `json:"value"`
}

// ObservedFact is what the evidence showed at a normalized path. Its value is
// carried only when State is FactKnown, so an unknown, absent, or sensitive
// field cannot present a value at all.
type ObservedFact struct {
	// Path is the normalized capability path.
	Path string `json:"path"`
	// State records what is known about the value.
	State FactState `json:"state"`
	// Value is present only when State is FactKnown.
	Value *Scalar `json:"value,omitempty"`
}

// KnownFact returns an observed fact with a definite value.
func KnownFact(path string, value *Scalar) *ObservedFact {
	return &ObservedFact{Path: path, State: FactKnown, Value: value}
}

// UnknownFact returns an observed fact whose value the source had not yet
// determined.
func UnknownFact(path string) *ObservedFact {
	return &ObservedFact{Path: path, State: FactUnknown}
}

// AbsentFact returns an observed fact for a field the source did not contain.
// Absence is not a provider default.
func AbsentFact(path string) *ObservedFact {
	return &ObservedFact{Path: path, State: FactAbsent}
}

// RedactedFact returns an observed fact for a field the source marked
// sensitive. It cannot carry a value.
func RedactedFact(path string) *ObservedFact {
	return &ObservedFact{Path: path, State: FactRedacted}
}

// EvidenceRef locates source data. It has no value field by construction, so
// raw sensitive data cannot travel through evidence.
type EvidenceRef struct {
	// Source names the evidence source, such as "terraform_plan".
	Source string `json:"source"`
	// ResourceAddress is the resource the data was read from, when applicable.
	ResourceAddress string `json:"resource_address"`
	// Path locates the data within the source.
	Path string `json:"path"`
	// Redacted reports that the located value is sensitive and was not read.
	Redacted bool `json:"redacted"`
}

// Unknown records evidence that was required or expected but unavailable.
type Unknown struct {
	// CheckID is the stable identifier of the check that could not conclude.
	CheckID string `json:"check_id"`
	// Required reports whether this absence prevents a PASS decision.
	Required bool `json:"required"`
	// Reason is a safe human-readable explanation carrying no sensitive value.
	Reason string `json:"reason"`
	// ResourceAddress is the affected resource, or nil when not resource
	// specific. It is rendered as null rather than omitted so that "not
	// applicable" stays distinguishable from an empty address.
	ResourceAddress *string `json:"resource_address"`
	// Evidence locates non-sensitive source data related to the gap.
	Evidence []EvidenceRef `json:"evidence"`
}
