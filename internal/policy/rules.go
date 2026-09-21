package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// Rule and check identifiers, stable across releases because consumers branch
// on them.
const (
	// RuleDestructiveChange reports a change that destroys an existing object.
	RuleDestructiveChange = "DESTRUCTIVE_CHANGE"
	// RuleCloudNotAllowed reports a plan affecting a cloud the contract does
	// not permit.
	RuleCloudNotAllowed = "CLOUD_NOT_ALLOWED"
	// RuleEnvironmentMismatch reports a resource declaring an environment the
	// contract was not written for.
	RuleEnvironmentMismatch = "ENVIRONMENT_MISMATCH"

	// CheckCloudDeterminable reports a resource whose cloud could not be
	// determined, so it could not be checked against the allowed set.
	CheckCloudDeterminable = "CLOUD_DETERMINABLE"
	// CheckEnvironmentEvidence reports a resource carrying no readable
	// environment declaration.
	CheckEnvironmentEvidence = "ENVIRONMENT_EVIDENCE_AVAILABLE"
	// CheckContractUnevaluated reports a contract field this build loaded but
	// evaluated nothing against.
	CheckContractUnevaluated = "CONTRACT_FIELD_UNEVALUATED"
	// CheckContractFamilyAbsent reports a declaration the plan gave nothing to
	// apply to.
	CheckContractFamilyAbsent = "CONTRACT_DECLARATION_UNEXERCISED"
	// CheckResourceEvaluated reports a resource this build understood and no
	// rule judged.
	CheckResourceEvaluated = "RESOURCE_EVALUATED"
)

// DestructiveChange reports changes that destroy an existing object.
//
// Destruction is visible in the plan's actions and needs no provider
// knowledge, so this rule applies to every resource — including one no mapper
// understood. A resource this build cannot interpret is exactly the one whose
// destruction a reader most needs told about.
func DestructiveChange(contract intent.Contract, graph model.Graph) Result {
	var result Result

	disposition := evidence.DispositionBlock
	claim := "The change destroys an existing object, which the intent contract forbids."
	remediation := "Remove the destructive change, or record destruction as permitted in the intent contract."
	if contract.DestructiveChanges == intent.DestructiveAllowedWithWarning {
		disposition = evidence.DispositionWarn
		claim = "The change destroys an existing object, which the intent contract permits with a warning."
		remediation = "Confirm that destroying this object is intended before proceeding."
	}

	for _, resource := range graph.Resources {
		if !resource.Destructive {
			continue
		}
		result.Findings = append(result.Findings, evidence.Finding{
			RuleID: RuleDestructiveChange,
			// Severity records impact and does not move with the contract: the
			// same destruction is equally destructive under either policy.
			Severity:    evidence.SeverityHigh,
			Disposition: disposition,
			Claim:       claim,
			Resource:    resourceRef(resource),
			Observed:    evidence.KnownFact("change.destructive", evidence.Bool(true)),
			Expected: &evidence.ExpectedFact{
				Path:  "change.destructive",
				Value: evidence.Bool(false),
			},
			Evidence: []evidence.EvidenceRef{{
				Source:          "terraform_plan",
				ResourceAddress: inline(resource.Address),
				Path:            "resource_changes[].change.actions",
			}},
			Remediation: remediation,
		})
	}

	return result
}

// CloudAllowed reports resources in a cloud the contract does not permit.
//
// A resource no mapper claimed has no stated cloud, and an unstated cloud is
// not evidence of an allowed one. Reading it as allowed would let an entire
// provider the contract forbids pass unremarked, for no better reason than that
// this build cannot read it.
func CloudAllowed(contract intent.Contract, graph model.Graph) Result {
	var result Result

	reported := map[model.Cloud]bool{}
	for _, resource := range graph.Resources {
		if resource.Cloud == model.CloudUnknown || resource.Cloud == "" {
			address := inline(resource.Address)
			result.Unknowns = append(result.Unknowns, evidence.Unknown{
				CheckID: CheckCloudDeterminable,
				// Required: an unreadable resource could be in any cloud,
				// including one the contract forbids. That is a question the
				// run could not answer, not a limit on an answer it gave.
				Required: true,
				// The reason says what is true. The plan may well name a
				// provider for this resource; what is missing is a mapper that
				// interprets it, and without one the cloud is not established
				// in the normalized model the rules read. Claiming the cloud
				// was undeterminable would put a false statement inside a
				// bundle whose whole value is that its statements are true.
				Reason: "No mapper interpreted this resource, so it was not normalized and could not " +
					"be checked against the allowed clouds.",
				ResourceAddress: &address,
				Evidence:        []evidence.EvidenceRef{},
			})
			continue
		}
		if contract.AllowsCloud(string(resource.Cloud)) || reported[resource.Cloud] {
			continue
		}
		reported[resource.Cloud] = true

		// The violation is the cloud, not the resource: a plan with fifty
		// buckets in one forbidden cloud has one problem, not fifty.
		result.Findings = append(result.Findings, evidence.Finding{
			RuleID:      RuleCloudNotAllowed,
			Severity:    evidence.SeverityCritical,
			Disposition: evidence.DispositionBlock,
			Claim: fmt.Sprintf("The change affects %s, which the intent contract does not allow.",
				resource.Cloud),
			Resource: resourceRef(resource),
			Expected: &evidence.ExpectedFact{
				Path:  "resource.cloud",
				Value: evidence.String(strings.Join(contract.AllowedClouds, ", ")),
			},
			Observed: evidence.KnownFact("resource.cloud", evidence.String(string(resource.Cloud))),
			Evidence: []evidence.EvidenceRef{{
				Source:          "terraform_plan",
				ResourceAddress: inline(resource.Address),
				Path:            "resource_changes[].provider_name",
			}},
			Remediation: "Remove the resources in this cloud, or add the cloud to allowed_clouds in the intent contract.",
		})
	}

	return result
}

// EnvironmentMatch reports resources declaring an environment the contract was
// not written for.
//
// Only an explicit declaration is compared. docs/INTENT-CONTRACT.md is direct
// about the limit: filename guessing alone is not sufficient evidence for
// blocking, and a module path or a provider alias is the same kind of guess
// wearing different clothes. A resource with no readable declaration is
// reported as evidence this run did not have, never as a disagreement.
func EnvironmentMatch(contract intent.Contract, graph model.Graph) Result {
	var result Result

	for _, resource := range graph.Resources {
		declared := resource.Environment

		if !declared.IsKnown() {
			address := inline(resource.Address)
			result.Unknowns = append(result.Unknowns, evidence.Unknown{
				CheckID: CheckEnvironmentEvidence,
				// The line is not at "absent". A resource carrying no
				// environment tag says nothing about which environment it is
				// in; that is the common case, and requiring it would make
				// every untagged plan UNKNOWN. A resource that declares one
				// this run could not read is a different fact: the plan
				// asserts something bearing directly on the question and the
				// run could not evaluate it, which is what a required unknown
				// is for.
				Required:        declared.State != model.FactAbsent && declared.State != "",
				Reason:          environmentReason(declared.State),
				ResourceAddress: &address,
				Evidence:        environmentEvidence(declared),
			})
			continue
		}
		// The comparison is exact. A tag key is a convention and its
		// capitalization is incidental, which is why the key is matched without
		// regard to case; a tag value is a name the author chose, and two
		// spellings of it are two names. Folding them would let "Production"
		// satisfy a contract written for "production", and where those are
		// deliberately distinct environments the mismatch this rule exists to
		// find would go unreported.
		if declared.Get() == contract.Environment {
			continue
		}

		result.Findings = append(result.Findings, evidence.Finding{
			RuleID:      RuleEnvironmentMismatch,
			Severity:    evidence.SeverityHigh,
			Disposition: evidence.DispositionBlock,
			Claim:       "The resource declares an environment the intent contract was not written for.",
			Resource:    resourceRef(resource),
			Expected: &evidence.ExpectedFact{
				Path:  "resource.environment",
				Value: evidence.String(contract.Environment),
			},
			Observed: evidence.KnownFact("resource.environment", evidence.String(inline(declared.Get()))),
			Evidence: environmentEvidence(declared),
			Remediation: "Target the environment the contract declares, or write the contract for the " +
				"environment this change affects.",
		})
	}

	return result
}

func environmentReason(state model.FactState) string {
	switch state {
	case model.FactRedacted:
		return "The environment declaration is marked sensitive, so it could not be compared with the contract."
	case model.FactUnknown:
		return "The environment declaration could not be determined — it is either not known until apply, " +
			"or the resource carries more than one declaration and they disagree — so it could not be " +
			"compared with the contract."
	default:
		return "The resource declares no environment, so it could not be compared with the contract."
	}
}

func environmentEvidence(fact model.Fact[string]) []evidence.EvidenceRef {
	canonical := fact.Canonical()
	refs := make([]evidence.EvidenceRef, 0, len(canonical.Sources))
	for _, source := range canonical.Sources {
		refs = append(refs, evidence.EvidenceRef{
			Source:          "terraform_plan",
			ResourceAddress: inline(source.ResourceAddress),
			Path:            inline(source.AttributePath),
			Redacted:        fact.State == model.FactRedacted,
		})
	}
	return refs
}

// ContractUnevaluated reports contract fields this build loaded and checked
// nothing against.
//
// A restriction written in a contract and enforced by nothing is the
// product-level form of reading absence as permission: a reader sees the
// constraint and a PASS beside it, and concludes it held.
func ContractUnevaluated(contract intent.Contract) Result {
	var result Result

	for _, field := range contract.Unevaluated() {
		result.Unknowns = append(result.Unknowns, evidence.Unknown{
			CheckID: CheckContractUnevaluated,
			// Not required: the contract asked for something this build cannot
			// check, which limits the report rather than invalidating the
			// checks that did run.
			Required: false,
			Reason: fmt.Sprintf(
				"The contract declares %s, which this build loads and validates but does not evaluate.", field),
			Evidence: []evidence.EvidenceRef{{Source: "intent_contract", Path: field}},
		})
	}

	slices.SortStableFunc(result.Unknowns, func(a, b evidence.Unknown) int {
		return strings.Compare(a.Reason, b.Reason)
	})
	return result
}

// ContractCoverage reports declarations the plan gave nothing to apply to.
//
// A contract requiring private object storage, evaluated against a plan holding
// none, otherwise produces a PASS with no findings and no unknowns: the reader
// is told the change is consistent with the contract in every supported check,
// when in truth no check had anything to run against. That is reading absence
// as permission at the level above a rule — not a fact wrongly concluded, but a
// conclusion drawn from no facts at all.
//
// It is not required. Nothing here is wrong with the change: a contract may
// legitimately describe more than one plan carries out. What must not happen is
// for that to be indistinguishable from a contract whose requirements were
// checked and met.
func ContractCoverage(contract intent.Contract, graph model.Graph) Result {
	var result Result

	for _, declared := range contract.Resources {
		if declared.Exposure == intent.ExposureUnspecified {
			// The author declined to commit, so there was no requirement to
			// exercise and nothing to report as unexercised.
			continue
		}
		if len(graph.OfFamily(model.Family(declared.Family))) > 0 {
			continue
		}

		result.Unknowns = append(result.Unknowns, evidence.Unknown{
			CheckID:  CheckContractFamilyAbsent,
			Required: false,
			Reason: fmt.Sprintf(
				"The contract declares %s exposure for %s, and the plan contains no resource of that "+
					"family, so the declaration was not exercised.", declared.Exposure, declared.Family),
			Evidence: []evidence.EvidenceRef{{Source: "intent_contract", Path: "resources"}},
		})
	}

	slices.SortStableFunc(result.Unknowns, func(a, b evidence.Unknown) int {
		return strings.Compare(a.Reason, b.Reason)
	})
	return result
}

// ResourceCoverage reports resources a mapper understood and no rule judged.
//
// Coverage otherwise holds by accident. Every resource is currently either
// opaque, which raises a required unknown because its cloud is not established,
// or object storage, which the exposure rule judges. A second mapped family
// would break that with no symptom: the resource produces no finding, raises no
// unknown, and the PASS beside it means "not checked" while reading as "checked
// and fine". That is absence read as permission at the level above a rule.
//
// evaluated is what the rules reported judging, so this cannot go stale. A rule
// added later that judges a new family reports it and this falls silent; a
// mapper added without a rule does not, and this says so.
func ResourceCoverage(graph model.Graph, evaluated []string) Result {
	var result Result

	judged := make(map[string]bool, len(evaluated))
	for _, address := range evaluated {
		judged[address] = true
	}

	for _, resource := range graph.Resources {
		switch {
		case !resource.Interpreted:
			// Already reported, and more usefully: an opaque resource raises a
			// required unknown naming the cloud that could not be established.
			// Saying it twice in different words tells a reader less.
			continue
		case judged[resource.Address]:
			continue
		}

		address := inline(resource.Address)
		result.Unknowns = append(result.Unknowns, evidence.Unknown{
			CheckID: CheckResourceEvaluated,
			// Required. The resource was understood well enough to be
			// normalized, so this build knows what it is and has no rule for
			// it — which is a question this run did not answer, not a limit on
			// an answer it gave.
			Required: true,
			Reason: fmt.Sprintf(
				"This resource was normalized as %s, and no rule in this build judges that family, "+
					"so nothing about it was checked against the contract.", resource.Family),
			ResourceAddress: &address,
			Evidence:        []evidence.EvidenceRef{},
		})
	}

	return result
}

func resourceRef(resource model.NormalizedResource) *evidence.Resource {
	return &evidence.Resource{
		Address:  inline(resource.Address),
		Provider: inline(resource.Provider),
		Cloud:    bundleCloud(resource.Cloud),
	}
}

// inline makes plan-derived text usable as a bundle field.
//
// The Evidence Bundle forbids a line break in anything that reaches the report
// as inline text, because a break ends a paragraph and lets a value forge a
// heading in a document a human is expected to trust. A plan can contain one —
// in a tag value, in principle in an address — and that is the plan's doing, not
// this program's. Refusing to produce a bundle would report our own invariant as
// broken and tell the reader nothing about their change, so the value is carried
// on one line instead: the reader still sees what the plan said, and sees it as
// a value rather than as structure.
func inline(text string) string {
	if !strings.ContainsAny(text, "\r\n") {
		return text
	}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	return strings.ReplaceAll(text, "\n", " ")
}
