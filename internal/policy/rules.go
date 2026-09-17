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
				ResourceAddress: resource.Address,
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
			address := resource.Address
			result.Unknowns = append(result.Unknowns, evidence.Unknown{
				CheckID: CheckCloudDeterminable,
				// Required: an unreadable resource could be in any cloud,
				// including one the contract forbids. That is a question the
				// run could not answer, not a limit on an answer it gave.
				Required: true,
				Reason: "No mapper interpreted this resource, so the cloud it belongs to could not be " +
					"determined and could not be checked against the allowed set.",
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
				ResourceAddress: resource.Address,
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
			address := resource.Address
			result.Unknowns = append(result.Unknowns, evidence.Unknown{
				CheckID: CheckEnvironmentEvidence,
				// Not required. An untagged resource is the common case, and
				// escalating every untagged plan to UNKNOWN would make the
				// decision say nothing. It bounds the evidence rather than
				// preventing a conclusion.
				Required:        false,
				Reason:          environmentReason(declared.State),
				ResourceAddress: &address,
				Evidence:        environmentEvidence(declared),
			})
			continue
		}
		if strings.EqualFold(declared.Get(), contract.Environment) {
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
			Observed: evidence.KnownFact("resource.environment", evidence.String(declared.Get())),
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
		return "The environment declaration is not known until apply, so it could not be compared with the contract."
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
			ResourceAddress: source.ResourceAddress,
			Path:            source.AttributePath,
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

func resourceRef(resource model.NormalizedResource) *evidence.Resource {
	return &evidence.Resource{
		Address:  resource.Address,
		Provider: resource.Provider,
		Cloud:    bundleCloud(resource.Cloud),
	}
}
