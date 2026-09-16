package policy

import (
	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// Result is what a rule produced: findings, and the questions it could not
// answer. Unknowns are returned rather than swallowed, because a rule that
// quietly declines to conclude is indistinguishable from one that concluded
// everything is fine.
type Result struct {
	Findings []evidence.Finding
	Unknowns []evidence.Unknown
}

// Rule identifiers, stable across releases because consumers branch on them.
const (
	// RuleStoragePublic reports object storage the change exposes publicly.
	RuleStoragePublic = "STORAGE_PUBLIC"
	// CheckStoragePublicDeterminable reports that public exposure could not be
	// determined from the plan.
	CheckStoragePublicDeterminable = "STORAGE_PUBLIC_DETERMINABLE"
)

// StoragePublic reports object storage whose change grants public access.
//
// The claim is about the change, not about what will ultimately be reachable: a
// plan can prove that a change asks for public access, while whether the
// request takes effect may depend on an account-level block or an organization
// policy that no plan contains. Those limits are reported as unknowns alongside
// the finding rather than folded into it, so a reader sees both the violation
// and the boundary of the evidence for it.
func StoragePublic(graph model.Graph) Result {
	var result Result

	for _, resource := range graph.OfFamily(model.FamilyObjectStorage) {
		if resource.ObjectStorage == nil {
			// A control resource: understood, but exposure belongs to the
			// resource it controls.
			continue
		}
		capabilities := *resource.ObjectStorage

		switch {
		case capabilities.PublicAccess.IsKnown() && capabilities.PublicAccess.Get():
			result.Findings = append(result.Findings, publicFinding(resource, capabilities))
		case capabilities.PublicAccess.IsKnown():
			// The plan proves prevention. Nothing to report.
		default:
			result.Unknowns = append(result.Unknowns, undeterminedUnknown(resource, capabilities))
		}

		result.Unknowns = append(result.Unknowns, unresolvedUnknowns(resource, capabilities)...)
	}

	return result
}

func publicFinding(resource model.NormalizedResource, capabilities model.ObjectStorageCapabilities) evidence.Finding {
	return evidence.Finding{
		RuleID:      RuleStoragePublic,
		Severity:    evidence.SeverityCritical,
		Disposition: evidence.DispositionBlock,
		Claim:       "The change grants public access to object storage.",
		Resource: &evidence.Resource{
			Address:  resource.Address,
			Provider: resource.Provider,
			Cloud:    evidence.Cloud(resource.Cloud),
		},
		Expected: &evidence.ExpectedFact{
			Path:  "object_storage.public_access",
			Value: evidence.Bool(false),
		},
		Observed: evidence.KnownFact("object_storage.public_access", evidence.Bool(true)),
		Evidence: referencesOf(capabilities.PublicAccess),
		Remediation: "Remove the grant that exposes this storage publicly, or record the exposure as " +
			"intended in the intent contract.",
	}
}

func undeterminedUnknown(resource model.NormalizedResource, capabilities model.ObjectStorageCapabilities) evidence.Unknown {
	address := resource.Address
	return evidence.Unknown{
		CheckID:  CheckStoragePublicDeterminable,
		Required: true,
		Reason: "Public exposure could not be determined from the plan; the state of the deciding " +
			"value is " + string(capabilities.PublicAccess.State) + ".",
		ResourceAddress: &address,
		Evidence:        referencesOf(capabilities.PublicAccess),
	}
}

// unresolvedUnknowns reports controls that could change the answer but are not
// in the plan. They are not required: they bound the evidence rather than
// preventing a conclusion, so they must not on their own turn a PASS into an
// UNKNOWN.
func unresolvedUnknowns(resource model.NormalizedResource, capabilities model.ObjectStorageCapabilities) []evidence.Unknown {
	if len(capabilities.Unresolved) == 0 {
		return nil
	}

	address := resource.Address
	out := make([]evidence.Unknown, 0, len(capabilities.Unresolved))
	for _, control := range capabilities.Unresolved {
		out = append(out, evidence.Unknown{
			CheckID:         control.CheckID,
			Required:        false,
			Reason:          control.Reason,
			ResourceAddress: &address,
			Evidence:        []evidence.EvidenceRef{},
		})
	}
	return out
}

// referencesOf turns a fact's provenance into evidence. A reference locates the
// provider attribute a conclusion came from and can carry nothing else.
func referencesOf(fact model.Fact[bool]) []evidence.EvidenceRef {
	canonical := fact.Canonical()

	refs := make([]evidence.EvidenceRef, 0, len(canonical.Sources))
	for _, source := range canonical.Sources {
		refs = append(refs, evidence.EvidenceRef{
			Source:          "terraform_plan",
			ResourceAddress: source.ResourceAddress,
			Path:            source.AttributePath,
		})
	}
	return refs
}
