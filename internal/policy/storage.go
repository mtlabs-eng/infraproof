package policy

import (
	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// Result is what a rule produced: findings, and the questions it could not
// answer. Unknowns are returned rather than swallowed, because a rule that
// quietly declines to conclude is indistinguishable from one that concluded
// everything is fine.
type Result struct {
	Findings []evidence.Finding
	Unknowns []evidence.Unknown
	// Evaluated names the resources whose capabilities this rule judged
	// against the contract, by address.
	//
	// It exists so that coverage can be derived rather than assumed. A rule
	// that reaches a resource and reaches no verdict about it leaves the same
	// silence as a rule that never ran, and silence is what a PASS is made of.
	// Reporting what was judged lets the engine say what was not, without
	// keeping a list of families that goes stale the moment one is added.
	//
	// Rules that apply to every resource regardless of family — destruction,
	// the allowed cloud set — do not populate it. They ask a question about the
	// change, not about what the resource is for, and answering it is not
	// evidence that the resource's own semantics were examined.
	Evaluated []string
}

// Rule identifiers, stable across releases because consumers branch on them.
const (
	// RuleStoragePublic reports object storage the change exposes publicly.
	RuleStoragePublic = "STORAGE_PUBLIC"
	// CheckStoragePublicDeterminable reports that public exposure could not be
	// determined from the plan.
	CheckStoragePublicDeterminable = "STORAGE_PUBLIC_DETERMINABLE"
)

// StorageExposure compares declared exposure with what the plan proves.
//
// The claim is about the change, not about what will ultimately be reachable: a
// plan can prove that a change asks for public access, while whether the
// request takes effect may depend on an account-level block or an organization
// policy that no plan contains. Those limits are reported as unknowns alongside
// the finding rather than folded into it, so a reader sees both the violation
// and the boundary of the evidence for it.
//
// A contract entry carries no address, and docs/INTENT-CONTRACT.md defers
// resource cardinality, so an entry constrains every resource of its family.
// That is the only reading which does not require the cardinality the contract
// cannot yet express, and it fails safe: adding a resource to a plan does not
// escape a declared intent.
func StorageExposure(contract intent.Contract, graph model.Graph) Result {
	var result Result

	declared, mentioned := contract.ExposureOf(intent.FamilyObjectStorage)
	if !mentioned {
		// The contract never addressed this family. The change is still
		// reported, because a plan doing more than the contract described is
		// exactly what a reader needs to see, but nothing here is a violation
		// of an intent that was never stated.
		declared = intent.ExposureUnspecified
	}

	for _, resource := range graph.OfFamily(model.FamilyObjectStorage) {
		if resource.ObjectStorage == nil {
			// A control resource: understood, but exposure belongs to the
			// resource it controls. This rule reached no verdict about it and
			// must not say otherwise; whether the subject it defers to was
			// judged is a question about the graph, and coverage answers it.
			continue
		}
		capabilities := *resource.ObjectStorage
		result.Evaluated = append(result.Evaluated, resource.Address)

		switch {
		case capabilities.PublicAccess.IsKnown() && capabilities.PublicAccess.Get():
			if declared != intent.ExposurePublic {
				result.Findings = append(result.Findings,
					publicFinding(resource, capabilities, declared))
			}
		case capabilities.PublicAccess.IsKnown():
			// The plan proves prevention. Nothing to report.
		case capabilities.Withdrawn:
			// Something was determined here and this build declined to use it.
			// That is not a question the plan left open, so the contract's
			// silence does not bound it: a reader must be told, whatever
			// exposure was declared.
			result.Unknowns = append(result.Unknowns, undeterminedUnknown(resource, capabilities, true))
		case declared == intent.ExposurePrivate:
			// The contract requires private storage and the plan cannot show
			// it. This is the case that separates this tool from one that
			// reports whatever it happened to understand.
			result.Unknowns = append(result.Unknowns, undeterminedUnknown(resource, capabilities, true))
		default:
			// No private exposure was required, so the undetermined answer
			// bounds the report rather than blocking a conclusion.
			result.Unknowns = append(result.Unknowns, undeterminedUnknown(resource, capabilities, false))
		}

		result.Unknowns = append(result.Unknowns, unresolvedUnknowns(resource, capabilities)...)
	}

	return result
}

// publicFinding reports storage the change exposes publicly.
//
// Disposition follows what the contract declared, and severity does not: public
// storage is equally exposed whether or not anyone wrote down that it should be
// private. Where the contract committed to private, the evidence contradicts it
// and that is a block. Where the author explicitly declined to commit, the
// change still needs a human, because "I have not decided" is not "go ahead".
func publicFinding(resource model.NormalizedResource, capabilities model.ObjectStorageCapabilities,
	declared intent.Exposure) evidence.Finding {

	disposition := evidence.DispositionWarn
	claim := "The change grants public access to object storage, and the intent contract does not declare it."
	remediation := "Declare the exposure in the intent contract, or remove the grant that exposes this storage publicly."
	if declared == intent.ExposurePrivate {
		disposition = evidence.DispositionBlock
		claim = "The change grants public access to object storage the intent contract requires to be private."
		remediation = "Remove the grant that exposes this storage publicly, or record the exposure as intended in the intent contract."
	}

	return evidence.Finding{
		RuleID:      RuleStoragePublic,
		Severity:    evidence.SeverityCritical,
		Disposition: disposition,
		Claim:       claim,
		Resource:    resourceRef(resource),
		Expected: &evidence.ExpectedFact{
			Path:  "object_storage.public_access",
			Value: evidence.Bool(false),
		},
		Observed:    evidence.KnownFact("object_storage.public_access", evidence.Bool(true)),
		Evidence:    referencesOf(capabilities.PublicAccess),
		Remediation: remediation,
	}
}

// undeterminedUnknown reports exposure the rule could not settle.
//
// It is required only when the contract asked for private storage: an author
// who declared public exposure, or none, is not waiting on evidence that it is
// private, and raising a required unknown for them would make every
// undetermined plan an UNKNOWN regardless of what was asked.
//
// A withdrawn determination is the exception, and the reason says which case
// this is. The two are not interchangeable: one is a plan that answered
// nothing, the other is an answer this build refused to use.
func undeterminedUnknown(resource model.NormalizedResource, capabilities model.ObjectStorageCapabilities,
	required bool) evidence.Unknown {

	reason := "Public exposure could not be determined from the plan; the state of the deciding " +
		"value is " + string(capabilities.PublicAccess.State) + "."
	if capabilities.Withdrawn {
		reason = "Public exposure was determined from a source this verdict may not rest on, " +
			"so the determination was withdrawn and the exposure is not settled."
	}

	address := inline(resource.Address)
	return evidence.Unknown{
		CheckID:         CheckStoragePublicDeterminable,
		Required:        required,
		Reason:          reason,
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

	address := inline(resource.Address)
	out := make([]evidence.Unknown, 0, len(capabilities.Unresolved))
	for _, control := range capabilities.Unresolved {
		out = append(out, evidence.Unknown{
			CheckID:  control.CheckID,
			Required: false,
			// Inlined like every other plan-derived string. A MissingControl
			// reason may interpolate a resource address, and a for_each key
			// holding a newline is legal Terraform — which made the bundle
			// fail its own single-line rule and replaced a verdict the tool
			// could give with an internal error.
			Reason:          inline(control.Reason),
			ResourceAddress: &address,
			Evidence:        locate(control.Sources),
		})
	}
	return out
}

// bundleCloud converts a normalized cloud into the Evidence Bundle's closed
// enumeration.
//
// The model deliberately does not constrain its clouds — a mapper for a cloud
// this build has never heard of is the point of the design — but the bundle
// contract does, and a finding the bundle refuses to validate is a finding that
// cannot be rendered. An unrecognized cloud is reported as unknown rather than
// smuggled through as a value the contract rejects.
func bundleCloud(cloud model.Cloud) evidence.Cloud {
	converted := evidence.Cloud(cloud)
	if !converted.Valid() {
		return evidence.CloudUnknown
	}
	return converted
}

// locate turns a control's sources into evidence references. A control that is
// an absence has none, and the bundle contract requires the list rather than a
// null.
func locate(sources []model.Provenance) []evidence.EvidenceRef {
	refs := make([]evidence.EvidenceRef, 0, len(sources))
	for _, source := range sources {
		refs = append(refs, evidence.EvidenceRef{
			Source:          "terraform_plan",
			ResourceAddress: inline(source.ResourceAddress),
			Path:            inline(source.AttributePath),
			Redacted:        source.Withheld,
		})
	}
	return refs
}

// referencesOf turns a fact's provenance into evidence. A reference locates the
// provider attribute a conclusion came from and can carry nothing else.
//
// It carries whether that particular attribute was readable, because the
// bundle contract defines the field as a property of the located value. Taking
// it from the fact's own state marked every source of a redacted fact, which
// told a reader that values the mapper had read in order to conclude were
// secret.
func referencesOf(fact model.Fact[bool]) []evidence.EvidenceRef {
	canonical := fact.Canonical()

	refs := make([]evidence.EvidenceRef, 0, len(canonical.Sources))
	for _, source := range canonical.Sources {
		refs = append(refs, evidence.EvidenceRef{
			Source:          "terraform_plan",
			ResourceAddress: inline(source.ResourceAddress),
			Path:            inline(source.AttributePath),
			Redacted:        source.Withheld,
		})
	}
	return refs
}
