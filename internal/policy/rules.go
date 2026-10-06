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
	// CheckActionRecognized reports a change naming an operation this build
	// does not know.
	CheckActionRecognized = "CHANGE_ACTION_RECOGNIZED"
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
		if resource.ReadOnly {
			// A read destroys nothing. The guard is defensive: the normalizer
			// never sets Destructive on a read, so removing it changes no
			// output today and no test can see it.
			continue
		}
		if resource.UnrecognizedAction {
			// Destruction is read from the actions, so an action this build
			// does not know would make this change look like one that destroys
			// nothing. What the verb means is Terraform's to say, and a run
			// that could not read it has not established that the change is
			// safe.
			address := inline(resource.Address)
			result.Unknowns = append(result.Unknowns, evidence.Unknown{
				CheckID:  CheckActionRecognized,
				Required: true,
				Reason: "This change names an operation this build does not recognize, so whether it " +
					"destroys anything could not be determined.",
				ResourceAddress: &address,
				Evidence: []evidence.EvidenceRef{{
					Source:          "terraform_plan",
					ResourceAddress: address,
					Path:            "resource_changes[].change.actions",
				}},
			})
			// The doubt is raised alongside whatever the plan does state, not
			// instead of it. A plan naming both "delete" and a verb nobody can
			// read still names delete, and replacing the finding with the
			// unknown turned a BLOCK into an UNKNOWN — which a pipeline that
			// stops on one and warns on the other lets through.
		}
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
		if resource.ReadOnly {
			// A read does not affect a cloud; it observes one.
			continue
		}
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
		if resource.ReadOnly {
			continue
		}
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
				Reason:          environmentReason(resource),
				ResourceAddress: &address,
				Evidence:        environmentEvidence(declared),
			})
			continue
		}
		// The comparison is exact in case and forgiving of surrounding space.
		// A tag key is a convention and its capitalization is incidental, which
		// is why the key is matched without regard to case; a tag value is a
		// name the author chose, and two spellings of it are two names.
		// Folding them would let "Production" satisfy a contract written for
		// "production", and where those are deliberately distinct environments
		// the mismatch this rule exists to find would go unreported.
		//
		// Space around a name is not part of it. Both sides are trimmed where
		// they are produced, and trimming here as well is the difference
		// between a rule that is correct and one that is correct because of
		// what two other packages happen to do.
		if strings.TrimSpace(declared.Get()) == strings.TrimSpace(contract.Environment) {
			continue
		}

		result.Findings = append(result.Findings, evidence.Finding{
			RuleID:      RuleEnvironmentMismatch,
			Severity:    evidence.SeverityHigh,
			Disposition: evidence.DispositionBlock,
			Claim:       "The resource declares an environment the intent contract was not written for.",
			Resource:    resourceRef(resource),
			Expected: &evidence.ExpectedFact{
				Path: "resource.environment",
				// Inlined like the observed side two lines down. A contract is a
				// file a person writes, an environment holding a line break is
				// loadable, and a bundle that fails its own single-line rule
				// replaces a verdict this build could give with an internal
				// error.
				Value: evidence.String(inline(contract.Environment)),
			},
			Observed: evidence.KnownFact("resource.environment", evidence.String(inline(declared.Get()))),
			Evidence: environmentEvidence(declared),
			Remediation: "Target the environment the contract declares, or write the contract for the " +
				"environment this change affects.",
		})
	}

	return result
}

// environmentReason says which of four things happened, because they have
// different fixes and a reader acts on the sentence.
//
// The fact state alone cannot tell them apart: it answers what the resource
// said, and the zero value has to answer whether the resource was asked. An
// earlier form read the zero value as "declared but undeterminable" and printed
// "not known until apply, or more than one declaration that disagree" about a
// resource whose tags were plainly readable and which nothing had read.
func environmentReason(resource model.NormalizedResource) string {
	switch resource.Environment.State {
	case "":
		if !resource.Interpreted {
			return "No mapper interpreted this resource, so there was no attribute to read an " +
				"environment from and none was compared with the contract."
		}
		return "This resource was interpreted by a mapper that reads no environment, so none was " +
			"compared with the contract."
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
			// Per source, like every other reference. A fact is redacted if
			// any one of its sources was, so asking the fact marks values the
			// mapper plainly read.
			Redacted: source.Withheld,
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
// It is required. An intent contract carries a change_id and is written for one
// change, so a declaration the change gives nothing to apply to is a
// requirement this run could not verify — and docs/PRODUCT.md states that a
// PASS means everything was checked, not that nothing objected. Reporting it
// without preventing the PASS left the summary saying the change was
// consistent with the contract in every supported check when no check had run.
//
// An author who meant to leave the question open writes exposure:
// "unspecified", which is skipped below.
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
			Required: true,
			Reason: fmt.Sprintf(
				"The contract declares %s, and the plan contains no resource of that family, so the "+
					"declaration was not exercised.", declaredAs(declared)),
			Evidence: []evidence.EvidenceRef{{Source: "intent_contract", Path: "resources"}},
		})
	}

	slices.SortStableFunc(result.Unknowns, func(a, b evidence.Unknown) int {
		return strings.Compare(a.Reason, b.Reason)
	})
	return result
}

// declaredAs names what an entry declared, in the vocabulary of its own family.
//
// Each family declares what its own rule reads -- storage an exposure, network a
// set of ports -- so one sentence cannot describe both. Writing "declares
// exposure for network" would be this check reporting a field that family does
// not have.
func declaredAs(declared intent.ResourceIntent) string {
	if declared.Family == intent.FamilyNetwork {
		if declared.PublicPorts == nil || len(*declared.PublicPorts) == 0 {
			return "that no port of " + intent.FamilyNetwork + " may be reachable from any address"
		}
		return "the ports of " + intent.FamilyNetwork + " that may be reachable from any address"
	}
	return fmt.Sprintf("%s exposure for %s", declared.Exposure, declared.Family)
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
//
// A rule's report is taken only for resources it reached a verdict about. A
// control resource is covered by deferral instead, and the deferral is resolved
// against the graph rather than believed: the subject must be present and must
// itself have been judged. Believing the claim was the defect — a policy
// attached to a bucket managed elsewhere defers to nobody, and reported that
// the change was consistent in every supported check.
func ResourceCoverage(graph model.Graph, evaluated []string) Result {
	var result Result

	judged := make(map[string]bool, len(evaluated))
	for _, address := range evaluated {
		judged[address] = true
	}

	for _, resource := range graph.Resources {
		switch {
		case resource.ReadOnly:
			// Nothing judges a read, and nothing needs to.
			continue
		case !resource.Interpreted:
			// Already reported, and more usefully: an opaque resource raises a
			// required unknown naming the cloud that could not be established.
			// Saying it twice in different words tells a reader less.
			continue
		case judged[resource.Address]:
			continue
		case deferredToAJudgedSubject(resource, judged):
			continue
		}

		address := inline(resource.Address)
		result.Unknowns = append(result.Unknowns, evidence.Unknown{
			CheckID: CheckResourceEvaluated,
			// Required. The resource was understood well enough to be
			// normalized, so this build knows what it is and has no rule for
			// it — which is a question this run did not answer, not a limit on
			// an answer it gave.
			Required:        true,
			Reason:          coverageReason(resource),
			ResourceAddress: &address,
			Evidence:        []evidence.EvidenceRef{},
		})
	}

	return result
}

// coverageReason says which of the two gaps this is, because they have
// different fixes: one needs a rule, the other needs the resource it governs.
func coverageReason(resource model.NormalizedResource) string {
	if resource.GovernsWithheld {
		return "This resource controls only resources this plan reads rather than changes, so " +
			"nothing it governs was judged and nothing about it was checked against the contract."
	}
	if len(resource.DefersTo) > 0 {
		return "This resource controls another, and no resource it governs was judged in this plan, " +
			"so nothing about it was checked against the contract."
	}
	return fmt.Sprintf(
		"This resource was normalized as %s, and nothing judged it against the contract: either no "+
			"rule in this build covers that family, or it controls a resource that is not part of "+
			"this plan.", resource.Family)
}

// deferredToAJudgedSubject reports whether a control resource's meaning reached
// something that answered for it.
//
// Naming a subject is not enough. The subject must be in the graph — a control
// governing a bucket managed elsewhere names one that is not here — and it must
// itself have been judged, or the deferral passes the question to something
// that never answered it either.
func deferredToAJudgedSubject(resource model.NormalizedResource, judged map[string]bool) bool {
	for _, subject := range resource.DefersTo {
		if judged[subject] {
			return true
		}
	}
	return false
}

func resourceRef(resource model.NormalizedResource) *evidence.Resource {
	return &evidence.Resource{
		Address:  inline(resource.Address),
		Provider: inline(resource.Provider),
		Cloud:    bundleCloud(resource.Cloud),
	}
}

// inline makes a plan-derived value usable in a single-line bundle field. The
// rule belongs to the contract, so the contract states it: a producer and a
// renderer each keeping their own copy is how two answers to one question come
// about, and this file already had one that knew only about line breaks.
func inline(text string) string {
	return evidence.Inline(text)
}
