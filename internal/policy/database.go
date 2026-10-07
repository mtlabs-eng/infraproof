package policy

import (
	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

const (
	// RuleDatabasePublicReachable is the one rule this family has.
	RuleDatabasePublicReachable = "DATABASE_PUBLIC_REACHABLE"
	// CheckDatabaseReachabilityDeterminable is the question the plan may leave
	// open, and it names which half it left open.
	CheckDatabaseReachabilityDeterminable = "DATABASE_REACHABILITY_DETERMINABLE"
	// CheckDatabasePortUndetermined records that the answer is wider than
	// reality because the engine does not name a port.
	CheckDatabasePortUndetermined = "DATABASE_PORT_UNDETERMINED"
)

// DatabaseExposure reports a database the change makes reachable from the public
// internet.
//
// Reachability is a conjunction of two independent facts, which is what makes
// this family different from the two before it: a database has an endpoint
// outside the private network, and something admits every address to that
// endpoint. Neither alone is a finding. A public endpoint nobody is admitted to
// is not reachable, and an allow list in front of no endpoint reaches nothing;
// reporting either would produce a finding on the ordinary shape, which is how a
// tool teaches people to ignore it.
//
// The second fact may belong to another resource. On AWS a database's allow list
// is a security group, which the network family already judges in its own right,
// so the mapper names it and this resolves the name against the graph. That keeps
// every mapper independent of every other, and it is what the policy layer
// already does with DefersTo.
//
// It names no cloud, no resource type and no attribute; those reach a reader only
// through the evidence a mapper attached.
func DatabaseExposure(contract intent.Contract, graph model.Graph) Result {
	var result Result

	declared, mentioned := contract.ExposureOf(intent.FamilyDatabase)
	if !mentioned {
		// The contract never addressed this family. The change is still
		// reported, because a plan doing more than the contract described is
		// what a reader needs to see, but nothing here violates an intent
		// nobody stated.
		declared = intent.ExposureUnspecified
	}

	for _, resource := range graph.OfFamily(model.FamilyDatabase) {
		if resource.Database == nil {
			// A control resource: its meaning belongs to the database it
			// governs. This rule reached no verdict about it and must not say
			// otherwise; coverage answers whether the subject was judged.
			continue
		}
		capabilities := *resource.Database
		result.Evaluated = append(result.Evaluated, resource.Address)

		admits, approximated := admitsAnyAddress(capabilities, graph)

		switch {
		case capabilities.PublicEndpoint.IsKnown() && !capabilities.PublicEndpoint.Get():
			// No endpoint outside the private network. What the allow list says
			// cannot make it reachable, so there is nothing to settle.
		case admits.IsKnown() && !admits.Get():
			// An endpoint nobody is admitted to.
		case capabilities.PublicEndpoint.IsKnown() && admits.IsKnown():
			if declared != intent.ExposurePublic {
				result.Findings = append(result.Findings,
					reachableFinding(resource, capabilities, admits, declared))
			}
			if approximated {
				result.Unknowns = append(result.Unknowns, portUndetermined(resource, capabilities))
			}
		case capabilities.Withdrawn:
			// Something was determined here and this build declined to use it.
			// That is not a question the plan left open, so the contract's
			// silence does not bound it.
			result.Unknowns = append(result.Unknowns,
				undeterminedReachability(resource, capabilities, admits, true))
		default:
			result.Unknowns = append(result.Unknowns,
				undeterminedReachability(resource, capabilities, admits, mentioned))
		}

		result.Unknowns = append(result.Unknowns, unresolvedUnknowns(resource, capabilities.Unresolved)...)
	}

	return result
}

// admitsAnyAddress answers whether every address is admitted to this database,
// and whether the answer is wider than reality.
//
// Three sources, in order. The mapper answers directly where the allow list
// belongs to the database or its own controls. Where it belongs to another
// subject, the mapper named it and the gate's own verdict answers. A gate the
// graph does not hold is a security group managed elsewhere, and settles
// nothing.
//
// The port is what decides whether a gate's open ranges reach this database. When
// the engine does not name one, any admitted range is treated as reaching it --
// wider than reality, which is the safe direction, and reported as such rather
// than presented as exact.
func admitsAnyAddress(capabilities model.DatabaseCapabilities,
	graph model.Graph) (model.Fact[bool], bool) {

	if capabilities.AdmitsAnyAddress.IsKnown() {
		return capabilities.AdmitsAnyAddress, false
	}
	if len(capabilities.GatedBy) == 0 {
		return capabilities.AdmitsAnyAddress, false
	}

	var approximated bool
	settled := true
	for _, address := range capabilities.GatedBy {
		gate, found := graph.At(address)
		if !found || gate.Network == nil || !gate.Network.PublicIngress.IsKnown() {
			// A gate nobody here can read leaves the conjunction open: it could
			// be the one that admits everything.
			settled = false
			continue
		}
		if !gate.Network.PublicIngress.Get() {
			continue
		}
		reaches, wider := rangesReach(gate.Network.OpenToAnyAddress, capabilities.Port)
		if wider {
			approximated = true
		}
		if reaches {
			return model.Known(true, referencesTo(gate)...), approximated
		}
	}
	if !settled {
		return model.Unknown[bool](capabilities.AdmitsAnyAddress.Sources...), approximated
	}
	return model.Known(false, capabilities.AdmitsAnyAddress.Sources...), approximated
}

// rangesReach reports whether any range admitted from every address reaches this
// database's port, and whether the answer is wider than reality.
//
// A protocol with no ports reaches a port by definition: there is nothing to
// compare, and a rule admitting ICMP from everywhere does not reach a database
// port -- but this build cannot tell which protocols a database answers on, so
// treating it as reaching is the direction that cannot hide a grant.
func rangesReach(open []model.OpenRange, port model.Fact[int]) (reaches, wider bool) {
	if !port.IsKnown() {
		// No port to compare against, so any range admitted at all is treated
		// as reaching it.
		return len(open) > 0, len(open) > 0
	}
	wanted := model.PortRange{From: port.Get(), To: port.Get()}
	for _, range_ := range open {
		if !range_.Protocol.HasPorts() {
			return true, true
		}
		if range_.Ports.Contains(wanted) {
			return true, false
		}
	}
	return false, false
}

// referencesTo cites a gate's own deciding fact, so a reader following the
// evidence arrives at the resource that actually admits the traffic.
func referencesTo(gate model.NormalizedResource) []model.Provenance {
	if gate.Network == nil {
		return nil
	}
	return gate.Network.PublicIngress.Sources
}

// reachableFinding reports a database the change makes reachable.
//
// Severity is HIGH, unconditionally. A reachable database still demands
// credentials, so it is one layer of several -- the reading network exposure
// already uses. Public object storage is CRITICAL because it exposes the data
// itself to anyone. Severity communicates impact and may not depend on what
// anyone wrote down.
func reachableFinding(resource model.NormalizedResource, capabilities model.DatabaseCapabilities,
	admits model.Fact[bool], declared intent.Exposure) evidence.Finding {

	disposition := evidence.DispositionWarn
	claim := "The change makes a database reachable from any address, and the intent contract does " +
		"not declare that exposure."
	remediation := "Declare the exposure in the intent contract, or close the public endpoint or the " +
		"rule that admits every address."
	if declared == intent.ExposurePrivate {
		disposition = evidence.DispositionBlock
		claim = "The change makes a database reachable from any address, which the intent contract " +
			"requires to be private."
		remediation = "Close the public endpoint or the rule that admits every address, or record the " +
			"exposure as intended in the intent contract."
	}

	return evidence.Finding{
		RuleID:      RuleDatabasePublicReachable,
		Severity:    evidence.SeverityHigh,
		Disposition: disposition,
		Claim:       claim,
		Resource:    resourceRef(resource),
		Expected: &evidence.ExpectedFact{
			Path:  "database.reachable_from_any_address",
			Value: evidence.Bool(false),
		},
		Observed: evidence.KnownFact("database.reachable_from_any_address", evidence.Bool(true)),
		// Both halves, because a reader needs to know which rule and which
		// switch between them produced this.
		Evidence:    append(referencesOf(capabilities.PublicEndpoint), referencesOf(admits)...),
		Remediation: remediation,
	}
}

// undeterminedReachability reports a conjunction the plan left open, naming the
// half it left open.
//
// Which half matters: the fixes are different. An undetermined endpoint is an
// attribute of the database; an undetermined allow list is usually a security
// group in another module, which for AWS is the common case rather than an edge
// one.
func undeterminedReachability(resource model.NormalizedResource, capabilities model.DatabaseCapabilities,
	admits model.Fact[bool], required bool) evidence.Unknown {

	reason := "Whether this database is reachable from any address could not be determined from the plan: "
	switch {
	case !capabilities.PublicEndpoint.IsKnown():
		reason += "the plan does not state whether it has an endpoint outside the private network."
	default:
		reason += "it has an endpoint outside the private network, and the plan does not state " +
			"whether anything admits every address to it."
	}

	address := inline(resource.Address)
	return evidence.Unknown{
		CheckID:         CheckDatabaseReachabilityDeterminable,
		Required:        required,
		Reason:          reason,
		ResourceAddress: &address,
		Evidence:        append(referencesOf(capabilities.PublicEndpoint), referencesOf(admits)...),
	}
}

// portUndetermined records that a finding is wider than reality because the
// engine does not name a port, so a reader is not shown an exact answer.
func portUndetermined(resource model.NormalizedResource,
	capabilities model.DatabaseCapabilities) evidence.Unknown {

	address := inline(resource.Address)
	return evidence.Unknown{
		CheckID:  CheckDatabasePortUndetermined,
		Required: false,
		Reason: "The port this database listens on is not stated in the plan and its engine does not " +
			"name one, so every address admitted by a rule in front of it is reported as reaching " +
			"it, which may be wider than what the set permits.",
		ResourceAddress: &address,
		Evidence:        referencesOf(capabilities.Port),
	}
}
