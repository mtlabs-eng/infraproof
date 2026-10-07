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
	// CheckDatabasePortInferred is the opposite direction: a rule admitting every
	// address was ruled out by a port the engine named rather than one the plan
	// stated, so a silence rests on a documented default.
	CheckDatabasePortInferred = "DATABASE_PORT_INFERRED"
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

		if resource.Removed {
			// The change removes this database, so it permits nothing through
			// it. Judged, so coverage does not report it as a resource no rule
			// looked at, and silent, because a destroy-only change states no
			// attributes and records no configuration -- which read as a
			// reachability nobody could determine, with two sentences that were
			// untrue of a database that is going away.
			//
			// A replacement is not a removal: it creates the database again, and
			// what it creates is what the verdict is about.
			continue
		}

		admits, how := admitsAnyAddress(capabilities, graph)

		switch {
		case capabilities.Withdrawn:
			// Something was determined here and this build declined to use it,
			// because it came from a source a verdict may not rest on. That is
			// not a question the plan left open, so the contract's silence does
			// not bound it.
			//
			// Tested first, which the one-fact rules do not have to do: the
			// normalizer resets their single fact to Unknown whenever it sets
			// Withdrawn, so no known arm can fire. With two facts that invariant
			// does not hold -- whichever fact was withdrawn, the other can still
			// carry the switch to silence or to a BLOCK, and the withdrawal then
			// reaches a reader nowhere.
			result.Unknowns = append(result.Unknowns,
				undeterminedReachability(resource, capabilities, admits, how, true))
		case capabilities.PublicEndpoint.IsKnown() && !capabilities.PublicEndpoint.Get():
			// No endpoint outside the private network. What the allow list says
			// cannot make it reachable, so there is nothing to settle.
		case admits.IsKnown() && !admits.Get():
			// An endpoint nobody is admitted to. If that silence rests on a port
			// the engine named rather than one the plan stated, say so -- a
			// reader of a PASS cannot otherwise learn the verdict depends on it.
			if how.restsOnInferredPort {
				result.Unknowns = append(result.Unknowns, portInferred(resource, capabilities))
			}
		case capabilities.PublicEndpoint.IsKnown() && admits.IsKnown():
			if declared != intent.ExposurePublic {
				result.Findings = append(result.Findings,
					reachableFinding(resource, capabilities, admits, declared))
			}
			if how.widerThanReality {
				result.Unknowns = append(result.Unknowns, portUndetermined(resource, capabilities))
			}
		default:
			// Required only when the contract asked for a private database, which
			// is the rule StorageExposure states and explains: an author who
			// declared public exposure, or none, is not waiting on evidence of
			// privacy, and raising a required unknown for them would make every
			// undetermined plan an UNKNOWN regardless of what was asked. For
			// this family that matters more than for storage, because a security
			// group is usually in another module -- so the undetermined half is
			// the common case and would have made exit 4 the normal answer.
			result.Unknowns = append(result.Unknowns,
				undeterminedReachability(resource, capabilities, admits, how,
					declared == intent.ExposurePrivate))
		}

		result.Unknowns = append(result.Unknowns, unresolvedUnknowns(resource, capabilities.Unresolved)...)
	}

	return result
}

// admitsAnyAddress answers whether every address is admitted to this database,
// and how far that answer can be trusted.
//
// A disjunction, not a precedence. Two sources can answer: the mapper, where the
// allow list belongs to the database or its own controls, and each gate the
// mapper named, where it belongs to another subject the network family judges.
// Either can open the question and neither can close what the other opens.
//
// Reading the mapper's answer first and returning it was a false proof of
// privacy. A database with a public endpoint, an inline Known(false), and a gate
// in the graph open to every address on every port produced no finding and no
// unknown at all -- PASS, exit 0. Nothing in the model forbids a mapper from
// answering both ways, and three mappers were about to be written against it.
//
// The port decides whether a gate's open ranges reach this database, and it is an
// inference rather than a plan fact. Both directions of that inference are
// recorded: a port the engine cannot name makes every admitted address count, and
// a port it does name is what makes an admitted address *not* count. The second
// is the dangerous one, because then a silence rests on a table.
func admitsAnyAddress(capabilities model.DatabaseCapabilities,
	graph model.Graph) (model.Fact[bool], approximation) {

	var how approximation
	if capabilities.AdmitsAnyAddress.IsKnown() && capabilities.AdmitsAnyAddress.Get() {
		return capabilities.AdmitsAnyAddress, how
	}

	// Settled when something can answer: the mapper's own fact, or at least one
	// gate. An unreadable gate clears it again, because that gate could be the
	// one that admits everything.
	//
	// Starting from the mapper's fact alone left the question open whenever a
	// gate answered "closed" and the mapper had deferred -- which is the ordinary
	// AWS shape, and meant a database behind a security group the network family
	// had proven closed came out UNKNOWN rather than settled.
	settled := capabilities.AdmitsAnyAddress.IsKnown() || len(capabilities.GatedBy) > 0
	for _, address := range capabilities.GatedBy {
		gate, found := graph.At(address)
		if !found || gate.Network == nil || !gate.Network.PublicIngress.IsKnown() {
			// A gate nobody here can read leaves the question open: it could be
			// the one that admits everything.
			settled = false
			how.unreadableGates = append(how.unreadableGates, address)
			continue
		}
		if !gate.Network.PublicIngress.Get() {
			continue
		}
		reaches, wider := rangesReach(gate.Network.OpenToAnyAddress, capabilities.Port)
		if reaches {
			how.widerThanReality = how.widerThanReality || wider
			return model.Known(true, referencesTo(gate)...), how
		}
		if gate.Network.RangesPartial {
			// The port is not in the set, and the set is not the whole set: at
			// least one rule contributed no range because something about it
			// could not be read, and that rule is exactly the one that might
			// hold this port. The absence is a fact about what was readable, so
			// it settles nothing.
			settled = false
			how.unreadableGates = append(how.unreadableGates, address)
			continue
		}
		// A gate open to the world that does not reach this database. Whether
		// that rests on an inference depends on what ruled it out: a port from
		// the engine table did, and a protocol carrying no ports did not --
		// that exclusion is exact, and reporting it as resting on the table is
		// the inverse of the gap this disclosure was added to close.
		if capabilities.Port.IsKnown() && carriesPorts(gate.Network.OpenToAnyAddress) {
			how.restsOnInferredPort = true
		}
	}

	if !settled {
		return model.Unknown[bool](capabilities.AdmitsAnyAddress.Sources...), how
	}
	return model.Known(false, capabilities.AdmitsAnyAddress.Sources...), how
}

// approximation records how far the admission answer can be trusted, so every
// inference the verdict rests on reaches the reader.
//
// It is a struct rather than a bool because the two directions need different
// sentences, and because reporting only the harmless one -- over-reporting --
// while staying silent about a PASS that rests on an inferred port is the
// asymmetry a review found here.
type approximation struct {
	// widerThanReality: a finding rests on a comparison this build could not
	// make exactly.
	widerThanReality bool
	// restsOnInferredPort: a gate open to every address was ruled out by a port
	// that came from the engine rather than from the plan.
	restsOnInferredPort bool
	// unreadableGates names the gates the graph does not hold, so an unknown can
	// say which resource to go and look for.
	unreadableGates []string
}

// rangesReach reports whether any range admitted from every address reaches this
// database's port, and whether the answer is wider than reality.
//
// Every range is scanned and an exact containment is preferred over an
// approximation. Returning on the first port-less range made the answer depend
// on the order the provider happened to write the rules in: one set reported an
// approximation and the same set reordered did not.
//
// A protocol with no ports cannot reach a port. This build cannot tell which
// protocols a database answers on, so it is reported as reaching -- the direction
// that cannot hide a grant -- and the approximation says so, because a BLOCK
// resting on it is a BLOCK whose claim is wider than the evidence.
func rangesReach(open []model.OpenRange, port model.Fact[int]) (reaches, wider bool) {
	// The protocol decides first, because it decides without the port. A
	// protocol with no ports cannot reach a port, whether this build knows the
	// port or not -- so a rule admitting only ICMP reaches nothing a database
	// listens on, exactly.
	//
	// Testing the port first returned on the unknown-port branch before this
	// was reached, so a group admitting only ICMP in front of a database whose
	// engine the table cannot name produced a BLOCK: a claim that is untrue, on
	// evidence that is an approximation, which is what a BLOCK may not rest on.
	var ported []model.OpenRange
	for _, admitted := range open {
		if admitted.Protocol.HasPorts() {
			ported = append(ported, admitted)
		}
	}
	if len(ported) == 0 {
		return false, false
	}

	if !port.IsKnown() || port.Get() <= 0 {
		// No port to compare against, or a value that is not a port -- zero is
		// not one. Every range that could carry the database's port is treated
		// as reaching it, which over-reports and says so.
		return true, true
	}

	wanted := model.PortRange{From: port.Get(), To: port.Get()}
	for _, admitted := range ported {
		if admitted.Ports.Contains(wanted) {
			return true, false
		}
	}
	// Ruled out by the port, which came from the engine rather than the plan.
	// That is the silence the caller discloses.
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
	admits model.Fact[bool], how approximation, required bool) evidence.Unknown {

	reason := "Whether this database is reachable from any address could not be determined from the plan: "
	switch {
	case capabilities.Withdrawn:
		reason += "a determination was reached from a source a verdict may not rest on, and was " +
			"withdrawn."
	case !capabilities.PublicEndpoint.IsKnown():
		reason += "the plan does not state whether it has an endpoint outside the private network."
	default:
		reason += "it has an endpoint outside the private network, and the plan does not state " +
			"whether anything admits every address to it."
	}

	address := inline(resource.Address)
	// The gate's own address, so a reader is told which resource to go and look
	// for. Citing only the database's sources named the missing half and not
	// which security group it was, which is the one thing a reader needs to act.
	refs := append(referencesOf(capabilities.PublicEndpoint), referencesOf(admits)...)
	for _, gate := range how.unreadableGates {
		refs = append(refs, evidence.EvidenceRef{
			Source:          "terraform_plan",
			ResourceAddress: inline(gate),
			Path:            "network.public_ingress",
		})
	}
	return evidence.Unknown{
		CheckID:         CheckDatabaseReachabilityDeterminable,
		Required:        required,
		Reason:          reason,
		ResourceAddress: &address,
		Evidence:        refs,
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
		Reason: "This database is reported as reachable from a comparison this build could not make " +
			"exactly: either the port it listens on is not stated in the plan and its engine does " +
			"not name one, or a rule in front of it admits a protocol that carries no ports. Either " +
			"way what is reported may be wider than what the set permits.",
		ResourceAddress: &address,
		Evidence:        referencesOf(capabilities.Port),
	}
}

// portInferred records that a database reads as unreachable because of a port
// the engine named rather than one the plan stated.
//
// The direction that needed saying. The approximation was announced when it
// over-reported -- harmless -- and not when a gate open to every address was
// ruled out by an inferred port, which is a PASS resting on a table of
// documented defaults. The milestone names this as the choice most likely to be
// wrong in practice, and a reader of that PASS had no way to learn the verdict
// depended on it.
func portInferred(resource model.NormalizedResource,
	capabilities model.DatabaseCapabilities) evidence.Unknown {

	address := inline(resource.Address)
	return evidence.Unknown{
		CheckID:  CheckDatabasePortInferred,
		Required: false,
		Reason: "A rule in front of this database admits every address, and this build reads it as " +
			"not reaching the database because of the port the engine listens on by default. The " +
			"plan does not state the port, so that part of the answer rests on a documented " +
			"default rather than on the plan.",
		ResourceAddress: &address,
		Evidence:        referencesOf(capabilities.Port),
	}
}

// carriesPorts reports that a rule set admits anything on a protocol that has
// ports, which is what makes a port comparison the thing that decided.
func carriesPorts(open []model.OpenRange) bool {
	for _, admitted := range open {
		if admitted.Protocol.HasPorts() {
			return true
		}
	}
	return false
}
