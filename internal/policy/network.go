package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
)

// Network rule identifiers, stable across releases because consumers branch on
// them.
const (
	// RuleNetworkPublicIngress reports a change permitting ingress from any
	// address.
	RuleNetworkPublicIngress = "NETWORK_PUBLIC_INGRESS"
	// CheckNetworkIngressDeterminable reports that ingress from any address
	// could not be determined from the plan.
	CheckNetworkIngressDeterminable = "NETWORK_PUBLIC_INGRESS_DETERMINABLE"
)

// NetworkExposure compares the ingress a change permits with the ports the
// contract declares may be reachable from any address.
//
// The claim is about the change, not about what will be reachable: reachability
// needs the attachment, which is usually in another resource, another module, or
// already exists, and asserting it would make most real plans UNKNOWN. That is
// the choice StorageExposure makes for storage, for the same reason, and the
// limits are reported as unknowns beside the finding rather than folded into it.
//
// It names no cloud, no resource type and no attribute. Ordering, deny rules and
// priority are what the three clouds disagree about, and resolving them is the
// mapper's work: by the time this reads a capability, the answer is about the set.
func NetworkExposure(contract intent.Contract, graph model.Graph) Result {
	var result Result

	declared, stated := contract.PublicPortsOf(intent.FamilyNetwork)

	for _, resource := range graph.OfFamily(model.FamilyNetwork) {
		if resource.Network == nil {
			// A rule resource: understood, and its meaning belongs to the set it
			// belongs to. This rule reached no verdict about it and must not say
			// otherwise; whether the set it defers to was judged is a question
			// about the graph, and coverage answers it.
			continue
		}
		capabilities := *resource.Network
		result.Evaluated = append(result.Evaluated, resource.Address)

		switch {
		case capabilities.PublicIngress.IsKnown() && capabilities.PublicIngress.Get():
			if finding, reported := ingressFinding(resource, capabilities, declared, stated); reported {
				result.Findings = append(result.Findings, finding)
			}
		case capabilities.PublicIngress.IsKnown():
			// The plan holds the whole set and the set permits nothing from any
			// address. Nothing to report.
		case capabilities.Withdrawn:
			// Something was determined here and this build declined to use it.
			// That is not a question the plan left open, so the contract's
			// silence does not bound it.
			result.Unknowns = append(result.Unknowns, undeterminedIngress(resource, capabilities, true))
		case stated:
			// The contract declares what may be public and the plan cannot show
			// what is. A grant can be proven from part of a rule set; closure
			// cannot, and this is that asymmetry reaching a reader.
			result.Unknowns = append(result.Unknowns, undeterminedIngress(resource, capabilities, true))
		default:
			result.Unknowns = append(result.Unknowns, undeterminedIngress(resource, capabilities, false))
		}

		result.Unknowns = append(result.Unknowns, unresolvedUnknowns(resource, capabilities.Unresolved)...)
	}

	return result
}

// ingressFinding reports ingress the change permits from any address, and whether
// there is anything to report at all.
//
// Disposition follows what the contract declared and severity does not: a port
// open to the internet is equally open whether or not anyone wrote down that it
// should not be. Where the contract declared ports and the change exceeds them,
// the evidence contradicts it and that is a block. Where the contract declared
// nothing, the change still needs a human, because "I have not said" is not "go
// ahead". Where the change opens a protocol a port list cannot describe, a human
// decides too: reporting nothing would read as permission, and blocking would be
// this build deciding on its own that ping from the internet is a violation.
func ingressFinding(resource model.NormalizedResource, capabilities model.NetworkCapabilities,
	declared []model.PortRange, stated bool) (evidence.Finding, bool) {

	exceeding, undescribable := beyondDeclaration(capabilities.OpenToAnyAddress, declared, stated)
	if len(exceeding) == 0 && len(undescribable) == 0 {
		return evidence.Finding{}, false
	}

	disposition := evidence.DispositionWarn
	claim := "The change permits ingress from any address, and the intent contract does not declare " +
		"which ports may be reachable from any address."
	remediation := "Declare the ports in the intent contract, or remove the rule that permits ingress from any address."
	// A violation outranks a question: an undeclared port open to the internet is
	// a statement the contract contradicts, a protocol a port list cannot
	// describe is a question it cannot answer, and a disposition must never be
	// lowered by an additional fact. The claim has to account for both when both
	// are present, or part of a BLOCK's evidence supports a conclusion the claim
	// never states.
	switch {
	case stated && len(exceeding) > 0 && len(undescribable) > 0:
		disposition = evidence.DispositionBlock
		claim = "The change permits ingress from any address on a port the intent contract does not " +
			"declare as reachable from any address, and on a protocol the contract cannot describe."
		remediation = "Remove the rule that permits ingress from any address, declare the port in the " +
			"intent contract, and confirm that the protocol is intended to be reachable from any address."
	case stated && len(exceeding) > 0:
		disposition = evidence.DispositionBlock
		claim = "The change permits ingress from any address on a port the intent contract does not " +
			"declare as reachable from any address."
		remediation = "Remove the rule that permits ingress from any address, or declare the port in the intent contract."
	case len(undescribable) > 0:
		claim = "The change permits ingress from any address on a protocol the intent contract cannot " +
			"describe, because a port declaration can neither permit nor forbid it."
		remediation = "Confirm that this protocol is intended to be reachable from any address, or remove the rule."
	}

	finding := evidence.Finding{
		RuleID: RuleNetworkPublicIngress,
		// Impact, not enforcement. A port is one layer of several and what is
		// listening behind it is not in the plan, which this family's milestone
		// puts out of scope; public object storage exposes the data itself and
		// is reported CRITICAL for that reason.
		Severity:    evidence.SeverityHigh,
		Disposition: disposition,
		Claim:       claim,
		Resource:    resourceRef(resource),
		Expected:    declarationExpected(declared, stated),
		Observed:    openObserved(append(exceeding, undescribable...)),
		Evidence:    ingressEvidence(capabilities, append(exceeding, undescribable...)),
		Remediation: remediation,
	}
	return finding, true
}

// beyondDeclaration splits what the change opens into the ranges the contract did
// not declare and the ranges it cannot describe at all.
//
// A declaration permits a range only by covering all of it, between all the
// ranges it names. Partial overlap is not permission: a contract declaring
// 8000-8100 has not declared 7999, and reading an overlap as permission is how a
// declaration comes to cover a port nobody wrote down. The union matters as much
// -- asking whether any one declared range contained the whole opened range
// reported a violation on a contract declaring 80 and 81 against an opened
// 80-81, with a claim untrue of every port involved.
//
// Every protocol at once is never fully permitted by a port list, whatever its
// ports. It carries the protocols that have no ports, and this build's own
// doctrine is that a port declaration can neither permit nor forbid those. ICMP
// alone needed a human; ICMP as part of "every protocol" was permitted outright.
func beyondDeclaration(opened []model.OpenRange, declared []model.PortRange,
	stated bool) (exceeding, undescribable []model.OpenRange) {

	for _, open := range opened {
		if !open.Protocol.HasPorts() {
			undescribable = append(undescribable, open)
			continue
		}
		if open.Protocol == model.ProtocolEvery {
			// A port declaration cannot describe all of this, so it needs a
			// human whatever the ports say. The ports are still compared below,
			// because an undeclared one is a violation in its own right.
			undescribable = append(undescribable, open)
		}
		if stated && model.Covers(declared, open.Ports) {
			continue
		}
		// Every protocol with an undeclared port is both: a question the port
		// list cannot answer and a port it contradicts. It lands in both lists
		// and renderOpen compacts the repeat, so the observed value says it once
		// while the disposition accounts for both.
		exceeding = append(exceeding, open)
	}
	return exceeding, undescribable
}

// declarationExpected renders what the contract asked for.
//
// Two shapes, because the contract makes two different statements. A list of
// ports is the list; a declaration of none is "no ingress from any address",
// which is the same claim StorageExposure writes as public_access = false, and
// reads that way to anyone who has seen one.
func declarationExpected(declared []model.PortRange, stated bool) *evidence.ExpectedFact {
	if !stated {
		return nil
	}
	if len(declared) == 0 {
		return &evidence.ExpectedFact{
			Path:  "network.public_ingress",
			Value: evidence.Bool(false),
		}
	}
	return &evidence.ExpectedFact{
		Path:  "network.public_ports",
		Value: evidence.String(renderRanges(declared)),
	}
}

// openObserved renders what the change opens.
//
// The value is composed here out of integers and a closed protocol set, never
// copied from a provider field. That is what keeps a for_each key or a rule
// description out of it: every other free-text field in this build is inlined on
// the way out, and the way to not need that is to not carry provider text at all.
func openObserved(ranges []model.OpenRange) *evidence.ObservedFact {
	if len(ranges) == 0 {
		// A grant with no ranges recorded. Nothing downstream should see this --
		// a mapper that proves a grant names what it opens -- but the fact is
		// still true and reporting it as absent would be a worse answer than
		// reporting it without its ports.
		return evidence.KnownFact("network.public_ingress", evidence.Bool(true))
	}
	return evidence.KnownFact("network.open_to_any_address", evidence.String(renderOpen(ranges)))
}

// renderOpen writes the protocols and ports a change opens, deterministically.
func renderOpen(ranges []model.OpenRange) string {
	texts := make([]string, 0, len(ranges))
	for _, open := range ranges {
		if !open.Protocol.HasPorts() {
			texts = append(texts, open.Protocol.Name())
			continue
		}
		texts = append(texts, open.Protocol.Name()+"/"+renderRange(open.Ports))
	}
	// Sorted and deduplicated, so two runs over one plan say the same thing and
	// a rule set that opens one port twice says it once.
	slices.Sort(texts)
	return strings.Join(slices.Compact(texts), ", ")
}

// renderRanges writes a declared set of ports in the order the contract wrote
// it, bounded.
//
// A contract may declare any number of ports and this wrote all of them: 1,500
// entries produced a 49 KB report with almost all of it inside one Markdown
// table cell. The intent package bounds a quoted contract value for the same
// reason and says it plainly -- a message that reprints the file is one nobody
// reads to the end.
//
// What is elided is counted. A reader who cannot see the whole declaration must
// at least be told how much of it there was, or the report quietly implies the
// contract declared only what fitted.
func renderRanges(declared []model.PortRange) string {
	const most = 120

	var built strings.Builder
	for i, permitted := range declared {
		text := renderRange(permitted)
		if built.Len() > 0 && built.Len()+len(text)+2 > most {
			return fmt.Sprintf("%s, and %d more of %d declared",
				built.String(), len(declared)-i, len(declared))
		}
		if built.Len() > 0 {
			built.WriteString(", ")
		}
		built.WriteString(text)
	}
	return built.String()
}

// renderRange writes one range: a single port as itself.
func renderRange(ports model.PortRange) string {
	if ports.From == ports.To {
		return fmt.Sprintf("%d", ports.From)
	}
	return fmt.Sprintf("%d-%d", ports.From, ports.To)
}

// ingressEvidence locates the fact and the ranges a finding rests on.
// The deciding fact first, because it is the one citation a reader cannot do
// without, and the ranges carry their own sources -- so dropping the fact's
// provenance left the list non-empty and every assertion satisfied.
//
// Deduplicated: the fact and the ranges cite overlapping attributes, and a reader
// shown the same source three times stops reading the list.
func ingressEvidence(capabilities model.NetworkCapabilities, ranges []model.OpenRange) []evidence.EvidenceRef {
	refs := referencesOf(capabilities.PublicIngress)
	for _, open := range ranges {
		refs = append(refs, locate(open.Sources)...)
	}

	seen := make(map[evidence.EvidenceRef]bool, len(refs))
	unique := make([]evidence.EvidenceRef, 0, len(refs))
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		seen[ref] = true
		unique = append(unique, ref)
	}
	return unique
}

// undeterminedIngress reports ingress the rule could not settle.
//
// Required only when the contract declared something, for the reason storage's
// equivalent is: an author who declared nothing is not waiting on evidence about
// ports, and raising a required unknown for them would make every plan holding
// part of a rule set an UNKNOWN regardless of what was asked. A withdrawn
// determination is the exception, and the reason says which case this is.
func undeterminedIngress(resource model.NormalizedResource, capabilities model.NetworkCapabilities,
	required bool) evidence.Unknown {

	reason := "Ingress from any address could not be determined from the plan; the state of the " +
		"deciding value is " + string(capabilities.PublicIngress.State) + "."
	if capabilities.Withdrawn {
		reason = "Ingress from any address was determined from a source this verdict may not rest on, " +
			"so the determination was withdrawn and the exposure is not settled."
	}

	address := inline(resource.Address)
	return evidence.Unknown{
		CheckID:         CheckNetworkIngressDeterminable,
		Required:        required,
		Reason:          reason,
		ResourceAddress: &address,
		Evidence:        referencesOf(capabilities.PublicIngress),
	}
}
