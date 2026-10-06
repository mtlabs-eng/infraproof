package policy_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
)

// declaring returns a contract whose network entry declares these ports. A nil
// slice declares none at all, which is a different statement from an empty one.
func declaring(ports []model.PortRange) intent.Contract {
	return contract(func(c *intent.Contract) {
		if ports == nil {
			return
		}
		c.Resources = append(c.Resources, intent.ResourceIntent{
			Family:      intent.FamilyNetwork,
			PublicPorts: &ports,
		})
	})
}

// open returns a network resource whose change permits ingress from any address
// on these ranges.
func open(ranges ...model.OpenRange) model.Graph {
	return model.Graph{Resources: []model.NormalizedResource{{
		Address:     "aws_security_group.web",
		Provider:    "registry.terraform.io/hashicorp/aws",
		Cloud:       model.CloudAWS,
		Family:      model.FamilyNetwork,
		Interpreted: true,
		Network: &model.NetworkCapabilities{
			PublicIngress: model.Known(true, model.Provenance{
				ResourceAddress: "aws_security_group.web",
				AttributePath:   "ingress[0].cidr_blocks[0]",
				Cloud:           model.CloudAWS,
			}),
			OpenToAnyAddress: ranges,
		},
	}}}
}

// tcp is one open TCP range.
func tcp(from, to int) model.OpenRange {
	return model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: from, To: to},
		Sources: []model.Provenance{{
			ResourceAddress: "aws_security_group.web",
			AttributePath:   "ingress[0].from_port",
			Cloud:           model.CloudAWS,
		}},
	}
}

func port(n int) model.PortRange { return model.PortRange{From: n, To: n} }

// TestADeclaredPortIsWhatWasAskedFor covers the top of the disposition table. A
// change opening exactly what the contract declared is the change the contract
// was written for, and reporting it would make the declaration pointless.
func TestADeclaredPortIsWhatWasAskedFor(t *testing.T) {
	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}), open(tcp(443, 443)))

	if findings := findingsFor(result, policy.RuleNetworkPublicIngress); len(findings) != 0 {
		t.Fatalf("the declared port produced %d findings: %+v", len(findings), findings)
	}
	if len(result.Evaluated) != 1 {
		t.Fatalf("evaluated = %v; a judged resource must be reported judged", result.Evaluated)
	}
}

// TestARangeInsideADeclaredRangeIsPermitted covers the comparison being about
// containment rather than equality.
func TestARangeInsideADeclaredRangeIsPermitted(t *testing.T) {
	declared := []model.PortRange{{From: 8000, To: 8100}}

	result := policy.NetworkExposure(declaring(declared), open(tcp(8080, 8090)))

	if findings := findingsFor(result, policy.RuleNetworkPublicIngress); len(findings) != 0 {
		t.Fatalf("a range inside a declared range produced %+v", findings)
	}
}

// TestAPortOutsideTheDeclarationBlocks is the violation this rule exists for.
func TestAPortOutsideTheDeclarationBlocks(t *testing.T) {
	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}), open(tcp(22, 22)))

	findings := findingsFor(result, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	finding := findings[0]
	if finding.Disposition != evidence.DispositionBlock {
		t.Errorf("disposition = %q, want BLOCK", finding.Disposition)
	}
	if finding.Severity != evidence.SeverityHigh {
		t.Errorf("severity = %q, want HIGH; severity is impact and does not follow the contract",
			finding.Severity)
	}
	if finding.Resource == nil || finding.Resource.Address != "aws_security_group.web" {
		t.Errorf("the finding does not name the resource: %+v", finding.Resource)
	}
	if len(finding.Evidence) == 0 {
		t.Error("the finding carries no evidence, so nothing locates what it rests on")
	}
	if finding.Observed == nil || finding.Observed.Value == nil ||
		!strings.Contains(finding.Observed.Value.Display(), "22") {
		t.Errorf("the observed fact does not say which port is open: %+v", finding.Observed)
	}
}

// TestAPartlyOverlappingRangeExceedsTheDeclaration covers the half-permission a
// containment check must refuse: most of the range was declared and one port was
// not, and one port is enough.
func TestAPartlyOverlappingRangeExceedsTheDeclaration(t *testing.T) {
	declared := []model.PortRange{{From: 8000, To: 8100}}

	result := policy.NetworkExposure(declaring(declared), open(tcp(7999, 8050)))

	if findings := findingsFor(result, policy.RuleNetworkPublicIngress); len(findings) != 1 {
		t.Fatalf("a partly declared range produced %d findings", len(findings))
	}
}

// TestAnEmptyDeclarationForbidsEveryPort covers the most restrictive thing the
// contract can say about this family.
func TestAnEmptyDeclarationForbidsEveryPort(t *testing.T) {
	result := policy.NetworkExposure(declaring([]model.PortRange{}), open(tcp(443, 443)))

	findings := findingsFor(result, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 || findings[0].Disposition != evidence.DispositionBlock {
		t.Fatalf("an empty declaration did not block port 443: %+v", findings)
	}
}

// TestNoDeclarationNeedsAHuman covers the product decision that silence is not
// permission. The change is reported, and it is not called a violation of an
// intent nobody stated.
func TestNoDeclarationNeedsAHuman(t *testing.T) {
	result := policy.NetworkExposure(declaring(nil), open(tcp(22, 22)))

	findings := findingsFor(result, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Disposition != evidence.DispositionWarn {
		t.Errorf("disposition = %q, want WARN where the contract declared nothing", findings[0].Disposition)
	}
	if findings[0].Severity != evidence.SeverityHigh {
		t.Errorf("severity = %q, want HIGH; it does not follow the contract", findings[0].Severity)
	}
}

// TestAProtocolWithNoPortsNeedsAHuman covers the decision taken rather than
// asked. A port list can neither permit nor forbid ICMP, so reporting nothing
// would read as permission and blocking would be this build deciding that ping
// from the internet is a violation.
func TestAProtocolWithNoPortsNeedsAHuman(t *testing.T) {
	icmp := model.OpenRange{Protocol: model.ProtocolICMP}

	for name, ports := range map[string][]model.PortRange{
		"with a declaration":  {port(443)},
		"with an empty one":   {},
		"with no declaration": nil,
	} {
		t.Run(name, func(t *testing.T) {
			result := policy.NetworkExposure(declaring(ports), open(icmp))

			findings := findingsFor(result, policy.RuleNetworkPublicIngress)
			if len(findings) != 1 {
				t.Fatalf("got %d findings, want 1", len(findings))
			}
			if findings[0].Disposition != evidence.DispositionWarn {
				t.Fatalf("disposition = %q, want WARN for a protocol the contract cannot describe",
					findings[0].Disposition)
			}
		})
	}
}

// TestEveryProtocolOnEveryPortIsNotPermittedByAPortList covers the rule a reader
// would most want right: "-1" on AWS, "*" on Azure, "all" on GCP opens every
// protocol, and a declaration of 443 has not declared that.
func TestEveryProtocolOnEveryPortIsNotPermittedByAPortList(t *testing.T) {
	every := model.OpenRange{Protocol: model.ProtocolEvery, Ports: model.EveryPort()}

	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}), open(every))

	findings := findingsFor(result, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 || findings[0].Disposition != evidence.DispositionBlock {
		t.Fatalf("every protocol on every port did not block under a declaration of 443: %+v", findings)
	}
}

// TestProvenClosureIsSilent covers the case that must produce nothing: the plan
// holds the whole set and the set permits no ingress from any address.
func TestProvenClosureIsSilent(t *testing.T) {
	graph := open()
	graph.Resources[0].Network.PublicIngress = model.Known(false, model.Provenance{
		ResourceAddress: "aws_security_group.web",
		AttributePath:   "ingress",
		Cloud:           model.CloudAWS,
	})

	result := policy.NetworkExposure(declaring([]model.PortRange{}), graph)

	if len(result.Findings) != 0 {
		t.Fatalf("proven closure produced %+v", result.Findings)
	}
	if len(unknownsFor(result, policy.CheckNetworkIngressDeterminable)) != 0 {
		t.Fatal("proven closure produced an unknown")
	}
	if len(result.Evaluated) != 1 {
		t.Fatal("a resource this rule settled was not reported judged")
	}
}

// TestAnUnsettledRuleSetIsUnknown covers the asymmetry the design rests on: a
// grant can be proven from part of a set and closure cannot, so a set the plan
// does not hold in full is undetermined rather than closed.
func TestAnUnsettledRuleSetIsUnknown(t *testing.T) {
	graph := open()
	graph.Resources[0].Network.PublicIngress = model.Unknown[bool](model.Provenance{
		ResourceAddress: "aws_security_group.web",
		AttributePath:   "ingress",
		Cloud:           model.CloudAWS,
	})

	for name, c := range map[string]struct {
		ports    []model.PortRange
		required bool
	}{
		"a declaration is waiting on it": {[]model.PortRange{port(443)}, true},
		"an empty declaration too":       {[]model.PortRange{}, true},
		"nothing was declared":           {nil, false},
	} {
		t.Run(name, func(t *testing.T) {
			result := policy.NetworkExposure(declaring(c.ports), graph)

			unknowns := unknownsFor(result, policy.CheckNetworkIngressDeterminable)
			if len(unknowns) != 1 {
				t.Fatalf("got %d unknowns, want 1: %+v", len(unknowns), unknowns)
			}
			if unknowns[0].Required != c.required {
				t.Fatalf("required = %v, want %v", unknowns[0].Required, c.required)
			}
			if len(result.Findings) != 0 {
				t.Fatalf("an undetermined set produced a finding: %+v", result.Findings)
			}
		})
	}
}

// TestAWithdrawnDeterminationIsAlwaysRequired covers the distinction storage
// learned the hard way: "the plan determined nothing" is bounded by what the
// contract asked for, and "something was determined and this build declined to
// use it" is not.
func TestAWithdrawnDeterminationIsAlwaysRequired(t *testing.T) {
	graph := open()
	graph.Resources[0].Network.PublicIngress = model.Unknown[bool]()
	graph.Resources[0].Network.Withdrawn = true

	result := policy.NetworkExposure(declaring(nil), graph)

	unknowns := unknownsFor(result, policy.CheckNetworkIngressDeterminable)
	if len(unknowns) != 1 || !unknowns[0].Required {
		t.Fatalf("a withdrawn determination produced %+v", unknowns)
	}
}

// TestUnresolvedControlsAreReportedWithoutPreventingAConclusion covers what
// bounds the evidence rather than blocking it: the attachment that decides what a
// rule set applies to is usually not in the plan, and a reader needs to know that
// without the finding being withheld.
func TestUnresolvedControlsAreReportedWithoutPreventingAConclusion(t *testing.T) {
	graph := open(tcp(22, 22))
	graph.Resources[0].Network.Unresolved = []model.MissingControl{{
		CheckID: "NETWORK_ATTACHMENT_UNKNOWN",
		Reason:  "The plan does not state what this rule set is attached to.",
		Cloud:   model.CloudAWS,
	}}

	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}), graph)

	if len(findingsFor(result, policy.RuleNetworkPublicIngress)) != 1 {
		t.Fatal("an unresolved control withheld the finding")
	}
	unknowns := unknownsFor(result, "NETWORK_ATTACHMENT_UNKNOWN")
	if len(unknowns) != 1 {
		t.Fatalf("got %d unknowns for the attachment, want 1", len(unknowns))
	}
	if unknowns[0].Required {
		t.Error("an unresolved control made the verdict unknown; it bounds the evidence, not the conclusion")
	}
}

// TestAControlResourceReachesNoVerdict covers the resource that is understood and
// carries no capabilities of its own, because its meaning belongs to the set it
// belongs to. Claiming to have judged it would make coverage lie.
func TestAControlResourceReachesNoVerdict(t *testing.T) {
	graph := model.Graph{Resources: []model.NormalizedResource{{
		Address:     "aws_vpc_security_group_ingress_rule.web",
		Cloud:       model.CloudAWS,
		Family:      model.FamilyNetwork,
		Interpreted: true,
		DefersTo:    []string{"aws_security_group.web"},
	}}}

	result := policy.NetworkExposure(declaring(nil), graph)

	if len(result.Findings) != 0 || len(result.Unknowns) != 0 {
		t.Fatalf("a control resource produced %+v and %+v", result.Findings, result.Unknowns)
	}
	if len(result.Evaluated) != 0 {
		t.Fatalf("a control resource was reported judged: %v", result.Evaluated)
	}
}

// TestTheObservedValueIsBuiltFromNumbersAndNotFromProviderText covers the one
// place a plan value could reach a report through this rule. The ports are
// integers and the protocol is a closed set, so what reaches a reader is composed
// here rather than copied from a provider field -- which is what keeps a for_each
// key or a rule description out of it.
func TestTheObservedValueIsBuiltFromNumbersAndNotFromProviderText(t *testing.T) {
	hostile := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 22, To: 22},
		Sources: []model.Provenance{{
			ResourceAddress: "aws_security_group.web[\"<script>\"]",
			AttributePath:   "ingress[0].description",
			Cloud:           model.CloudAWS,
		}},
	}

	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}), open(hostile))

	findings := findingsFor(result, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	observed := findings[0].Observed.Value.Display()
	if strings.Contains(observed, "script") {
		t.Fatalf("provider text reached the observed value: %q", observed)
	}
	if observed != "tcp/22" {
		t.Fatalf("observed = %q, want the protocol and port this build composed", observed)
	}
}

// TestOneFindingPerResourceWhateverTheRanges keeps a reader's report proportionate
// to the change: a security group opening forty ports is one thing to fix, not
// forty findings.
func TestOneFindingPerResourceWhateverTheRanges(t *testing.T) {
	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}),
		open(tcp(22, 22), tcp(3389, 3389), tcp(443, 443)))

	findings := findingsFor(result, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want one per resource", len(findings))
	}
	observed := findings[0].Observed.Value.Display()
	for _, want := range []string{"tcp/22", "tcp/3389"} {
		if !strings.Contains(observed, want) {
			t.Errorf("observed %q does not name %s", observed, want)
		}
	}
	if strings.Contains(observed, "443") {
		t.Errorf("observed %q names a port the contract declared", observed)
	}
}

// TestANetworkDeclarationThePlanCannotExerciseIsReported covers the contract-level
// form of absence read as permission: a declaration the change gives nothing to
// apply to was checked against an empty set, and a PASS beside it would read as
// "held".
func TestANetworkDeclarationThePlanCannotExerciseIsReported(t *testing.T) {
	ports := []model.PortRange{port(443)}
	declared := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: intent.FamilyNetwork, PublicPorts: &ports}}
	})

	result := policy.ContractCoverage(declared, model.Graph{})

	unknowns := unknownsFor(result, policy.CheckContractFamilyAbsent)
	if len(unknowns) != 1 {
		t.Fatalf("got %d unknowns, want 1: %+v", len(unknowns), unknowns)
	}
	if !unknowns[0].Required {
		t.Error("an unexercised declaration did not prevent a pass")
	}
	// The sentence has to be about the ports that were declared, because that is
	// what this family declares. "declares  exposure for network" is what one
	// sentence for both families produced.
	//
	// Both halves are asserted, and that is the point: the two network sentences
	// are near-inversions of each other -- "the ports that may be reachable" and
	// "that no port may be reachable" -- and a test checking only that the reason
	// mentions "reachable from any address" is satisfied by either. Swapping them
	// made this report say the contract declares that no port may be reachable
	// for a contract declaring 443, with the suite green.
	reason := unknowns[0].Reason
	if !strings.Contains(reason, "the ports of network that may be reachable from any address") {
		t.Errorf("the reason does not say a declaration of ports was made: %q", reason)
	}
	if strings.Contains(reason, "no port") {
		t.Errorf("the reason inverts what the contract declared: %q", reason)
	}
	if strings.Contains(reason, "exposure") {
		t.Errorf("the reason names a field this family does not have: %q", reason)
	}
}

// TestAnEmptyNetworkDeclarationIsDescribedAsTheRestrictionItIs is the other
// sentence, and the reason the one above asserts both halves.
//
// An empty port list is the most restrictive thing this field can say, and the
// report has to say that rather than "the ports that may be reachable", which
// would describe a list the author deliberately left empty as though it named
// something.
func TestAnEmptyNetworkDeclarationIsDescribedAsTheRestrictionItIs(t *testing.T) {
	none := []model.PortRange{}
	declared := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: intent.FamilyNetwork, PublicPorts: &none}}
	})

	result := policy.ContractCoverage(declared, model.Graph{})

	unknowns := unknownsFor(result, policy.CheckContractFamilyAbsent)
	if len(unknowns) != 1 {
		t.Fatalf("got %d unknowns, want 1: %+v", len(unknowns), unknowns)
	}
	reason := unknowns[0].Reason
	if !strings.Contains(reason, "that no port of network may be reachable from any address") {
		t.Errorf("an empty declaration is not described as the restriction it is: %q", reason)
	}
	if strings.Contains(reason, "the ports of network that may") {
		t.Errorf("an empty declaration is described as naming ports: %q", reason)
	}
}

// TestAnEmptyNetworkDeclarationIsStillARequirement covers the one that is easiest
// to drop: declaring that no port may be public is a statement, and a plan with no
// network resource did not exercise it.
func TestAnEmptyNetworkDeclarationIsStillARequirement(t *testing.T) {
	none := []model.PortRange{}
	declared := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{Family: intent.FamilyNetwork, PublicPorts: &none}}
	})

	result := policy.ContractCoverage(declared, model.Graph{})

	if len(unknownsFor(result, policy.CheckContractFamilyAbsent)) != 1 {
		t.Fatal("an empty declaration was not treated as a requirement to exercise")
	}
}

// TestTheNetworkRuleRunsInTheEngine keeps the rule wired in. A rule nobody calls
// is a rule whose tests pass and whose verdict never reaches a reader.
func TestTheNetworkRuleRunsInTheEngine(t *testing.T) {
	bundle := policy.Evaluate(declaring([]model.PortRange{port(443)}), open(tcp(22, 22)),
		policy.Subject{PlanFormatVersion: "1.2", PlanDigest: "sha256:" + strings.Repeat("0", 64)})

	if bundle.Decision != evidence.DecisionBlock {
		t.Fatalf("decision = %q, want BLOCK", bundle.Decision)
	}
	var found bool
	for _, finding := range bundle.Findings {
		if finding.RuleID == policy.RuleNetworkPublicIngress {
			found = true
		}
	}
	if !found {
		t.Fatalf("the engine produced no network finding: %+v", bundle.Findings)
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("the bundle does not satisfy its own contract: %v", err)
	}
}

// TestTheObservedValueIsOrderedAndSaysEachThingOnce covers two properties a
// report is read with. Two runs over one plan must say the same thing, so the
// ranges are ordered rather than left in whatever order a mapper appended them;
// and a rule set that opens one port twice is one port, not two.
func TestTheObservedValueIsOrderedAndSaysEachThingOnce(t *testing.T) {
	result := policy.NetworkExposure(declaring([]model.PortRange{}),
		open(tcp(3389, 3389), tcp(22, 22), tcp(3389, 3389), tcp(80, 443)))

	findings := findingsFor(result, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	if got := findings[0].Observed.Value.Display(); got != "tcp/22, tcp/3389, tcp/80-443" {
		t.Fatalf("observed = %q, want it ordered and each range once", got)
	}
}

// TestAFindingStatesNoExpectationNobodyDeclared covers what a bundle must not
// claim. Where the contract declared nothing about this family, there is no
// expectation to record -- and recording "no ingress from any address" would put
// a requirement in the report that its author never wrote.
func TestAFindingStatesNoExpectationNobodyDeclared(t *testing.T) {
	undeclared := policy.NetworkExposure(declaring(nil), open(tcp(22, 22)))

	findings := findingsFor(undeclared, policy.RuleNetworkPublicIngress)
	if len(findings) != 1 {
		t.Fatalf("got %d findings", len(findings))
	}
	if findings[0].Expected != nil {
		t.Fatalf("a finding under no declaration expects %+v", findings[0].Expected)
	}

	// And where the contract declared none, the expectation is exactly that.
	declaredNone := policy.NetworkExposure(declaring([]model.PortRange{}), open(tcp(22, 22)))
	stated := findingsFor(declaredNone, policy.RuleNetworkPublicIngress)
	if len(stated) != 1 || stated[0].Expected == nil {
		t.Fatalf("a finding under an empty declaration carries no expectation: %+v", stated)
	}
	if stated[0].Expected.Path != "network.public_ingress" ||
		stated[0].Expected.Value.Display() != "false" {
		t.Fatalf("expected = %+v, want network.public_ingress = false", stated[0].Expected)
	}

	// And where it declared ports, the expectation is the ports.
	declaredPorts := policy.NetworkExposure(declaring([]model.PortRange{port(443), {From: 8000, To: 8100}}),
		open(tcp(22, 22)))
	ports := findingsFor(declaredPorts, policy.RuleNetworkPublicIngress)
	if len(ports) != 1 || ports[0].Expected == nil {
		t.Fatalf("a finding under a port declaration carries no expectation: %+v", ports)
	}
	if got := ports[0].Expected.Value.Display(); got != "443, 8000-8100" {
		t.Fatalf("expected = %q, want the declared ports", got)
	}
}

// TestADeclarationPermitsWhatItsRangesCoverTogether covers the arithmetic of the
// declaration side, which asked whether any one declared range contained the
// whole opened range and never whether the declaration covered it between them.
//
// A contract declaring 80 and 81 has declared 80-81. Reporting a BLOCK there
// produced a finding whose claim -- "on a port the intent contract does not
// declare" -- was untrue of every port involved, and a BLOCK is required to rest
// on deterministic evidence rather than on arithmetic.
func TestADeclarationPermitsWhatItsRangesCoverTogether(t *testing.T) {
	cases := map[string]struct {
		declared []model.PortRange
		opened   model.OpenRange
		findings int
		why      string
	}{
		"two adjacent single ports covering a range": {
			[]model.PortRange{port(80), port(81)}, tcp(80, 81), 0,
			"80 and 81 declared is 80-81 declared"},
		"overlapping declarations covering a range": {
			[]model.PortRange{{From: 8000, To: 8050}, {From: 8040, To: 8100}}, tcp(8000, 8100), 0,
			"the two together cover every port opened; overlap is not a gap"},
		"three ranges meeting exactly": {
			[]model.PortRange{{From: 1, To: 10}, {From: 11, To: 20}, {From: 21, To: 30}},
			tcp(1, 30), 0, "a declaration written in pieces is still a declaration"},
		// The direction that must not move: a gap in the declaration is a port
		// nobody declared, and reading the union as permission must not paper
		// over it.
		"two ranges with a gap": {
			[]model.PortRange{{From: 1, To: 10}, {From: 12, To: 30}}, tcp(1, 30), 1,
			"port 11 is opened and declared nowhere"},
		"a declaration one port short": {
			[]model.PortRange{port(80)}, tcp(80, 81), 1,
			"81 is opened and not declared"},
		"partial overlap is still not permission": {
			[]model.PortRange{{From: 8000, To: 8100}}, tcp(7999, 8000), 1,
			"7999 is opened and not declared"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			result := policy.NetworkExposure(declaring(c.declared), open(c.opened))

			if got := len(result.Findings); got != c.findings {
				t.Fatalf("%d findings, want %d: %s\n%+v", got, c.findings, c.why, result.Findings)
			}
		})
	}
}

// TestEveryProtocolIsNeverFullyPermittedByAPortList covers the one protocol a
// port declaration cannot describe while still having ports.
//
// `every` carries ports, so it was compared by ports alone and a declaration of
// 0-65535 permitted it outright -- including the port-less protocols inside it
// that this build's own doctrine says a port list can neither permit nor forbid.
// ICMP alone needed a human; ICMP plus everything else did not.
func TestEveryProtocolIsNeverFullyPermittedByAPortList(t *testing.T) {
	everything := model.OpenRange{
		Protocol: model.ProtocolEvery,
		Ports:    model.EveryPort(),
		Sources:  tcp(0, 0).Sources,
	}
	onePort := model.OpenRange{
		Protocol: model.ProtocolEvery,
		Ports:    port(443),
		Sources:  tcp(0, 0).Sources,
	}

	for name, opened := range map[string]model.OpenRange{
		"every port": everything,
		"one port":   onePort,
	} {
		t.Run(name, func(t *testing.T) {
			declaredEverything := []model.PortRange{model.EveryPort()}
			result := policy.NetworkExposure(declaring(declaredEverything), open(opened))

			if len(result.Findings) != 1 {
				t.Fatalf("a grant on every protocol produced %d findings; a port list cannot permit "+
					"the protocols inside it that have no ports", len(result.Findings))
			}
			if got := result.Findings[0].Claim; !strings.Contains(got, "protocol") {
				t.Errorf("the claim does not mention the protocol: %q", got)
			}
		})
	}

	// And ICMP alone, which already worked, has to keep answering the same way:
	// the two are the same question and must not diverge.
	icmp := model.OpenRange{Protocol: model.ProtocolICMP, Sources: tcp(0, 0).Sources}
	result := policy.NetworkExposure(declaring([]model.PortRange{model.EveryPort()}), open(icmp))
	if len(result.Findings) != 1 {
		t.Fatalf("ICMP alone produced %d findings", len(result.Findings))
	}
}

// TestAContractViolationOutranksAQuestion covers the precedence between the two
// dispositions this rule can reach, which nothing tested.
//
// An undeclared port open to the internet is a statement the contract
// contradicts. A port-less protocol is a question the contract cannot answer. A
// disposition must never be lowered by an additional fact, so when both are
// present the answer is BLOCK -- and reversing the two switch arms turned a
// contract violation into a warning with a green suite.
func TestAContractViolationOutranksAQuestion(t *testing.T) {
	undeclared := tcp(22, 22)
	portless := model.OpenRange{Protocol: model.ProtocolICMP, Sources: tcp(0, 0).Sources}
	declared := []model.PortRange{port(443)}

	result := policy.NetworkExposure(declaring(declared), open(undeclared, portless))

	if len(result.Findings) != 1 {
		t.Fatalf("%d findings, want one finding about the set", len(result.Findings))
	}
	finding := result.Findings[0]
	if finding.Disposition != evidence.DispositionBlock {
		t.Fatalf("disposition = %q, want %q: an undeclared port open to the internet is a violation "+
			"whether or not something else alongside it needs a human",
			finding.Disposition, evidence.DispositionBlock)
	}

	// And the claim has to account for everything the Observed value carries, or
	// part of a BLOCK's evidence supports a conclusion the claim never states.
	if finding.Observed == nil {
		t.Fatal("the finding observes nothing")
	}
	observed := finding.Observed.Value.Display()
	if !strings.Contains(observed, "tcp/22") || !strings.Contains(observed, "icmp") {
		t.Fatalf("observed = %q, want both facts", observed)
	}
	if !strings.Contains(finding.Claim, "port") || !strings.Contains(finding.Claim, "protocol") {
		t.Fatalf("the claim covers only part of what it observed: %q\nobserved: %q",
			finding.Claim, observed)
	}
}

// TestTheDecidingFactIsAlwaysCited covers the one citation a reader cannot do
// without. The ranges carry their own sources, so dropping the provenance of the
// fact the verdict rests on left the evidence list non-empty and every existing
// assertion satisfied.
func TestTheDecidingFactIsAlwaysCited(t *testing.T) {
	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}), open(tcp(22, 22)))

	if len(result.Findings) != 1 {
		t.Fatalf("%d findings, want one", len(result.Findings))
	}
	var cited bool
	for _, ref := range result.Findings[0].Evidence {
		if ref.Path == "ingress[0].cidr_blocks[0]" {
			cited = true
		}
	}
	if !cited {
		t.Fatalf("the fact the verdict rests on is not cited: %+v", result.Findings[0].Evidence)
	}

	// And no citation appears twice. The deciding fact and the ranges overlap,
	// so a reader was shown each source two and three times over, which is how
	// an evidence list stops being read.
	seen := map[evidence.EvidenceRef]bool{}
	for _, ref := range result.Findings[0].Evidence {
		if seen[ref] {
			t.Errorf("the evidence cites %+v twice", ref)
		}
		seen[ref] = true
	}
}

// TestNoRangeEverCarriesAProtocolWithNoName covers the mandatory observed fact.
//
// ProtocolUnrecognized is the empty string, deliberately: it is the zero value so
// that a protocol nobody read cannot be mistaken for one that was. But a range
// carrying it renders as nothing, and a finding whose one required observed fact
// is "" tells a reader less than no finding would. The mappers now refuse such a
// protocol outright, and this is the assertion that keeps them doing it.
func TestNoRangeEverCarriesAProtocolWithNoName(t *testing.T) {
	unnameable := model.OpenRange{Protocol: model.ProtocolUnrecognized, Sources: tcp(0, 0).Sources}

	result := policy.NetworkExposure(declaring([]model.PortRange{port(443)}),
		open(unnameable, tcp(22, 22)))

	if len(result.Findings) != 1 {
		t.Fatalf("%d findings, want one", len(result.Findings))
	}
	observed := result.Findings[0].Observed
	if observed == nil {
		t.Fatal("the finding observes nothing")
	}
	got := observed.Value.Display()
	if got == "" || strings.HasPrefix(got, ",") || strings.Contains(got, ", ,") {
		t.Fatalf("observed = %q: a range whose protocol has no name reached the reader as nothing", got)
	}
}

// TestARenderedDeclarationIsBounded covers the one value in this finding that
// comes from the contract rather than from the plan.
//
// A contract may declare any number of ports, and the Expected fact wrote all of
// them: 1,500 entries produced a 49 KB report with almost all of it inside one
// Markdown table cell. The intent package bounds a quoted contract value at 80
// characters and says why -- "a message that reprints the file is one nobody
// reads to the end" -- and this is the same value reaching the same reader.
//
// What is elided is counted, because a declaration the reader cannot see all of
// must at least say how much of it there was.
func TestARenderedDeclarationIsBounded(t *testing.T) {
	declared := make([]model.PortRange, 0, 1500)
	for p := 1000; p < 4000; p += 2 {
		declared = append(declared, port(p))
	}

	result := policy.NetworkExposure(declaring(declared), open(tcp(22, 22)))

	if len(result.Findings) != 1 {
		t.Fatalf("%d findings, want one", len(result.Findings))
	}
	expected := result.Findings[0].Expected
	if expected == nil {
		t.Fatal("the finding expects nothing")
	}
	rendered := expected.Value.Display()
	if len(rendered) > 200 {
		t.Fatalf("the rendered declaration is %d bytes:\n%s", len(rendered), rendered)
	}
	if !strings.Contains(rendered, "1000") {
		t.Errorf("the rendered declaration does not begin with what was declared: %q", rendered)
	}
	if !strings.Contains(rendered, "1500") && !strings.Contains(rendered, "more") {
		t.Errorf("the rendered declaration elides without saying how much: %q", rendered)
	}

	// A declaration a reader can see all of is written out in full, or the bound
	// has made every report worse to spare the one that was too long.
	short := policy.NetworkExposure(declaring([]model.PortRange{port(80), port(443)}), open(tcp(22, 22)))
	if got := short.Findings[0].Expected.Value.Display(); got != "80, 443" {
		t.Fatalf("a short declaration renders as %q, want it in full", got)
	}
}

// TestTheClaimAccountsForEveryFactWhateverTheContractDeclared covers the half of
// the combined-claim fix that was left gated.
//
// The combined arm was written as `stated && exceeding && undescribable`, so it
// only applied when the contract declared ports. A contract with no network entry
// is the documented, supported case -- silence is not permission -- and there an
// undeclared port beside a port-less protocol produced a claim about the protocol
// alone. SSH open to the whole internet sat in the Observed value and in neither
// the claim nor the remediation, and the review format renders the claim and not
// the observation.
//
// A disposition may depend on what was declared. What a claim accounts for may
// not.
//
// The assertions name whole phrases rather than words. The first version looked
// for "port", which the protocol claim satisfies from inside the sentence "a port
// declaration can neither permit nor forbid it" -- a test passing for the wrong
// reason, in the test written to stop exactly that.
func TestTheClaimAccountsForEveryFactWhateverTheContractDeclared(t *testing.T) {
	const (
		aboutAPort      = "on a port"
		aboutAProtocol  = "on a protocol the intent contract cannot describe"
		fixThePort      = "declare the port in the intent contract"
		fixTheProtocol  = "Confirm that this protocol is intended"
		noDeclaration   = "does not declare which ports may be reachable"
		declareThePorts = "Declare the ports in the intent contract"
	)

	undeclared := tcp(22, 22)
	portless := model.OpenRange{Protocol: model.ProtocolICMP, Sources: tcp(0, 0).Sources}

	cases := map[string]struct {
		contract    intent.Contract
		opened      []model.OpenRange
		disposition evidence.Disposition
		claim       []string
		remediation []string
		why         string
	}{
		"a declaration, a port and a protocol": {
			declaring([]model.PortRange{port(443)}), []model.OpenRange{undeclared, portless},
			evidence.DispositionBlock,
			[]string{aboutAPort, aboutAProtocol}, []string{fixThePort, "protocol"},
			"an undeclared port is a violation whether or not something else needs a human"},
		"no declaration, a port and a protocol": {
			declaring(nil), []model.OpenRange{undeclared, portless},
			evidence.DispositionWarn,
			[]string{aboutAPort, aboutAProtocol}, []string{declareThePorts, "protocol"},
			"the contract declaring nothing does not make the open port stop being a fact"},
		"no declaration, a port alone": {
			declaring(nil), []model.OpenRange{undeclared},
			evidence.DispositionWarn,
			[]string{noDeclaration}, []string{declareThePorts},
			"silence is not permission, and the claim says what is open"},
		"no declaration, a protocol alone": {
			declaring(nil), []model.OpenRange{portless},
			evidence.DispositionWarn,
			[]string{aboutAProtocol}, []string{fixTheProtocol},
			"a port list cannot describe it, declared or not"},
		"an empty declaration, a port and a protocol": {
			declaring([]model.PortRange{}), []model.OpenRange{undeclared, portless},
			evidence.DispositionBlock,
			[]string{aboutAPort, aboutAProtocol}, []string{fixThePort, "protocol"},
			"an empty list is the most restrictive thing the field can say"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			result := policy.NetworkExposure(c.contract, open(c.opened...))

			if len(result.Findings) != 1 {
				t.Fatalf("%d findings, want one: %s", len(result.Findings), c.why)
			}
			finding := result.Findings[0]
			if finding.Disposition != c.disposition {
				t.Errorf("disposition = %q, want %q: %s",
					finding.Disposition, c.disposition, c.why)
			}
			for _, phrase := range c.claim {
				if !strings.Contains(finding.Claim, phrase) {
					t.Errorf("the claim does not say %q: %q\n  %s", phrase, finding.Claim, c.why)
				}
			}
			for _, phrase := range c.remediation {
				if !strings.Contains(finding.Remediation, phrase) {
					t.Errorf("the remediation does not say %q: %q", phrase, finding.Remediation)
				}
			}

			// And nothing in the Observed value may go unaccounted for by the
			// claim, which is the property the whole test defends.
			if finding.Observed == nil {
				t.Fatal("the finding observes nothing")
			}
			observed := finding.Observed.Value.Display()
			if strings.Contains(observed, "tcp/") &&
				!strings.Contains(finding.Claim, aboutAPort) &&
				!strings.Contains(finding.Claim, noDeclaration) {
				t.Errorf("observed %q carries a port the claim never mentions: %q",
					observed, finding.Claim)
			}
			if strings.Contains(observed, "icmp") && !strings.Contains(finding.Claim, aboutAProtocol) {
				t.Errorf("observed %q carries a protocol the claim never mentions: %q",
					observed, finding.Claim)
			}
		})
	}
}
