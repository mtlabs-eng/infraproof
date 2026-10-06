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
	// The sentence has to be about ports, because that is what this family
	// declares. "declares  exposure for network" is what one sentence for both
	// families produced.
	if !strings.Contains(unknowns[0].Reason, "reachable from any address") {
		t.Errorf("the reason does not describe a network declaration: %q", unknowns[0].Reason)
	}
	if strings.Contains(unknowns[0].Reason, "exposure") {
		t.Errorf("the reason names a field this family does not have: %q", unknowns[0].Reason)
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
