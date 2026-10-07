package policy_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
)

// declaringExposure returns a contract whose database entry declares one.
func declaringExposure(exposure intent.Exposure) intent.Contract {
	return contract(func(c *intent.Contract) {
		if exposure == "" {
			return
		}
		c.Resources = append(c.Resources, intent.ResourceIntent{
			Family:   intent.FamilyDatabase,
			Exposure: exposure,
		})
	})
}

// reachable returns a graph holding one database with the two facts set, and
// optionally the resource that gates it.
func reachable(endpoint, admits model.Fact[bool], port model.Fact[int],
	gatedBy ...model.NormalizedResource) model.Graph {

	var gates []string
	for _, gate := range gatedBy {
		gates = append(gates, gate.Address)
	}
	graph := model.Graph{Resources: []model.NormalizedResource{{
		Address:     "aws_db_instance.main",
		Provider:    "registry.terraform.io/hashicorp/aws",
		Cloud:       model.CloudAWS,
		Family:      model.FamilyDatabase,
		Interpreted: true,
		Database: &model.DatabaseCapabilities{
			PublicEndpoint:   endpoint,
			AdmitsAnyAddress: admits,
			Port:             port,
			// The helper stands for the AWS shape, where a determined port
			// almost always came from the engine table: `port` is Optional and
			// Computed, so it is unknown unless somebody wrote it. A test about
			// a port the plan states sets this false and says so -- see
			// TestTheInferredPortDisclosureIsNotMadeAboutAStatedPort.
			PortInferred: true,
			GatedBy:      gates,
		},
	}}}
	graph.Resources = append(graph.Resources, gatedBy...)
	return graph
}

// group returns a security group as the network family already normalizes one.
func group(address string, ingress model.Fact[bool], open ...model.OpenRange) model.NormalizedResource {
	return model.NormalizedResource{
		Address:     address,
		Provider:    "registry.terraform.io/hashicorp/aws",
		Cloud:       model.CloudAWS,
		Family:      model.FamilyNetwork,
		Interpreted: true,
		Network: &model.NetworkCapabilities{
			PublicIngress:    ingress,
			OpenToAnyAddress: open,
		},
	}
}

func known(v bool) model.Fact[bool]   { return model.Known(v, provenance()) }
func knownPort(p int) model.Fact[int] { return model.Known(p, provenance()) }
func unknownBool() model.Fact[bool]   { return model.Unknown[bool](provenance()) }
func unknownPort() model.Fact[int]    { return model.Unknown[int](provenance()) }

func provenance() model.Provenance {
	return model.Provenance{
		ResourceAddress: "aws_db_instance.main",
		AttributePath:   "publicly_accessible",
		Cloud:           model.CloudAWS,
	}
}

// TestADatabaseIsReachableOnlyWhenBothHalvesAreOpen is the rule's whole job, and
// the thing that makes this family different from the two before it.
//
// Reachability is a conjunction. An endpoint nobody is admitted to is not
// reachable; an allow list in front of no endpoint reaches nothing. Reporting
// either half alone would produce a finding on the ordinary shape, which is how a
// tool teaches people to ignore it.
func TestADatabaseIsReachableOnlyWhenBothHalvesAreOpen(t *testing.T) {
	cases := map[string]struct {
		endpoint, admits model.Fact[bool]
		findings         int
		why              string
	}{
		"both open": {known(true), known(true), 1,
			"an endpoint outside the network, and everything admitted to it"},
		"an endpoint nobody is admitted to": {known(true), known(false), 0,
			"a public endpoint is not reachability"},
		"an allow list in front of no endpoint": {known(false), known(true), 0,
			"admitting the world to something that has no public endpoint reaches nothing"},
		"neither": {known(false), known(false), 0,
			"the ordinary private database"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			result := policy.DatabaseExposure(
				declaringExposure(intent.ExposurePrivate),
				reachable(c.endpoint, c.admits, knownPort(5432)))

			if got := len(result.Findings); got != c.findings {
				t.Fatalf("%d findings, want %d: %s\n%+v", got, c.findings, c.why, result.Findings)
			}
			// Either way the rule judged it, or coverage reports a resource no
			// rule looked at.
			if len(result.Evaluated) != 1 {
				t.Errorf("the rule judged %d resources, want 1", len(result.Evaluated))
			}
		})
	}
}

// TestAHalfThePlanDoesNotHoldIsUnknownAndSaysWhichHalf covers what a reader does
// next. For AWS this is the common case, not an edge one: a security group is
// usually in another module.
func TestAHalfThePlanDoesNotHoldIsUnknownAndSaysWhichHalf(t *testing.T) {
	cases := map[string]struct {
		endpoint, admits model.Fact[bool]
		says             string
	}{
		"the endpoint is undetermined":   {unknownBool(), known(true), "endpoint"},
		"the allow list is undetermined": {known(true), unknownBool(), "admit"},
		"both are undetermined":          {unknownBool(), unknownBool(), "endpoint"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			result := policy.DatabaseExposure(
				declaringExposure(intent.ExposurePrivate),
				reachable(c.endpoint, c.admits, knownPort(5432)))

			if len(result.Findings) != 0 {
				t.Fatalf("an undetermined half produced %d findings", len(result.Findings))
			}
			if len(result.Unknowns) == 0 {
				t.Fatal("nothing is reported as undetermined")
			}
			var required, said bool
			for _, unknown := range result.Unknowns {
				if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable {
					required = unknown.Required
					if strings.Contains(unknown.Reason, c.says) {
						said = true
					}
				}
			}
			if !required {
				t.Error("the contract declared an exposure and the unknown does not prevent a pass")
			}
			if !said {
				t.Errorf("the reason does not name the missing half (%q):\n%+v", c.says, result.Unknowns)
			}
		})
	}

	// An author who declared nothing is not waiting on evidence about databases,
	// which is the rule storage and network already follow.
	result := policy.DatabaseExposure(declaringExposure(""),
		reachable(unknownBool(), unknownBool(), unknownPort()))
	for _, unknown := range result.Unknowns {
		if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable && unknown.Required {
			t.Error("an undeclared family raised a required unknown")
		}
	}
}

// TestTheDeclaredExposureChangesTheDispositionAndNotTheFinding is the milestone's
// criterion 9, and the doctrine severity follows: impact does not depend on what
// anyone wrote down.
func TestTheDeclaredExposureChangesTheDispositionAndNotTheFinding(t *testing.T) {
	cases := map[string]struct {
		declared    intent.Exposure
		findings    int
		disposition evidence.Disposition
	}{
		"private declared":     {intent.ExposurePrivate, 1, evidence.DispositionBlock},
		"unspecified declared": {intent.ExposureUnspecified, 1, evidence.DispositionWarn},
		"nothing declared":     {"", 1, evidence.DispositionWarn},
		"public declared":      {intent.ExposurePublic, 0, ""},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			result := policy.DatabaseExposure(declaringExposure(c.declared),
				reachable(known(true), known(true), knownPort(5432)))

			if got := len(result.Findings); got != c.findings {
				t.Fatalf("%d findings, want %d", got, c.findings)
			}
			if c.findings == 0 {
				return
			}
			finding := result.Findings[0]
			if finding.Disposition != c.disposition {
				t.Errorf("disposition = %q, want %q", finding.Disposition, c.disposition)
			}
			if finding.RuleID != policy.RuleDatabasePublicReachable {
				t.Errorf("rule = %q", finding.RuleID)
			}
			if finding.Severity != evidence.SeverityHigh {
				t.Errorf("severity = %q, want %q; impact does not depend on the contract",
					finding.Severity, evidence.SeverityHigh)
			}
		})
	}
}

// TestTheAllowListMayBeAnotherResourcesVerdict is the composition, and the
// milestone's reason for existing.
//
// On AWS a database's allow list is a security group, which is a subject the
// network family already judges. The database names it rather than re-reading it,
// and the rule resolves the name against the graph -- so no mapper depends on
// another mapper and nothing in the network family changes.
func TestTheAllowListMayBeAnotherResourcesVerdict(t *testing.T) {
	postgres := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 5432, To: 5432},
		Sources:  []model.Provenance{provenance()},
	}
	https := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 443, To: 443},
		Sources:  []model.Provenance{provenance()},
	}

	cases := map[string]struct {
		gate     model.NormalizedResource
		port     model.Fact[int]
		findings int
		why      string
	}{
		"the group admits the database's port": {
			group("aws_security_group.db", known(true), postgres), knownPort(5432), 1,
			"the group is open to the world on 5432 and the database listens there"},
		"the group admits another port": {
			group("aws_security_group.web", known(true), https), knownPort(5432), 0,
			"443 does not reach Postgres; a shared group is the common shape and must not report"},
		"the group admits nobody": {
			group("aws_security_group.db", known(false)), knownPort(5432), 0,
			"the network family proved the set permits none"},
		"the group admits the port among others": {
			group("aws_security_group.db", known(true), https, postgres), knownPort(5432), 1,
			"one range reaching it is enough"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
				reachable(known(true), unknownBool(), c.port, c.gate))

			if got := len(result.Findings); got != c.findings {
				t.Fatalf("%d findings, want %d: %s", got, c.findings, c.why)
			}
		})
	}
}

// TestAGateTheGraphDoesNotHoldSettlesNothing covers the security group managed
// elsewhere, which is the AWS shape a plan usually has.
func TestAGateTheGraphDoesNotHoldSettlesNothing(t *testing.T) {
	graph := reachable(known(true), unknownBool(), knownPort(5432))
	graph.Resources[0].Database.GatedBy = []string{"aws_security_group.elsewhere"}

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

	if len(result.Findings) != 0 {
		t.Fatalf("a gate the plan does not hold produced %d findings", len(result.Findings))
	}
	var required bool
	for _, unknown := range result.Unknowns {
		if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable {
			required = unknown.Required
		}
	}
	if !required {
		t.Error("a gate nobody can read does not prevent a pass")
	}
}

// TestAnUndeterminedPortReportsWiderThanRealityAndSaysSo covers the decision the
// milestone names as most likely to be wrong.
//
// An engine the port table cannot name leaves the port unknown, and then any
// address admitted at all is reported as possibly reaching the database. That
// over-reports, which is the safe direction, and the approximation is recorded so
// a reader is not told an exact thing.
//
// What the over-report is *called* changed. It used to be a finding, so a gate
// open on 443 in front of a database whose engine the table cannot name produced
// a BLOCK whose observed fact read `KNOWN true`. CLAUDE.md states without
// exception that a BLOCK must be supported by deterministic evidence and that
// insufficient evidence is UNKNOWN, and this rule's own comment says a BLOCK
// resting on an approximation is one whose claim is wider than the evidence. It
// is a required unknown now: still not silent, which is the whole of the
// milestone's decision, and no longer asserting a fact the build cannot prove.
//
// See TestABlockNeverRestsOnAPortNobodyKnows for the boundary -- a gate admitting
// every usable port is determined, because what the database listens on cannot
// matter.
func TestAnUndeterminedPortReportsWiderThanRealityAndSaysSo(t *testing.T) {
	https := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 443, To: 443},
		Sources:  []model.Provenance{provenance()},
	}

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), unknownPort(),
			group("aws_security_group.web", known(true), https)))

	if len(result.Findings) != 0 {
		t.Fatalf("%d findings: an approximation is not a BLOCK", len(result.Findings))
	}
	var stopped bool
	for _, unknown := range result.Unknowns {
		if unknown.Required {
			stopped = true
		}
	}
	if !stopped {
		t.Fatal("an unknown port ruled the group out in silence")
	}
	var said bool
	for _, unknown := range result.Unknowns {
		if strings.Contains(unknown.Reason, "port") {
			said = true
		}
	}
	if !said {
		t.Error("the approximation is not reported, so a reader reads the finding as exact")
	}
}

// TestADatabaseDeclarationThePlanCannotExerciseIsReported covers the coverage
// rule for the third family, and the sentence a reader is given for it.
//
// ContractCoverage discovers families from the graph rather than from a list, so
// it needs no change -- but declaredAs writes the sentence, and object storage is
// its fallthrough. A family inheriting that must still produce something true:
// "private exposure for database" is the right sentence, and the test says so
// rather than leaving the agreement to chance.
func TestADatabaseDeclarationThePlanCannotExerciseIsReported(t *testing.T) {
	declared := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{
			Family:   intent.FamilyDatabase,
			Exposure: intent.ExposurePrivate,
		}}
	})

	result := policy.ContractCoverage(declared, model.Graph{})

	unknowns := unknownsFor(result, policy.CheckContractFamilyAbsent)
	if len(unknowns) != 1 {
		t.Fatalf("got %d unknowns, want 1: %+v", len(unknowns), unknowns)
	}
	if !unknowns[0].Required {
		t.Error("an unexercised declaration did not prevent a pass")
	}
	reason := unknowns[0].Reason
	if !strings.Contains(reason, "private exposure for database") {
		t.Errorf("the reason does not describe the declaration: %q", reason)
	}
	// The failure the network family's sentence was written to fix: an empty
	// exposure rendering as a leading space.
	if strings.Contains(reason, "  ") || strings.Contains(reason, " exposure for database") &&
		!strings.Contains(reason, "private exposure for database") {
		t.Errorf("the reason names an exposure nobody declared: %q", reason)
	}
}

// TestADeclarationForOneFamilyDoesNotCoverAnother keeps the three families'
// declarations apart in the coverage rule, which is where a shared accessor
// would show up as one family answering for another.
func TestADeclarationForOneFamilyDoesNotCoverAnother(t *testing.T) {
	declared := contract(func(c *intent.Contract) {
		c.Resources = []intent.ResourceIntent{{
			Family:   intent.FamilyDatabase,
			Exposure: intent.ExposurePrivate,
		}}
	})
	// A graph holding a database satisfies the database declaration.
	withDatabase := reachable(known(false), known(false), knownPort(5432))

	if unknowns := unknownsFor(policy.ContractCoverage(declared, withDatabase),
		policy.CheckContractFamilyAbsent); len(unknowns) != 0 {
		t.Errorf("a database declaration is unexercised by a plan holding a database: %+v", unknowns)
	}

	// A graph holding only a security group does not.
	withGroup := model.Graph{Resources: []model.NormalizedResource{
		group("aws_security_group.web", known(true)),
	}}
	if unknowns := unknownsFor(policy.ContractCoverage(declared, withGroup),
		policy.CheckContractFamilyAbsent); len(unknowns) != 1 {
		t.Errorf("a network resource exercised a database declaration: %+v", unknowns)
	}
}

// TestAGateProvenClosedIsReadAsClosed covers the one thing the rule reads from
// another resource's verdict, and the mutation that showed nothing held it.
//
// The fixture carries a shape no mapper produces: a gate whose PublicIngress is
// Known(false) and whose OpenToAnyAddress is non-empty. The model documents that
// pairing as impossible -- ranges are recorded only alongside a grant -- and all
// three mappers honour it. It is written here anyway, because this rule now
// depends on that invariant and the invariant is documented in one direction and
// enforced in none: deleting the guard that reads the gate's verdict changed no
// test, which means a gate proven closed could have started admitting traffic
// with a green suite.
func TestAGateProvenClosedIsReadAsClosed(t *testing.T) {
	postgres := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 5432, To: 5432},
		Sources:  []model.Provenance{provenance()},
	}
	// Known(false) beside a range, which is the pairing the model forbids.
	closed := group("aws_security_group.db", known(false), postgres)

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432), closed))

	if len(result.Findings) != 0 {
		t.Fatalf("a gate the network family proved closed admitted traffic: %d findings",
			len(result.Findings))
	}
	// And it settles the conjunction rather than leaving it open, because the
	// gate did answer.
	for _, unknown := range result.Unknowns {
		if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable {
			t.Errorf("a gate that answered left the question open: %q", unknown.Reason)
		}
	}
}

// TestAPortOfZeroIsNotAPort covers a value the rule must not compare against.
//
// Zero is what a failed lookup returns, and `declared.DatabasePort` pairs it with
// a false second result so nothing reaches the rule with it today. The rule
// accepted it as a legitimate port anyway: a gate open on every usable port,
// 1 to 65535, does not contain zero, so the database read as unreachable in
// silence.
//
// The assertion is that the gate is not ruled out. An earlier version checked
// only that something was reported, and a separate fix -- disclosing a silence
// that rests on an inferred port -- then satisfied it for the wrong reason.
func TestAPortOfZeroIsNotAPort(t *testing.T) {
	everyUsablePort := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 1, To: 65535},
		Sources:  []model.Provenance{provenance()},
	}

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), model.Known(0, provenance()),
			group("aws_security_group.db", known(true), everyUsablePort)))

	if len(result.Findings) != 1 {
		t.Fatalf("%d findings: a port of zero ruled out a gate open on every usable port",
			len(result.Findings))
	}
	var said bool
	for _, unknown := range result.Unknowns {
		if unknown.CheckID == policy.CheckDatabasePortUndetermined {
			said = true
		}
	}
	if !said {
		t.Error("the answer rests on a port this build could not use and does not say so")
	}
}

// TestAWithdrawnDeterminationSaysThatIsWhatItIs covers the sentence, not just
// the unknown.
//
// Two different things produce an undetermined answer here and they need
// different fixes: a plan that stated nothing, and an answer this build reached
// and refused to use because it came from a source a verdict may not rest on.
// Reporting the second with the first's wording tells a reader to go and write
// something they have already written.
func TestAWithdrawnDeterminationSaysThatIsWhatItIs(t *testing.T) {
	graph := reachable(known(false), unknownBool(), knownPort(5432))
	graph.Resources[0].Database.Withdrawn = true

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

	var found bool
	for _, unknown := range result.Unknowns {
		if unknown.CheckID != policy.CheckDatabaseReachabilityDeterminable {
			continue
		}
		found = true
		if !strings.Contains(unknown.Reason, "withdrawn") {
			t.Errorf("a withdrawn determination is reported as a plan that stated nothing: %q",
				unknown.Reason)
		}
		if !unknown.Required {
			t.Error("a withdrawn determination does not bound the verdict")
		}
	}
	if !found {
		t.Fatal("a withdrawn determination is reported nowhere")
	}
}

// TestAnUnreadableGateIsNamedInTheEvidence covers the one thing a reader needs in
// order to act on this unknown.
//
// "Something admits every address and the plan does not say what" names the
// missing half. It does not name which security group was missing, and that
// address is the only thing a reader can go and look for -- the Evidence Bundle
// requires evidence locating the source data, not merely evidence that exists.
func TestAnUnreadableGateIsNamedInTheEvidence(t *testing.T) {
	graph := reachable(known(true), unknownBool(), knownPort(5432))
	graph.Resources[0].Database.GatedBy = []string{"aws_security_group.elsewhere"}

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

	var named bool
	for _, unknown := range result.Unknowns {
		if unknown.CheckID != policy.CheckDatabaseReachabilityDeterminable {
			continue
		}
		for _, ref := range unknown.Evidence {
			if ref.ResourceAddress == "aws_security_group.elsewhere" {
				named = true
			}
		}
	}
	if !named {
		t.Error("the gate the plan does not hold is not named, so a reader has nothing to look for")
	}
}

// TestAPortLessProtocolReachesNoPortWhateverThePortIs covers the half of that
// exclusion that was left in the wrong order.
//
// A protocol with no ports cannot reach a port. That is exact and it does not
// need the port: ICMP reaches nothing a database listens on whether this build
// knows the port or not. The unknown-port branch returned before the port-less
// filter, so a group admitting ICMP from everywhere in front of a database whose
// engine the table cannot name produced a BLOCK -- a claim that is untrue, on
// evidence that is an approximation, which is what a BLOCK may not rest on.
//
// The fix is an ordering: the protocol decides first, because it decides without
// the port.
func TestAPortLessProtocolReachesNoPortWhateverThePortIs(t *testing.T) {
	icmp := model.OpenRange{Protocol: model.ProtocolICMP, Sources: []model.Provenance{provenance()}}
	postgres := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 5432, To: 5432},
		Sources:  []model.Provenance{provenance()},
	}

	for name, port := range map[string]model.Fact[int]{
		"with the port known":        knownPort(5432),
		"with the port undetermined": unknownPort(),
	} {
		t.Run(name, func(t *testing.T) {
			result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
				reachable(known(true), unknownBool(), port,
					group("aws_security_group.pinged", known(true), icmp)))

			if len(result.Findings) != 0 {
				t.Fatalf("a rule admitting only ICMP produced %d findings: %q",
					len(result.Findings), result.Findings[0].Claim)
			}
		})
	}

	// And a readable port alongside it still reaches, or the ordering has turned
	// every mixed rule set into a silence. Asserted as "not silent" rather than
	// as a finding: this gate is open on one port and the database's port is
	// unknown, so the reachability is an approximation and the rule reports it as
	// a required unknown. What this test is about is the ordering -- that ICMP
	// first does not swallow the TCP range -- and silence is the failure it
	// guards against.
	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), unknownPort(),
			group("aws_security_group.both", known(true), icmp, postgres)))
	var reported bool
	for _, unknown := range result.Unknowns {
		if unknown.Required {
			reported = true
		}
	}
	if len(result.Findings) == 0 && !reported {
		t.Fatal("a TCP range beside ICMP reached nothing at all, so the ordering " +
			"has turned every mixed rule set into a silence")
	}
}

// TestTheInferredPortIsDisclosedOnlyWhenItDecided covers the other direction of
// the same disclosure.
//
// DATABASE_PORT_INFERRED says a silence rests on a documented default. When a
// gate is ruled out because its protocol carries no ports, the port decided
// nothing -- the exclusion is exact -- and saying otherwise is the inverse of the
// gap that identifier was added to close.
func TestTheInferredPortIsDisclosedOnlyWhenItDecided(t *testing.T) {
	icmp := model.OpenRange{Protocol: model.ProtocolICMP, Sources: []model.Provenance{provenance()}}
	https := model.OpenRange{
		Protocol: model.ProtocolTCP,
		Ports:    model.PortRange{From: 443, To: 443},
		Sources:  []model.Provenance{provenance()},
	}

	// Ruled out by the protocol: exact, so nothing to disclose.
	byProtocol := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432),
			group("aws_security_group.pinged", known(true), icmp)))
	for _, unknown := range byProtocol.Unknowns {
		if unknown.CheckID == policy.CheckDatabasePortInferred {
			t.Errorf("the port is reported as deciding what the protocol decided: %q", unknown.Reason)
		}
	}

	// Ruled out by the port: the silence rests on the engine table, and that is
	// the case the identifier exists for.
	byPort := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432),
			group("aws_security_group.web", known(true), https)))
	var said bool
	for _, unknown := range byPort.Unknowns {
		if unknown.CheckID == policy.CheckDatabasePortInferred {
			said = true
		}
	}
	if !said {
		t.Error("a silence resting on the engine table is not disclosed")
	}
}

// TestAGateWhoseOwnSetIsUnsettledLeavesTheQuestionOpen covers the one line that
// keeps the ordinary AWS shape from a false proof of privacy, and that no test
// held.
//
// A security group whose rules are separate resources has `PublicIngress`
// Unknown -- the network family's own asymmetry, and the common case on that
// cloud. `Get()` on an Unknown fact is false, so a guard that only asked whether
// the gate grants would skip it and let the conjunction settle as closed.
// Deleting `|| !gate.Network.PublicIngress.IsKnown()` changed no test.
func TestAGateWhoseOwnSetIsUnsettledLeavesTheQuestionOpen(t *testing.T) {
	unsettled := model.NormalizedResource{
		Address:     "aws_security_group.separate",
		Cloud:       model.CloudAWS,
		Family:      model.FamilyNetwork,
		Interpreted: true,
		Network: &model.NetworkCapabilities{
			// What the network family reports for a group whose rules it cannot
			// see in full: not a grant, and not a proof of closure either.
			PublicIngress: unknownBool(),
		},
	}

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432), unsettled))

	if len(result.Findings) != 0 {
		t.Fatalf("%d findings from a gate nobody has settled", len(result.Findings))
	}
	var required bool
	for _, unknown := range result.Unknowns {
		if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable {
			required = unknown.Required
		}
	}
	if !required {
		t.Fatal("a gate whose own rule set is unsettled was read as a proof that nothing is open")
	}
}

// TestADatabaseBeingDestroyedMakesNothingReachable covers a change that creates
// nothing, which this rule had no notion of.
//
// A destroy-only change has no `after`, so every attribute is absent and no
// configuration entry records it. On two clouds that produced a *required*
// UNKNOWN with two sentences that were untrue -- "the plan does not state whether
// it has an endpoint" about a database that is going away, and "written from
// something the plan cannot resolve" about something nothing writes. On the third
// it was silent by accident.
//
// The rule asserts what a change *permits*, and a change that removes a database
// permits nothing through it. That is the same reading the family's own claim
// already has: "the change makes a database reachable", not "this database is
// reachable".
func TestADatabaseBeingDestroyedMakesNothingReachable(t *testing.T) {
	graph := reachable(unknownBool(), unknownBool(), unknownPort())
	graph.Resources[0].Destructive = true
	graph.Resources[0].Removed = true

	result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

	if len(result.Findings) != 0 {
		t.Errorf("a database being destroyed produced %d findings", len(result.Findings))
	}
	for _, unknown := range result.Unknowns {
		if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable {
			t.Errorf("a database being destroyed is reported as undetermined: %q", unknown.Reason)
		}
	}
	// And it is still judged, so coverage does not report it as a resource no
	// rule looked at.
	if len(result.Evaluated) != 1 {
		t.Errorf("the rule judged %d resources, want 1", len(result.Evaluated))
	}

	// A replacement is not a removal: it creates the database again, and what it
	// creates is what the verdict is about.
	replaced := reachable(known(true), known(true), knownPort(5432))
	replaced.Resources[0].Destructive = true
	if result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), replaced); len(result.Findings) != 1 {
		t.Errorf("a database being replaced produced %d findings, want one", len(result.Findings))
	}
}

// TestAnUndeterminedPortChangesNothingWhereTheMapperAnsweredTheAdmission pins
// which half of the rule the port belongs to.
//
// The port exists to decide whether a gate open to every address reaches *this*
// database, and only the gate resolution asks it. A mapper that answers the
// admission from inside the subject -- GCP's authorized networks, Azure's
// firewall rules -- names no gate, and an authorized network has no port for the
// port to be compared against.
//
// So an undetermined port must not widen or narrow anything here, and the
// approximations must stay silent. The mapper may still disclose that it could
// not name the port; what it may not do is say the verdict rests on it.
func TestAnUndeterminedPortChangesNothingWhereTheMapperAnsweredTheAdmission(t *testing.T) {
	cases := map[string]struct {
		admits  model.Fact[bool]
		finding bool
	}{
		"a mapper that proved every address admitted": {known(true), true},
		"a mapper that proved the allow list closed":  {known(false), false},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			// No gate: the admission came from the subject itself.
			graph := reachable(known(true), want.admits, unknownPort())
			result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

			if got := len(result.Findings) > 0; got != want.finding {
				t.Fatalf("finding = %v, want %v: the port is not part of this half "+
					"of the question", got, want.finding)
			}
			for _, unknown := range result.Unknowns {
				switch unknown.CheckID {
				case policy.CheckDatabasePortUndetermined, policy.CheckDatabasePortInferred:
					t.Fatalf("raised %s where no gate was consulted, so the verdict "+
						"is reported as resting on a port nothing compared",
						unknown.CheckID)
				case policy.CheckDatabaseReachabilityDeterminable:
					t.Fatalf("raised %s where both halves are known",
						unknown.CheckID)
				}
			}
		})
	}
}

// TestAGateWhoseRangeSetIsPartialCannotProveItDoesNotReach is the other half of
// model.NetworkCapabilities.RangesPartial, and the reason the field exists.
//
// A gate open to every address on 443, in front of a Postgres instance, reaches
// nothing -- that silence is a product decision this milestone took deliberately
// and the fixture `shared_group` pins. It holds only while the range set is the
// whole set. When one rule contributed no range because its ports could not be
// read, "443 is the only range" is not a fact about the group; it is a fact about
// what was readable. The unread rule is exactly the one that might hold 5432.
//
// Measured before this: PASS, exit 0, on a real plan of a publicly accessible
// Postgres instance behind a group with one such rule.
func TestAGateWhoseRangeSetIsPartialCannotProveItDoesNotReach(t *testing.T) {
	gateOn := func(port int, partial bool) model.NormalizedResource {
		gate := group("aws_security_group.db", known(true), model.OpenRange{
			Protocol: model.ProtocolTCP,
			Ports:    model.PortRange{From: port, To: port},
		})
		gate.Network.RangesPartial = partial
		return gate
	}

	cases := map[string]struct {
		partial bool
		settled bool
	}{
		"the whole set was read":        {false, true},
		"one rule contributed no range": {true, false},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			// 443 open, the database on 5432: the gate does not reach it, if the
			// set is complete.
			graph := reachable(known(true), unknownBool(), knownPort(5432), gateOn(443, want.partial))
			result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

			var open bool
			for _, unknown := range result.Unknowns {
				if unknown.CheckID == policy.CheckDatabaseReachabilityDeterminable && unknown.Required {
					open = true
				}
			}
			if want.settled && open {
				t.Fatal("a complete set that does not hold the port settles the " +
					"question, and that silence is the milestone's own decision")
			}
			if !want.settled && !open {
				t.Fatal("the port was absent from a set that is not the whole set, " +
					"and the rule read that absence as proof the gate does not reach")
			}
			if len(result.Findings) > 0 {
				t.Fatalf("raised a finding on a gate that holds no database port: %v",
					result.Findings[0].RuleID)
			}
		})
	}
}

// TestTheDatabaseRuleRunsInTheEngine keeps the rule wired in, which the network
// family has had since milestone 08 and this one did not.
//
// Every test in this file and in the cross-cloud one calls DatabaseExposure
// directly. Measured: deleting the rule from Evaluate's list left the whole suite
// green and turned a real plan's BLOCK into UNKNOWN with the finding gone. A rule
// nobody calls is a rule whose tests pass and whose verdict never reaches a
// reader.
//
// It also asserts the other end of the same wire: a bound the mapper attached to
// its capabilities has to arrive in the bundle. Replacing that one append with a
// discard was green too, and it deleted every cloud-specific disclosure from
// every bundle -- including Azure's "closure is never provable here", which is
// the only thing telling a reader that a clean Azure verdict is not a proof.
func TestTheDatabaseRuleRunsInTheEngine(t *testing.T) {
	graph := reachable(known(true), known(true), knownPort(5432))
	graph.Resources[0].Database.Unresolved = []model.MissingControl{{
		CheckID: "AWS_DATABASE_ALLOW_LIST_MAY_BE_PARTIAL",
		Reason:  "a bound the mapper attached, which a reader has to be given",
		Cloud:   model.CloudAWS,
	}}

	bundle := policy.Evaluate(declaringExposure(intent.ExposurePrivate), graph,
		policy.Subject{PlanFormatVersion: "1.2", PlanDigest: "sha256:" + strings.Repeat("0", 64)})

	if bundle.Decision != evidence.DecisionBlock {
		t.Fatalf("decision = %q, want BLOCK", bundle.Decision)
	}
	var judged bool
	for _, finding := range bundle.Findings {
		if finding.RuleID == policy.RuleDatabasePublicReachable {
			judged = true
		}
	}
	if !judged {
		t.Fatalf("the engine produced no database finding: %+v", bundle.Findings)
	}
	var bounded bool
	for _, unknown := range bundle.Unknowns {
		if unknown.CheckID == "AWS_DATABASE_ALLOW_LIST_MAY_BE_PARTIAL" {
			bounded = true
		}
	}
	if !bounded {
		t.Fatal("the mapper's bound never reached the bundle, so a reader is not " +
			"told how far the evidence goes")
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("the bundle does not satisfy its own contract: %v", err)
	}
}

// TestABlockNeverRestsOnAPortNobodyKnows holds a rule CLAUDE.md states without
// exception: a BLOCK decision must be supported by deterministic evidence, and
// where the evidence is insufficient the answer is UNKNOWN.
//
// The milestone decided that an undetermined port should over-report rather than
// go silent, and that decision stands -- the question is what the over-report is
// called. It was a BLOCK whose claim read "the change makes a database reachable
// from any address" and whose observed fact read `state: KNOWN, value: true`,
// beside a non-required unknown admitting the answer is wider than reality. The
// rule's own comment says "a BLOCK resting on it is a BLOCK whose claim is wider
// than the evidence".
//
// So an approximation is a required UNKNOWN: it still stops a human, which is the
// safe direction the milestone wanted, and it does not assert a fact the build
// knows it cannot prove.
//
// The exception is a gate that admits every port. Then the database's port does
// not matter -- whatever it listens on is admitted -- so the reachability is
// determined even though the port is not, and the finding is a finding.
func TestABlockNeverRestsOnAPortNobodyKnows(t *testing.T) {
	gate := func(ports model.PortRange) model.NormalizedResource {
		return group("aws_security_group.db", known(true),
			model.OpenRange{Protocol: model.ProtocolTCP, Ports: ports})
	}

	cases := map[string]struct {
		ports   model.PortRange
		finding bool
		why     string
	}{
		"a gate open on one port": {model.PortRange{From: 443, To: 443}, false,
			"whether 443 reaches the database depends on a port nobody stated"},
		"a gate open on every port": {model.EveryPort(), true,
			"every port is admitted, so what the database listens on cannot matter"},
		// The boundary the exception is written at: every *usable* port, which
		// is what a rule set written `from_port = 1` admits. Zero is not a port
		// anything listens on, so requiring EveryPort's 0 would have made the
		// most open rule set there is read as an approximation.
		"a gate open on every usable port": {model.PortRange{From: 1, To: 65535}, true,
			"1 through 65535 is everything a database could be on"},
		// And the exception is not "the range starts at 1". A gate admitting
		// only port 1 admits almost nothing, and a database on 5432 may or may
		// not be behind it.
		"a gate open on port one alone": {model.PortRange{From: 1, To: 1}, false,
			"admitting port 1 says nothing about a database whose port is unknown"},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			graph := reachable(known(true), unknownBool(), unknownPort(), gate(want.ports))
			result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

			var raised bool
			for _, finding := range result.Findings {
				if finding.RuleID == policy.RuleDatabasePublicReachable {
					raised = true
				}
			}
			if raised != want.finding {
				t.Fatalf("finding = %v, want %v: %s", raised, want.finding, want.why)
			}

			var stopped bool
			for _, unknown := range result.Unknowns {
				if unknown.Required {
					stopped = true
				}
			}
			if !want.finding && !stopped {
				t.Fatal("no finding and no required unknown, so an approximation " +
					"that could be a reachable database reads as a clean verdict")
			}
		})
	}
}

// TestTheInferredPortDisclosureIsNotMadeAboutAStatedPort keeps the one
// disclosure guarding the permissive direction from firing on every silence.
//
// DATABASE_PORT_INFERRED tells a reader that a PASS rests on a documented
// default: the gate is open to every address, the database's port is not in it,
// and the port came from a table rather than from the plan. Its own reason says
// "the plan does not state the port".
//
// It was raised on `Port.IsKnown()` alone, with no test of where the port came
// from -- while the AWS mapper reads a stated `port` in preference to the table.
// So a Postgres instance deliberately moved to 5433, behind a group open on 5432,
// got the disclosure, which said the opposite of the fact and cited `port` as its
// own evidence while denying the plan states it. Worse, a reader could no longer
// tell "this silence rests on a table" from "this silence rests on the plan",
// which is the whole purpose of the thing.
func TestTheInferredPortDisclosureIsNotMadeAboutAStatedPort(t *testing.T) {
	cases := map[string]struct {
		inferred  bool
		disclosed bool
	}{
		"a port the engine table named": {true, true},
		"a port the plan stated":        {false, false},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			// Open to every address on 5432, database on 5433: ruled out by the
			// port, and whether that is worth disclosing depends on where the
			// port came from.
			graph := reachable(known(true), unknownBool(), knownPort(5433),
				group("aws_security_group.db", known(true), model.OpenRange{
					Protocol: model.ProtocolTCP,
					Ports:    model.PortRange{From: 5432, To: 5432},
				}))
			graph.Resources[0].Database.PortInferred = want.inferred

			result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), graph)

			if len(result.Findings) != 0 {
				t.Fatalf("%d findings: 5432 does not reach a database on 5433",
					len(result.Findings))
			}
			var disclosed bool
			for _, unknown := range result.Unknowns {
				if unknown.CheckID == policy.CheckDatabasePortInferred {
					disclosed = true
				}
			}
			if disclosed != want.disclosed {
				t.Fatalf("disclosed = %v, want %v: the disclosure is about a port "+
					"the plan does not state", disclosed, want.disclosed)
			}
		})
	}
}
