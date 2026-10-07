// Reproductions of the defects an independent review of this layer found, kept
// as its tests rather than rewritten as mine.
//
// Each one failed when it was written and passes now. They are here because the
// review reached shapes the author's own tests did not -- a mapper answering
// "closed" while naming a gate that admits everything, a withdrawal swallowed by
// a two-fact switch, an approximation whose flag depended on the order the
// provider wrote its rules in -- and because a defect that was once live is worth
// a test that says so in the words of the person who found it.
package policy_test

// Reproductions for the milestone 09 review. Drop this file into
// internal/policy/ and run:
//
//   go test ./internal/policy/ -run TestR0 -v
//
// Every one of these is a Go test rather than a CLI run because this layer has
// no mapper yet: no plan can produce a model.FamilyDatabase resource.

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
)

func rngR(p model.Protocol, from, to int) model.OpenRange {
	return model.OpenRange{Protocol: p, Ports: model.PortRange{From: from, To: to},
		Sources: []model.Provenance{provenance()}}
}

// R0-1 PERMISSIVE. A wide-open gate is never read when the mapper also answered
// AdmitsAnyAddress. Total silence: no finding, no unknown, PASS.
func TestR01InlineFalseHidesAnOpenGate(t *testing.T) {
	r := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), known(false), knownPort(5432),
			group("aws_security_group.db", known(true), rngR(model.ProtocolEvery, 0, 65535))))
	if len(r.Findings) == 0 && len(r.Unknowns) == 0 {
		t.Fatalf("a database with a public endpoint and a group open to every address on every " +
			"port produced no finding and no unknown")
	}
}

// R0-2 PERMISSIVE. Withdrawn is checked after both silence arms, so a withdrawn
// determination beside a known-false half is never reported at all.
func TestR02WithdrawnIsSwallowed(t *testing.T) {
	g := reachable(known(false), unknownBool(), knownPort(5432))
	g.Resources[0].Database.Withdrawn = true
	r := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), g)
	if len(r.Unknowns) == 0 {
		t.Error("a withdrawn determination beside PublicEndpoint=Known(false) is reported nowhere")
	}

	g2 := reachable(known(true), known(true), knownPort(5432))
	g2.Resources[0].Database.Withdrawn = true
	r2 := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate), g2)
	for _, u := range r2.Unknowns {
		if u.CheckID == policy.CheckDatabaseReachabilityDeterminable {
			return
		}
	}
	t.Error("a withdrawn determination beside two known facts produced a BLOCK and no unknown")
}

// R0-3 PERMISSIVE. The engine-derived port is load-bearing for the silence and
// nothing records it. The milestone names this as the choice most likely to be
// wrong, and the build says nothing when it is exercised.
func TestR03InferredPortSilenceIsUndisclosed(t *testing.T) {
	r := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432),
			group("aws_security_group.web", known(true), rngR(model.ProtocolTCP, 443, 443))))
	if len(r.Findings) == 0 && len(r.Unknowns) == 0 {
		t.Fatal("a PASS resting on a port this build inferred from a table records nothing about it")
	}
}

// R0-4 FALSE BLOCK + FALSE REASON. ICMP open to the world in front of a Postgres
// instance whose port IS known blocks, with a claim that is untrue and an unknown
// whose stated reason is untrue.
func TestR04ICMPBlocksWithAFalseReason(t *testing.T) {
	r := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432),
			group("aws_security_group.ping", known(true), rngR(model.ProtocolICMP, 0, 0))))
	for _, u := range r.Unknowns {
		if u.CheckID == policy.CheckDatabasePortUndetermined &&
			strings.Contains(u.Reason, "its engine does not name one") {
			t.Errorf("the port is Known(5432) and the unknown says the engine names none:\n  %s",
				u.Reason)
		}
	}
	for _, f := range r.Findings {
		t.Logf("disposition=%s claim=%s", f.Disposition, f.Claim)
	}
}

// R0-5 NON-DETERMINISM. The same rule set in a different order produces a
// different bundle, and the approximation is announced when nothing was
// approximated.
func TestR05ApproximationIsOrderDependent(t *testing.T) {
	icmp := rngR(model.ProtocolICMP, 0, 0)
	pg := rngR(model.ProtocolTCP, 5432, 5432)
	a := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432),
			group("aws_security_group.db", known(true), icmp, pg)))
	b := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), knownPort(5432),
			group("aws_security_group.db", known(true), pg, icmp)))
	if len(a.Unknowns) != len(b.Unknowns) {
		t.Fatalf("icmp-then-5432 gives %d unknowns, 5432-then-icmp gives %d, for the same set",
			len(a.Unknowns), len(b.Unknowns))
	}
}

// R0-6 OVER-STRICT, and inconsistent with the principle storage.go states.
func TestR06RequiredDisagreesWithStorage(t *testing.T) {
	bare := func(family string, e intent.Exposure) intent.Contract {
		return contract(func(c *intent.Contract) {
			c.Resources = []intent.ResourceIntent{{Family: family, Exposure: e}}
		})
	}
	for _, e := range []intent.Exposure{intent.ExposurePublic, intent.ExposureUnspecified} {
		db := policy.DatabaseExposure(bare(intent.FamilyDatabase, e),
			reachable(unknownBool(), unknownBool(), knownPort(5432)))
		st := policy.StorageExposure(bare(intent.FamilyObjectStorage, e),
			model.Graph{Resources: []model.NormalizedResource{{
				Address: "aws_s3_bucket.b", Family: model.FamilyObjectStorage, Interpreted: true,
				ObjectStorage: &model.ObjectStorageCapabilities{PublicAccess: unknownBool()}}}})
		reqOf := func(r policy.Result, id string) bool {
			for _, u := range r.Unknowns {
				if u.CheckID == id {
					return u.Required
				}
			}
			return false
		}
		d := reqOf(db, policy.CheckDatabaseReachabilityDeterminable)
		s := reqOf(st, policy.CheckStoragePublicDeterminable)
		if d != s {
			t.Errorf("declared %q: database required=%v, object_storage required=%v", e, d, s)
		}
	}
}

// R0-7 LATENT. Known(0) as a port makes a group open on 1-65535 read as closed.
func TestR07PortZeroReadsAsClosed(t *testing.T) {
	r := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
		reachable(known(true), unknownBool(), model.Known(0, provenance()),
			group("aws_security_group.db", known(true), rngR(model.ProtocolTCP, 1, 65535))))
	if len(r.Findings) == 0 && len(r.Unknowns) == 0 {
		t.Fatal("Port=Known(0) against a group open on every usable port produced total silence")
	}
}
