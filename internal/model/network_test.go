package model_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// TestOnlySomeProtocolsHavePorts covers the distinction the rule turns on. A port
// list can neither permit nor forbid ICMP, because ICMP has no ports -- so a rule
// that opens it to any address is something the contract cannot describe, and the
// rule has to know which protocols those are.
func TestOnlySomeProtocolsHavePorts(t *testing.T) {
	withPorts := map[model.Protocol]bool{
		model.ProtocolTCP:          true,
		model.ProtocolUDP:          true,
		model.ProtocolEvery:        true,
		model.ProtocolICMP:         false,
		model.ProtocolUnrecognized: false,
	}
	for protocol, want := range withPorts {
		t.Run(string(protocol), func(t *testing.T) {
			if got := protocol.HasPorts(); got != want {
				t.Fatalf("%s.HasPorts() = %v, want %v", protocol, got, want)
			}
		})
	}
}

// TestUnrecognizedIsTheZeroProtocol keeps the safe answer the default, for the
// reason declared.ReachUnreadable is the zero Reach: a protocol nobody set must
// not read as one that was read and understood.
func TestUnrecognizedIsTheZeroProtocol(t *testing.T) {
	var unset model.Protocol

	if unset != model.ProtocolUnrecognized {
		t.Fatalf("the zero Protocol is %q, want ProtocolUnrecognized", unset)
	}
	if unset.HasPorts() {
		t.Fatal("a protocol nobody set claims to have ports")
	}
}

// TestAPortRangeContainsAnother is the comparison the contract's declaration is
// made with: a range the change opens is permitted when a declared range covers
// all of it. Partial overlap is not permission.
func TestAPortRangeContainsAnother(t *testing.T) {
	cases := map[string]struct {
		outer, inner model.PortRange
		want         bool
	}{
		"the same range":        {model.PortRange{From: 443, To: 443}, model.PortRange{From: 443, To: 443}, true},
		"a range inside":        {model.PortRange{From: 8000, To: 8100}, model.PortRange{From: 8080, To: 8090}, true},
		"touching the low end":  {model.PortRange{From: 8000, To: 8100}, model.PortRange{From: 8000, To: 8000}, true},
		"touching the high end": {model.PortRange{From: 8000, To: 8100}, model.PortRange{From: 8100, To: 8100}, true},
		"overlapping below":     {model.PortRange{From: 8000, To: 8100}, model.PortRange{From: 7999, To: 8050}, false},
		"overlapping above":     {model.PortRange{From: 8000, To: 8100}, model.PortRange{From: 8050, To: 8101}, false},
		"disjoint":              {model.PortRange{From: 443, To: 443}, model.PortRange{From: 22, To: 22}, false},
		"every port inside one": {model.PortRange{From: 0, To: 65535}, model.PortRange{From: 22, To: 22}, true},
		"one inside every port": {model.PortRange{From: 22, To: 22}, model.PortRange{From: 0, To: 65535}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := c.outer.Contains(c.inner); got != c.want {
				t.Fatalf("%v.Contains(%v) = %v, want %v", c.outer, c.inner, got, c.want)
			}
		})
	}
}

// TestEveryPortIsARange keeps "all ports" a range like any other, so that nothing
// downstream has a second spelling for it to get wrong.
func TestEveryPortIsARange(t *testing.T) {
	every := model.EveryPort()

	if every.From != 0 || every.To != 65535 {
		t.Fatalf("EveryPort() = %v, want 0-65535", every)
	}
	if !every.Contains(model.PortRange{From: 22, To: 22}) {
		t.Fatal("every port does not contain port 22")
	}
}

// TestANetworkResourceCarriesItsCapabilities covers the shape the rule reads, and
// that an uninterpreted resource carries nil rather than an empty capability --
// nil means "not interpreted", never "nothing to worry about".
func TestANetworkResourceCarriesItsCapabilities(t *testing.T) {
	resource := model.NormalizedResource{
		Address: "aws_security_group.web",
		Cloud:   model.CloudAWS,
		Family:  model.FamilyNetwork,
		Network: &model.NetworkCapabilities{
			PublicIngress: model.Known(true, model.Provenance{
				ResourceAddress: "aws_security_group.web",
				AttributePath:   "ingress[0].cidr_blocks[0]",
				Cloud:           model.CloudAWS,
			}),
			OpenToAnyAddress: []model.OpenRange{{
				Protocol: model.ProtocolTCP,
				Ports:    model.PortRange{From: 22, To: 22},
			}},
		},
	}

	if resource.Network == nil || !resource.Network.PublicIngress.Get() {
		t.Fatal("the capability did not survive")
	}
	if len(resource.Network.PublicIngress.Sources) != 1 {
		t.Fatal("the fact carries no provenance, so a finding could not say where it came from")
	}
	opaque := model.NormalizedResource{Address: "something_else.x"}
	if opaque.Network != nil {
		t.Fatal("an uninterpreted resource carries a capability")
	}
}
