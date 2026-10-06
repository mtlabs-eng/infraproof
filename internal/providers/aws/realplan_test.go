package aws_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// TestTheMapperAgreesWithARealPlan is the authority this milestone was missing
// for AWS, and it exists because hand-authoring fixtures from provider
// documentation produced shapes Terraform does not emit.
//
// `ingress` is Optional and Computed. Every hand-written fixture here spells an
// absent inline set as `"ingress": []`; a real create plan omits the key from
// `after` and marks the whole attribute unknown in `after_unknown`. The docs even
// claim the blocks are "not computed attributes", which is why reading them
// instead of the schema failed.
//
// real-groups.json is genuine `terraform show -json` output: Terraform 1.14.0,
// hashicorp/aws v6, `terraform plan` only -- never applied, no cloud contacted,
// `skip_*` flags and placeholder strings for the provider. The two placeholder
// credential arguments were deleted from the provider block afterwards; nothing
// else was edited, and no resource data was touched.
//
// The expectations are written from what AWS does, not from what this mapper
// says.
func TestTheMapperAgreesWithARealPlan(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		grants bool
		opens  string
		why    string
	}{
		// No inline rules written and no standalone rule in the plan, so the
		// set is not here to be read. The hand-written fixture for this used
		// `"ingress": []`, which is not what the plan says.
		"norules": {model.FactUnknown, false, "",
			"a group whose rules are nowhere in the plan cannot be shown closed"},
		// Inline rules and a standalone rule on one group. The docs say not to
		// do this; the provider accepts it without a warning, which is what
		// makes the inline set no proof of completeness. The standalone rule
		// still proves the grant.
		"mixed": {model.FactKnown, true, "tcp/22",
			"a grant is provable from part of a rule set"},
		// A rule whose only source is a managed prefix list. This build cannot
		// read the list, and it may contain 0.0.0.0/0.
		"prefixlist": {model.FactUnknown, false, "",
			"a prefix list this build cannot read may contain every address"},
		"ipv6": {model.FactKnown, true, "tcp/443",
			"::/0 is every address, and a standalone rule carries it in cidr_ipv6"},
		// The provider does not normalize ip_protocol, so a real plan carries
		// the IANA number through verbatim.
		"protonum": {model.FactKnown, true, "tcp/22",
			"protocol 6 is TCP by IANA assignment"},
		"everyproto": {model.FactKnown, true, "every/0-65535",
			"ip_protocol -1 is every protocol and every port"},
		// Two spellings the mapper read and no fixture carried, which left the
		// branches for both deletable.
		"protoall": {model.FactKnown, true, "every/0-65535",
			`ip_protocol "all" is not normalized by the provider and means every protocol`},
		"icmpv6": {model.FactKnown, true, "icmp",
			"the provider normalizes protocol 58 to icmpv6, which carries no ports"},
		"splitsource": {model.FactKnown, true, "tcp/22",
			"a source written as two halves of IPv4 is every address"},
		// Inline rules written, none of them reaching any address. This is the
		// only shape that can be shown closed, and even here the proof is
		// bounded: the provider does not refuse a standalone rule elsewhere.
		"closed": {model.FactKnown, false, "",
			"an inline set none of whose rules reaches any address opens nothing"},
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			found, ok := normalize(t, "real-groups").At("aws_security_group." + name)
			if !ok {
				t.Fatalf("the real plan holds no group at aws_security_group.%s", name)
			}
			if found.Network == nil {
				t.Fatal("the mapper produced no network capabilities")
			}
			if got := found.Network.PublicIngress.State; got != want.state {
				t.Fatalf("state = %q, want %q: %s", got, want.state, want.why)
			}
			if want.state == model.FactKnown && found.Network.PublicIngress.Get() != want.grants {
				t.Fatalf("grants = %v, want %v: %s",
					found.Network.PublicIngress.Get(), want.grants, want.why)
			}
			if got := rendered(found.Network.OpenToAnyAddress); got != want.opens {
				t.Fatalf("opens %q, want %q: %s", got, want.opens, want.why)
			}
		})
	}
}

// TestAGroupThatCannotBeSettledSaysSoOnARealPlan covers what the review found
// behind the fixture shape: reshaping `"ingress": []` to the real unknown left
// the verdict right and made the explanation vanish, so the two check
// identifiers that are the whole reason a reader gets for the unknown never
// fired on real input.
func TestAGroupThatCannotBeSettledSaysSoOnARealPlan(t *testing.T) {
	for _, name := range []string{"norules", "prefixlist"} {
		t.Run(name, func(t *testing.T) {
			found, ok := normalize(t, "real-groups").At("aws_security_group." + name)
			if !ok {
				t.Fatalf("the real plan holds no group at aws_security_group.%s", name)
			}
			capabilities := found.Network

			if len(capabilities.Unresolved) == 0 {
				t.Fatal("an unsettled rule set reports no missing control")
			}
			for _, control := range capabilities.Unresolved {
				if control.CheckID == "" || control.Reason == "" {
					t.Fatalf("a missing control says nothing: %+v", control)
				}
				if strings.Contains(control.Reason, "aws_security_group") {
					t.Fatalf("the reason interpolates a plan value: %q", control.Reason)
				}
			}
		})
	}
}
