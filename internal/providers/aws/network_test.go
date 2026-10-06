package aws_test

import (
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// securityGroup returns the normalized security group of a fixture.
func securityGroup(t *testing.T, fixture string) model.NormalizedResource {
	t.Helper()
	found, ok := normalize(t, fixture).At("aws_security_group.web")
	if !ok {
		t.Fatalf("fixture %s has no security group at aws_security_group.web", fixture)
	}
	return found
}

// rendered writes the open ranges the way a reader sees them, so a table can
// state an expectation in one string.
func rendered(ranges []model.OpenRange) string {
	texts := make([]string, 0, len(ranges))
	for _, open := range ranges {
		if !open.Protocol.HasPorts() {
			texts = append(texts, string(open.Protocol))
			continue
		}
		if open.Ports.From == open.Ports.To {
			texts = append(texts, string(open.Protocol)+"/"+itoa(open.Ports.From))
			continue
		}
		texts = append(texts, string(open.Protocol)+"/"+itoa(open.Ports.From)+"-"+itoa(open.Ports.To))
	}
	return strings.Join(texts, ", ")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits
}

// TestIngressDetermination is the mapper's whole job for this family.
//
// Known(true) means the change permits ingress from any address. Known(false)
// means the plan holds the whole rule set and the set permits none. Unknown means
// the plan does not hold the set in full -- which, for a group whose rules are
// separate resources, is the common case rather than an edge one.
//
// AWS rules are an allow-only union with no priority and no deny, so a grant in
// the plan is a grant: there is nothing in the set that could override it. That is
// what makes this the simple cloud of the three, and it is the baseline the other
// two are compared against.
func TestIngressDetermination(t *testing.T) {
	cases := map[string]struct {
		state  model.FactState
		grants bool
		opens  string
	}{
		"sg-public-inline":       {model.FactKnown, true, "tcp/22"},
		"sg-closed-inline":       {model.FactKnown, false, ""},
		"sg-public-ipv6":         {model.FactKnown, true, "tcp/443"},
		"sg-every-protocol":      {model.FactKnown, true, "every/0-65535"},
		"sg-icmp":                {model.FactKnown, true, "icmp"},
		"sg-public-rule":         {model.FactKnown, true, "tcp/22"},
		"sg-rule-every-protocol": {model.FactKnown, true, "every/0-65535"},
		"sg-unreadable-port":     {model.FactUnknown, false, ""},
		// An address the plan has not determined could be 0.0.0.0/0, and
		// reading it as narrower would be reading an unknown as a reassurance.
		"sg-unreadable-address": {model.FactUnknown, false, ""},
		// And one address in a list the plan did determine: the list is
		// readable and one of its entries is not, which is the same unknown
		// one level in.
		"sg-unreadable-element": {model.FactUnknown, false, ""},
		"sg-partial-rule":       {model.FactUnknown, false, ""},
		"sg-no-rules":           {model.FactUnknown, false, ""},
	}

	for fixture, want := range cases {
		t.Run(fixture, func(t *testing.T) {
			group := securityGroup(t, fixture)
			if group.Family != model.FamilyNetwork {
				t.Fatalf("family = %q, want %q", group.Family, model.FamilyNetwork)
			}
			if group.Network == nil {
				t.Fatal("the mapper produced no network capabilities")
			}

			if got := group.Network.PublicIngress.State; got != want.state {
				t.Fatalf("state = %q, want %q", got, want.state)
			}
			if want.state == model.FactKnown && group.Network.PublicIngress.Get() != want.grants {
				t.Fatalf("grants = %v, want %v", group.Network.PublicIngress.Get(), want.grants)
			}
			if got := rendered(group.Network.OpenToAnyAddress); got != want.opens {
				t.Fatalf("opens %q, want %q", got, want.opens)
			}
		})
	}
}

// TestEveryFactNamesTheAttributeItCameFrom is the milestone's criterion made
// mechanical. A finding that cannot say which provider attribute decided it is a
// finding a reader has to take on trust.
func TestEveryFactNamesTheAttributeItCameFrom(t *testing.T) {
	for _, fixture := range []string{"sg-public-inline", "sg-public-rule", "sg-closed-inline"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := securityGroup(t, fixture).Network

			if len(capabilities.PublicIngress.Sources) == 0 {
				t.Fatal("the deciding fact cites nothing")
			}
			for _, source := range capabilities.PublicIngress.Sources {
				if source.ResourceAddress == "" || source.AttributePath == "" {
					t.Fatalf("a source names no attribute: %+v", source)
				}
				if source.Cloud != model.CloudAWS {
					t.Fatalf("a source names cloud %q", source.Cloud)
				}
			}
			for _, open := range capabilities.OpenToAnyAddress {
				if len(open.Sources) == 0 {
					t.Fatalf("the range %v cites nothing", open)
				}
			}
		})
	}
}

// TestTheRuleResourceDefersToItsGroup covers the control resource. Its meaning
// belongs to the set it is part of, and the deferral is recorded so that
// "it was judged through its group" is a claim coverage can check rather than
// believe.
func TestTheRuleResourceDefersToItsGroup(t *testing.T) {
	graph := normalize(t, "sg-public-rule")

	rule, ok := graph.At("aws_vpc_security_group_ingress_rule.web")
	if !ok {
		t.Fatal("the rule resource is not in the graph")
	}
	if !rule.Interpreted {
		t.Error("the rule resource was not recognized, so it reads as a resource nothing understood")
	}
	if rule.Family != model.FamilyNetwork {
		t.Errorf("family = %q, want %q; a storage family here would report it as the wrong thing entirely",
			rule.Family, model.FamilyNetwork)
	}
	if rule.Network != nil {
		t.Error("the rule resource carries capabilities of its own")
	}
	if len(rule.DefersTo) != 1 || rule.DefersTo[0] != "aws_security_group.web" {
		t.Errorf("defers to %v, want the group", rule.DefersTo)
	}
}

// TestAnIncompleteSetSaysWhyItCannotBeSettled covers what a reader does next. An
// unknown with no reason is a dead end; this one names the thing that would
// settle it.
func TestAnIncompleteSetSaysWhyItCannotBeSettled(t *testing.T) {
	for _, fixture := range []string{"sg-no-rules", "sg-partial-rule"} {
		t.Run(fixture, func(t *testing.T) {
			capabilities := securityGroup(t, fixture).Network

			if len(capabilities.Unresolved) == 0 {
				t.Fatal("an unsettled rule set reports no missing control")
			}
			for _, control := range capabilities.Unresolved {
				if control.CheckID == "" || control.Reason == "" {
					t.Fatalf("a missing control says nothing: %+v", control)
				}
				if strings.Contains(control.Reason, "aws_security_group.web") {
					t.Fatalf("the reason interpolates a plan value: %q", control.Reason)
				}
			}
		})
	}
}

// TestObjectStorageIsUntouched keeps the two families apart in the one mapper
// that now claims both. A bucket must still be a bucket.
func TestObjectStorageIsUntouched(t *testing.T) {
	assets := bucket(t, "public-acl")

	if assets.Family != model.FamilyObjectStorage {
		t.Fatalf("family = %q, want %q", assets.Family, model.FamilyObjectStorage)
	}
	if assets.Network != nil {
		t.Fatal("a bucket carries network capabilities")
	}
}
