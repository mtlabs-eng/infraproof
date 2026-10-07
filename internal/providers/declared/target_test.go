package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Correlating two resources through an attribute that names a third is the one
// thing a plan records and attribute values cannot answer, and it has a third
// state: the plan may name a resource without naming which instance of it.
//
// A mapper that collapsed the keys reported a deny on one network as applying to
// a firewall on another, and proved a grant closed with it. The storage path has
// had this discipline since milestone 04; this is the same rule where the second
// family needs it.
func TestWhatAnAttributeNamesIsEitherOneInstanceOrUndecidable(t *testing.T) {
	network := func(target string, keys ...string) terraformplan.ExpressionReference {
		return terraformplan.ExpressionReference{
			Attribute: "network", Target: target, TargetKeys: keys,
		}
	}
	repeated := func(address string) terraformplan.ResourceChange {
		return terraformplan.ResourceChange{
			Address: address, Type: "google_compute_network", DeclaredRepeated: true,
		}
	}
	single := func(address string) terraformplan.ResourceChange {
		return terraformplan.ResourceChange{Address: address, Type: "google_compute_network"}
	}

	cases := map[string]struct {
		references []terraformplan.ExpressionReference
		scope      []terraformplan.ResourceChange
		identity   string
		state      declared.Correlation
		why        string
	}{
		"one reference naming an instance": {
			references: []terraformplan.ExpressionReference{network("google_compute_network.vpc", "a")},
			scope:      []terraformplan.ResourceChange{repeated(`google_compute_network.vpc["a"]`)},
			identity:   `google_compute_network.vpc["a"]`,
			state:      declared.CorrelationNamed,
			why:        "the keys are what separate one instance from its sibling",
		},
		"two references to different instances are different identities": {
			references: []terraformplan.ExpressionReference{network("google_compute_network.vpc", "b")},
			scope:      []terraformplan.ResourceChange{repeated(`google_compute_network.vpc["b"]`)},
			identity:   `google_compute_network.vpc["b"]`,
			state:      declared.CorrelationNamed,
			why:        "and the sibling has to come out as a different identity",
		},
		"a reference to a resource declared once": {
			references: []terraformplan.ExpressionReference{network("google_compute_network.vpc")},
			scope:      []terraformplan.ResourceChange{single("google_compute_network.vpc")},
			identity:   "google_compute_network.vpc",
			state:      declared.CorrelationNamed,
			why:        "one instance and one declaration leaves nothing to choose between",
		},
		"a reference naming no instance of a repeated resource": {
			references: []terraformplan.ExpressionReference{network("google_compute_network.vpc")},
			scope: []terraformplan.ResourceChange{
				repeated("google_compute_network.vpc[0]"), repeated("google_compute_network.vpc[1]"),
			},
			state: declared.CorrelationUndecidable,
			why:   "count.index produces no key, so the reference cannot reach one instance",
		},
		"two references on one attribute": {
			references: []terraformplan.ExpressionReference{
				network("google_compute_network.a"), network("google_compute_network.b"),
			},
			scope: []terraformplan.ResourceChange{
				single("google_compute_network.a"), single("google_compute_network.b"),
			},
			state: declared.CorrelationUndecidable,
			why:   "a conditional names both and the plan does not say which it resolves to",
		},
		"no reference on that attribute": {
			references: []terraformplan.ExpressionReference{
				{Attribute: "project", Target: "google_project.main"},
			},
			scope: []terraformplan.ResourceChange{single("google_compute_network.vpc")},
			state: declared.CorrelationAbsent,
			why:   "the caller falls back to whatever the attribute's own value says",
		},
		"a reference to another type on that attribute": {
			references: []terraformplan.ExpressionReference{
				{Attribute: "network", Target: "google_compute_subnetwork.sub"},
			},
			scope: []terraformplan.ResourceChange{single("google_compute_network.vpc")},
			state: declared.CorrelationAbsent,
			why:   "only a reference to the type being correlated answers the question",
		},
		"a reference to a target the plan does not contain": {
			references: []terraformplan.ExpressionReference{network("google_compute_network.vpc")},
			scope:      nil,
			identity:   "google_compute_network.vpc",
			state:      declared.CorrelationNamed,
			why: "a network the plan does not change is not a network declared twice; " +
				"nothing says it is repeated, so the reference reaches it",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := terraformplan.ResourceChange{
				Address: "google_compute_firewall.web", References: c.references,
			}
			identity, state := declared.Target(change, "network", "google_compute_network", c.scope)

			if state != c.state {
				t.Fatalf("state = %v, want %v: %s", state, c.state, c.why)
			}
			if state == declared.CorrelationNamed && identity != c.identity {
				t.Fatalf("identity = %q, want %q: %s", identity, c.identity, c.why)
			}
		})
	}
}

// The zero value has to be the answer nobody may act on, the same way
// ReachUnreadable is: a correlation nobody managed to decide must not be
// mistaken for one decided and found absent, because absent is what lets a
// caller fall back to a value it can read.
func TestTheZeroCorrelationIsUndecidable(t *testing.T) {
	var state declared.Correlation

	if state != declared.CorrelationUndecidable {
		t.Fatalf("the zero value is %v", state)
	}
}

// A list-valued reference names several instances, and that is not an ambiguity.
//
// Target answers for an attribute holding one reference and calls two
// undecidable, which is right for a network or a cluster: a conditional naming
// both branches is a question the plan left open. It is wrong for
// `vpc_security_group_ids`, where naming three groups is three correlations and
// the database is gated by all of them.
//
// The distinction is the attribute's arity, which the caller knows and this
// cannot, so it is two functions rather than one with a flag.
func TestAListValuedAttributeNamesEveryInstanceItRefers(t *testing.T) {
	group := func(target string, keys ...string) terraformplan.ExpressionReference {
		return terraformplan.ExpressionReference{
			Attribute: "vpc_security_group_ids", Target: target, TargetKeys: keys,
		}
	}
	single := func(address string) terraformplan.ResourceChange {
		return terraformplan.ResourceChange{Address: address, Type: "aws_security_group"}
	}
	repeated := func(address string) terraformplan.ResourceChange {
		return terraformplan.ResourceChange{
			Address: address, Type: "aws_security_group", DeclaredRepeated: true,
		}
	}

	cases := map[string]struct {
		references []terraformplan.ExpressionReference
		scope      []terraformplan.ResourceChange
		identities []string
		state      declared.Correlation
		why        string
	}{
		"one group": {
			[]terraformplan.ExpressionReference{group("aws_security_group.db")},
			[]terraformplan.ResourceChange{single("aws_security_group.db")},
			[]string{"aws_security_group.db"}, declared.CorrelationNamed,
			"the ordinary case"},
		"three groups": {
			[]terraformplan.ExpressionReference{
				group("aws_security_group.a"), group("aws_security_group.b"), group("aws_security_group.c"),
			},
			[]terraformplan.ResourceChange{
				single("aws_security_group.a"), single("aws_security_group.b"), single("aws_security_group.c"),
			},
			[]string{"aws_security_group.a", "aws_security_group.b", "aws_security_group.c"},
			declared.CorrelationNamed,
			"a list naming three groups is three correlations, not an ambiguity"},
		"two instances of one repeated group": {
			[]terraformplan.ExpressionReference{
				group("aws_security_group.db", "a"), group("aws_security_group.db", "b"),
			},
			[]terraformplan.ResourceChange{
				repeated(`aws_security_group.db["a"]`), repeated(`aws_security_group.db["b"]`),
			},
			[]string{`aws_security_group.db["a"]`, `aws_security_group.db["b"]`},
			declared.CorrelationNamed,
			"the keys say which instances, and both are named"},
		"a reference naming no instance of a repeated group": {
			[]terraformplan.ExpressionReference{group("aws_security_group.db")},
			[]terraformplan.ResourceChange{
				repeated("aws_security_group.db[0]"), repeated("aws_security_group.db[1]"),
			},
			nil, declared.CorrelationUndecidable,
			"a splat over a repeated group reaches no one instance, so which gate applies is open"},
		"no reference on that attribute": {
			[]terraformplan.ExpressionReference{
				{Attribute: "db_subnet_group_name", Target: "aws_db_subnet_group.main"},
			},
			[]terraformplan.ResourceChange{single("aws_security_group.db")},
			nil, declared.CorrelationAbsent,
			"the caller falls back to whatever it does for an unnamed allow list"},
		"one decidable group beside one that is not": {
			[]terraformplan.ExpressionReference{
				group("aws_security_group.ok"), group("aws_security_group.db"),
			},
			[]terraformplan.ResourceChange{
				single("aws_security_group.ok"),
				repeated("aws_security_group.db[0]"), repeated("aws_security_group.db[1]"),
			},
			nil, declared.CorrelationUndecidable,
			"one gate nobody can place leaves the set open; a partial allow list is not an allow list"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := terraformplan.ResourceChange{
				Address: "aws_db_instance.main", References: c.references,
			}
			identities, state := declared.Targets(change, "vpc_security_group_ids",
				"aws_security_group", c.scope)

			if state != c.state {
				t.Fatalf("state = %v, want %v: %s", state, c.state, c.why)
			}
			if state != declared.CorrelationNamed {
				return
			}
			if len(identities) != len(c.identities) {
				t.Fatalf("named %v, want %v: %s", identities, c.identities, c.why)
			}
			for i := range identities {
				if identities[i] != c.identities[i] {
					t.Fatalf("named %v, want %v (sorted, so a plan's key order cannot change a bundle)",
						identities, c.identities)
				}
			}
		})
	}
}
