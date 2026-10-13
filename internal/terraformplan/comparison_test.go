package terraformplan

import (
	"reflect"
	"testing"
)

// Terraform records an attribute written as blocks with every attribute of the
// block, null where the author wrote nothing, and plans an attribute nobody
// wrote as an empty value: null, an empty list, an empty string, false. So
// nothing written matches only an empty value. A planned value that is not
// empty there came from somewhere other than the configuration -- under
// `lifecycle { ignore_changes }`, from state -- and the constant is
// contradicted. The same holds for an attribute a block written in block
// syntax does not write at all.
func TestNothingWrittenMatchesOnlyAnEmptyValue(t *testing.T) {
	const written = `{"ingress": {"constant_value": [{"cidr_blocks": ["10.0.0.0/8"], "extra": null}]}}`
	attributeCases := map[string]struct {
		extra string
		want  bool
	}{
		"null":                   {`null`, false},
		"absent":                 {``, false},
		"an empty list":          {`[]`, false},
		"an empty string":        {`""`, false},
		"false":                  {`false`, false},
		"an empty map":           {`{}`, false},
		"a list the state has":   {`["::/0"]`, true},
		"a string":               {`"x"`, true},
		"true":                   {`true`, true},
		"zero, which is a value": {`0`, true},
		"a map with a key":       {`{"a": "b"}`, true},
	}
	for name, c := range attributeCases {
		t.Run("written as null, planned "+name, func(t *testing.T) {
			after := `{"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]}`
			if c.extra != "" {
				after = `{"ingress": [{"cidr_blocks": ["10.0.0.0/8"], "extra": ` + c.extra + `}]}`
			}
			plan := expressionPlan(t, `{}`, written, after, `{}`, `{}`, `{}`)
			got, found := expressionAt(t, plan, "x_thing.t", "ingress")
			if !found || got.Evaluation != EvaluationConstant {
				t.Fatalf("ingress: %+v, found %v", got, found)
			}
			if got.Contradicted != c.want {
				t.Errorf("Contradicted = %v, want %v", got.Contradicted, c.want)
			}
		})
	}

	const allow = `{"allow": [{"protocol": {"constant_value": "tcp"}}]}`
	blockCases := map[string]struct {
		after string
		want  bool
	}{
		"ports planned empty":          {`{"allow": [{"protocol": "tcp", "ports": []}]}`, false},
		"ports planned null":           {`{"allow": [{"protocol": "tcp", "ports": null}]}`, false},
		"ports the state narrows":      {`{"allow": [{"protocol": "tcp", "ports": ["22"]}]}`, true},
		"a nested block planned empty": {`{"allow": [{"protocol": "tcp", "match": []}]}`, false},
		"a nested block the state has": {`{"allow": [{"protocol": "tcp", "match": [{"port": 22}]}]}`, true},
	}
	for name, c := range blockCases {
		t.Run("a block that does not write it, "+name, func(t *testing.T) {
			plan := expressionPlan(t, `{}`, allow, c.after, `{}`, `{}`, `{}`)
			got, found := blockAt(t, plan, "x_thing.t", "allow")
			if !found || got.Evaluation != EvaluationConstant {
				t.Fatalf("allow: %+v, found %v", got, found)
			}
			if got.Contradicted != c.want {
				t.Errorf("Contradicted = %v, want %v", got.Contradicted, c.want)
			}
		})
	}
}

// A comparison the plan cannot complete -- a planned value unknown, or withheld
// as sensitive, where the constant is compared -- is undecided, which is
// neither a match nor a contradiction. A definite contradiction elsewhere in the
// same value still decides it.
func TestAComparisonThePlanCannotCompleteIsUndecided(t *testing.T) {
	cases := map[string]struct {
		expressions, after, unknown, sensitive, path string
		block                                        bool
		contradicted, undecided                      bool
	}{
		"a value the plan does not know": {`{"acl": {"constant_value": "private"}}`,
			`{"acl": null}`, `{"acl": true}`, `{}`, "acl", false, false, true},
		"a value the plan withholds": {`{"acl": {"constant_value": "private"}}`,
			`{"acl": "private"}`, `{}`, `{"acl": true}`, "acl", false, false, true},
		"a value the plan shows": {`{"acl": {"constant_value": "private"}}`,
			`{"acl": "private"}`, `{}`, `{}`, "acl", false, false, false},
		"one element withheld": {`{"ranges": {"constant_value": ["10.0.0.0/8", "192.168.0.0/16"]}}`,
			`{"ranges": ["10.0.0.0/8", "x"]}`, `{}`, `{"ranges": [false, true]}`, "ranges", false, false, true},
		"one element withheld, compared first": {`{"ranges": {"constant_value": ["192.168.0.0/16", "10.0.0.0/8"]}}`,
			`{"ranges": ["10.0.0.0/8", "x"]}`, `{}`, `{"ranges": [false, true]}`, "ranges", false, false, true},
		// The pairing exists -- 22 with the first, 80 with the second -- through
		// values the plan withholds; pairing 22 with the second would leave
		// 80 contradicted.
		"a pairing through withheld values": {`{"rules": {"constant_value": [{"port": 22, "cidr": "a"}, {"port": 80, "cidr": "b"}]}}`,
			`{"rules": [{"port": 22, "cidr": "x"}, {"port": 1, "cidr": "x"}]}`, `{}`,
			`{"rules": [{"cidr": true}, {"port": true, "cidr": true}]}`, "rules", false, false, true},
		"one element withheld, another contradicted": {`{"ranges": {"constant_value": ["10.0.0.0/8", "192.168.0.0/16"]}}`,
			`{"ranges": ["0.0.0.0/0", "x"]}`, `{}`, `{"ranges": [false, true]}`, "ranges", false, true, false},
		"a count the plan does not keep": {`{"ranges": {"constant_value": ["10.0.0.0/8"]}}`,
			`{"ranges": ["10.0.0.0/8", "x"]}`, `{}`, `{"ranges": [false, true]}`, "ranges", false, true, false},
		"a key withheld": {`{"tags": {"constant_value": {"a": "1", "b": "2"}}}`,
			`{"tags": {"a": "1", "b": "x"}}`, `{}`, `{"tags": {"b": true}}`, "tags", false, false, true},
		"an attribute nobody wrote, withheld": {`{"ingress": {"constant_value": [{"from": 22, "note": null}]}}`,
			`{"ingress": [{"from": 22, "note": "x"}]}`, `{}`, `{"ingress": [{"note": true}]}`, "ingress", false, false, true},
		"a block one attribute of which is withheld": {`{"allow": [{"protocol": {"constant_value": "tcp"}}]}`,
			`{"allow": [{"protocol": "tcp", "ports": ["22"]}]}`, `{}`, `{"allow": [{"ports": true}]}`, "allow", true, false, true},
		// A static block beside a dynamic one: one recorded, two planned, so
		// no single planned value is the one written.
		"a path that names no single value": {`{"rule": [{"port": {"constant_value": 22}}]}`,
			`{"rule": [{"port": 80}, {"port": 22}]}`, `{}`, `{}`, "rule.port", false, false, true},
		"blocks the plan does not know": {`{"allow": [{"protocol": {"constant_value": "tcp"}}]}`,
			`{"allow": null}`, `{"allow": true}`, `{}`, "allow", true, false, true},
		"one of two blocks the plan does not know": {`{"allow": [{"protocol": {"constant_value": "tcp"}}, {"protocol": {"constant_value": "udp"}}]}`,
			`{"allow": [{"protocol": "tcp"}, null]}`, `{"allow": [false, true]}`, `{}`, "allow", true, false, true},
		"a block the plan does not hold": {`{"allow": [{"protocol": {"constant_value": "tcp"}}]}`,
			`{}`, `{}`, `{}`, "allow", true, true, false},
		"a block one attribute of which is unknown": {`{"allow": [{"protocol": {"constant_value": "tcp"}}]}`,
			`{"allow": [{"protocol": null}]}`, `{"allow": [{"protocol": true}]}`, `{}`, "allow", true, false, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			raw := `{
			  "format_version": "1.2",
			  "resource_changes": [{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
			    "provider_name": "registry.terraform.io/hashicorp/x",
			    "change": {"actions": ["update"], "before": ` + c.after + `, "after": ` + c.after + `,
			               "after_unknown": ` + c.unknown + `, "after_sensitive": ` + c.sensitive + `,
			               "before_sensitive": ` + c.sensitive + `}}],
			  "configuration": {"root_module": {"resources": [{"address": "x_thing.t", "mode": "managed",
			    "type": "x_thing", "name": "t", "provider_config_key": "x", "expressions": ` + c.expressions + `}]}}
			}`
			plan, err := Parse([]byte(raw))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			change := plan.ResourceChanges[0]
			got, found := change.Expression(c.path)
			if c.block {
				got, found = change.Block(c.path)
			}
			if !found || got.Evaluation != EvaluationConstant {
				t.Fatalf("%s: %+v, found %v", c.path, got, found)
			}
			if got.Contradicted != c.contradicted || got.Undecided != c.undecided {
				t.Errorf("Contradicted = %v, Undecided = %v; want %v, %v",
					got.Contradicted, got.Undecided, c.contradicted, c.undecided)
			}
		})
	}
}

// A verdict that reads one key of a map -- the environment a resource declares
// in its tags -- rests on what was written at that key, not on the map: under
// `ignore_changes = [tags["environment"]]` the state keeps that key while the
// configuration moves the others, and the map as a whole is contradicted only
// because of the key the lifecycle kept. Each key of a map written as a
// constant is recorded on its own; a key the plan holds that the constant does
// not write is written as nothing.
func TestEachKeyOfAWrittenMapIsDecidedOnItsOwn(t *testing.T) {
	const after = `{"tags": {"environment": "prod", "team": "b", "owner": "x"}}`
	cases := map[string]struct {
		expressions, key string
		evaluation       Evaluation
		contradicted     bool
	}{
		"a key the state keeps": {`{"tags": {"constant_value": {"environment": "staging", "team": "b", "owner": "x"}}}`,
			"environment", EvaluationConstant, true},
		"a key the configuration sets": {`{"tags": {"constant_value": {"environment": "staging", "team": "b", "owner": "x"}}}`,
			"team", EvaluationConstant, false},
		"a key written as null": {`{"tags": {"constant_value": {"environment": null, "team": "b", "owner": "x"}}}`,
			"environment", EvaluationNull, false},
		"a key the constant does not write": {`{"tags": {"constant_value": {"team": "b", "owner": "x"}}}`,
			"environment", EvaluationNull, false},
		"a map written from a variable": {`{"tags": {"references": ["var.t"]}}`,
			"environment", EvaluationUnresolved, false},
		"a map written from a resource": {`{"tags": {"references": ["x_other.o.tags", "x_other.o"]}}`,
			"environment", EvaluationDeferred, false},
		"a map written as null": {`{"tags": {"constant_value": null}}`,
			"environment", EvaluationNull, false},
		"a map written as a function": {`{"tags": {}}`,
			"environment", EvaluationDeferred, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			plan := expressionPlan(t, `{}`, c.expressions, after, `{}`, `{}`, `{}`)
			whole, found := expressionAt(t, plan, "x_thing.t", "tags")
			if !found {
				t.Fatal("no expression recorded for tags")
			}
			got := whole.Element(c.key)
			if got.Evaluation != c.evaluation || got.Contradicted != c.contradicted {
				t.Errorf("Element(%q) = %+v, want evaluation %v, contradicted %v",
					c.key, got, c.evaluation, c.contradicted)
			}
		})
	}

	// The map as a whole is still compared as a whole.
	plan := expressionPlan(t, `{}`, `{"tags": {"constant_value": {"environment": "staging", "team": "b", "owner": "x"}}}`,
		after, `{}`, `{}`, `{}`)
	if whole, _ := expressionAt(t, plan, "x_thing.t", "tags"); !whole.Contradicted {
		t.Error("a map one key of which the state keeps is not contradicted")
	}
}

// A key withheld as sensitive cannot be compared with what was written.
func TestAWithheldKeyIsUndecided(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	    "provider_name": "registry.terraform.io/hashicorp/x",
	    "change": {"actions": ["no-op"], "before": {"tags": {"environment": "prod"}}, "after": {"tags": {"environment": "prod"}},
	               "before_sensitive": {"tags": {"environment": true}}, "after_sensitive": {"tags": {"environment": true}}}}],
	  "configuration": {"root_module": {"resources": [{"address": "x_thing.t", "mode": "managed",
	    "type": "x_thing", "name": "t", "provider_config_key": "x",
	    "expressions": {"tags": {"constant_value": {"environment": "prod"}}}}]}}
	}`
	plan, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	whole, _ := plan.ResourceChanges[0].Expression("tags")
	got := whole.Element("environment")
	if got.Evaluation != EvaluationConstant || got.Contradicted || !got.Undecided {
		t.Errorf("Element = %+v, want an undecided constant", got)
	}
}

// Whether the plan keeps the value an object had is decided before sensitivity
// is applied: a sensitive mark withholds a value from this build's reading, and
// must not make a value the plan keeps look like one it moves. The comparison
// keeps nothing but its answer.
func TestAValueIsCarriedWhateverItsSensitivity(t *testing.T) {
	const canary = "CARRIED-CANARY-0c4f"
	parse := func(t *testing.T, before, after, beforeSensitive, afterSensitive, afterUnknown string) ResourceChange {
		t.Helper()
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
		    "provider_name": "registry.terraform.io/hashicorp/x",
		    "change": {"actions": ["update"], "before": ` + before + `, "after": ` + after + `,
		               "before_sensitive": ` + beforeSensitive + `, "after_sensitive": ` + afterSensitive + `,
		               "after_unknown": ` + afterUnknown + `}}]
		}`
		plan, err := Parse([]byte(raw))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return plan.ResourceChanges[0]
	}
	const (
		kept   = `{"tags": {"environment": "prod", "owner": "` + canary + `"}, "rules": [{"port": 22}, {"port": 80}]}`
		moved  = `{"tags": {"environment": "prod", "owner": "` + canary + `-new"}, "rules": [{"port": 22}, {"port": 443}]}`
		marked = `{"tags": {"owner": true}, "rules": [false, {"port": true}]}`
	)
	cases := map[string]struct {
		before, after, beforeSensitive, afterSensitive, afterUnknown string
		path                                                         []string
		want                                                         bool
	}{
		"a map, one key sensitive":                {kept, kept, marked, marked, `{}`, []string{"tags"}, true},
		"the sensitive key itself":                {kept, kept, marked, marked, `{}`, []string{"tags", "owner"}, true},
		"a key beside a sensitive one that moves": {kept, moved, marked, marked, `{}`, []string{"tags", "environment"}, true},
		"the map, its sensitive key moved":        {kept, moved, marked, marked, `{}`, []string{"tags"}, false},
		"a sensitive key that moves":              {kept, moved, marked, marked, `{}`, []string{"tags", "owner"}, false},
		"marked only after":                       {kept, kept, `{}`, marked, `{}`, []string{"tags"}, true},
		"a list, one element sensitive":           {kept, kept, marked, marked, `{}`, []string{"rules"}, true},
		"a list, the sensitive element moved":     {kept, moved, marked, marked, `{}`, []string{"rules"}, false},
		"not marked":                              {kept, kept, `{}`, `{}`, `{}`, []string{"tags"}, true},
		"not yet known":                           {kept, `{"tags": {"environment": "prod"}}`, `{}`, `{}`, `{"tags": {"owner": true}}`, []string{"tags"}, false},
		"not yet known, null on both sides":       {`{"tags": null}`, `{"tags": null}`, `{}`, `{}`, `{"tags": true}`, []string{"tags"}, false},
		"absent before":                           {`{}`, kept, `{}`, `{}`, `{}`, []string{"tags"}, false},
		// No prior value at the place is not a null one.
		"absent before, null after": {`{}`, `{"tags": null}`, `{}`, `{}`, `{}`, []string{"tags"}, false},
		// A mask can name a key the planned value omits; nothing is planned
		// there to be kept.
		"named only by a mask after":                {`{"tags": null}`, `{}`, `{}`, `{"tags": true}`, `{}`, []string{"tags"}, false},
		"no prior state":                            {`null`, kept, `{}`, `{}`, `{}`, []string{"tags"}, false},
		"before not an object":                      {`{"tags": "x"}`, kept, `{}`, `{}`, `{}`, []string{"tags", "environment"}, false},
		"before a list that is not the planned one": {`{"rules": [{"port": 22}]}`, kept, `{}`, `{}`, `{}`, []string{"rules"}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := parse(t, c.before, c.after, c.beforeSensitive, c.afterSensitive, c.afterUnknown)
			value := change.After
			for _, segment := range c.path {
				value = value.Field(segment)
			}
			if got := value.Carried(); got != c.want {
				t.Errorf("Carried = %v, want %v", got, c.want)
			}
			if found := findCanary(reflect.ValueOf(change.After), "after", canary); found != "" && c.afterSensitive == marked {
				t.Errorf("a sensitive value was retained at %s", found)
			}
		})
	}

	// An element of a list is compared with the element in the same place.
	change := parse(t, kept, moved, `{}`, `{}`, `{}`)
	rules := change.After.Field("rules")
	if !rules.At(0).Carried() || rules.At(1).Carried() {
		t.Errorf("elements: %v %v, want true false", rules.At(0).Carried(), rules.At(1).Carried())
	}
	// An element not yet known is not carried, even where the plan writes
	// null for it on both sides.
	change = parse(t, `{"rules": [null, 1]}`, `{"rules": [null, 1]}`, `{}`, `{}`, `{"rules": [true, false]}`)
	rules = change.After.Field("rules")
	if rules.At(0).Carried() || !rules.At(1).Carried() {
		t.Errorf("elements: %v %v, want false true", rules.At(0).Carried(), rules.At(1).Carried())
	}
}

// An element of a list or a set is in prior state where the prior list at the
// same place holds an equal element, at any position: a legacy-SDK set is
// ordered by hash, and a provider that suppresses removing an element plans it
// beside the one written, so the list moves and the element does not. It is
// decided like Carried, from the raw values before any mark applies, and only
// the answer is kept.
func TestAnElementIsInPriorWhereverThePriorListHoldsIt(t *testing.T) {
	const canary = "INPRIOR-CANARY-7d21"
	parse := func(t *testing.T, before, after, beforeSensitive, afterSensitive, afterUnknown string) ResourceChange {
		t.Helper()
		raw := `{
		  "format_version": "1.2",
		  "resource_changes": [{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
		    "provider_name": "registry.terraform.io/hashicorp/x",
		    "change": {"actions": ["update"], "before": ` + before + `, "after": ` + after + `,
		               "before_sensitive": ` + beforeSensitive + `, "after_sensitive": ` + afterSensitive + `,
		               "after_unknown": ` + afterUnknown + `}}]
		}`
		plan, err := Parse([]byte(raw))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		return plan.ResourceChanges[0]
	}
	cases := map[string]struct {
		before, after, beforeSensitive, afterSensitive, afterUnknown string
		want                                                         []bool
	}{
		"kept beside a new element": {`{"r": ["0.0.0.0/0"]}`, `{"r": ["0.0.0.0/0", "10.0.0.0/8"]}`,
			`{}`, `{}`, `{}`, []bool{true, false}},
		"kept at another position": {`{"r": ["0.0.0.0/0"]}`, `{"r": ["10.0.0.0/8", "0.0.0.0/0"]}`,
			`{}`, `{}`, `{}`, []bool{false, true}},
		"nothing kept": {`{"r": ["0.0.0.0/0"]}`, `{"r": ["10.0.0.0/8"]}`,
			`{}`, `{}`, `{}`, []bool{false}},
		"a block kept at another position": {`{"r": [{"port": 22}]}`, `{"r": [{"port": 80}, {"port": 22}]}`,
			`{}`, `{}`, `{}`, []bool{false, true}},
		"a block one attribute of which moved": {`{"r": [{"port": 22, "cidr": "0.0.0.0/0"}]}`,
			`{"r": [{"port": 80, "cidr": "0.0.0.0/0"}]}`, `{}`, `{}`, `{}`, []bool{false}},
		"sensitive on both sides": {`{"r": ["` + canary + `"]}`, `{"r": ["10.0.0.0/8", "` + canary + `"]}`,
			`{"r": [true]}`, `{"r": [false, true]}`, `{}`, []bool{false, true}},
		"sensitive, moved": {`{"r": ["` + canary + `"]}`, `{"r": ["10.0.0.0/8", "` + canary + `-new"]}`,
			`{"r": [true]}`, `{"r": [false, true]}`, `{}`, []bool{false, false}},
		// Not yet known is not a value, even where the plan writes the prior
		// one in its place.
		"not yet known": {`{"r": ["a", "b"]}`, `{"r": ["b", "a"]}`,
			`{}`, `{}`, `{"r": [false, true]}`, []bool{true, false}},
		"a block not yet known inside": {`{"r": [{"port": 22}]}`, `{"r": [{"port": 22}]}`,
			`{}`, `{}`, `{"r": [{"port": true}]}`, []bool{false}},
		"no prior list":            {`{}`, `{"r": ["a"]}`, `{}`, `{}`, `{}`, []bool{false}},
		"a prior null":             {`{"r": null}`, `{"r": ["a"]}`, `{}`, `{}`, `{}`, []bool{false}},
		"a prior value not a list": {`{"r": "a"}`, `{"r": ["a"]}`, `{}`, `{}`, `{}`, []bool{false}},
		"no prior state":           {`null`, `{"r": ["a"]}`, `{}`, `{}`, `{}`, []bool{false}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := parse(t, c.before, c.after, c.beforeSensitive, c.afterSensitive, c.afterUnknown)
			list := change.After.Field("r")
			if list.Len() != len(c.want) {
				t.Fatalf("%d elements, want %d", list.Len(), len(c.want))
			}
			for i, want := range c.want {
				if got := list.At(i).InPrior(); got != want {
					t.Errorf("element %d: InPrior = %v, want %v", i, got, want)
				}
			}
			if found := findCanary(reflect.ValueOf(change.After), "after", canary); found != "" {
				t.Errorf("a sensitive value was retained at %s", found)
			}
		})
	}

	// Anywhere but an element of a list, in prior is carried: the same value
	// at the same place.
	change := parse(t, `{"tags": {"a": "1", "b": "2"}}`, `{"tags": {"a": "1", "b": "3"}}`, `{}`, `{}`, `{}`)
	tags := change.After.Field("tags")
	if !tags.Field("a").InPrior() || tags.Field("b").InPrior() || tags.InPrior() {
		t.Errorf("keys: %v %v, map %v, want true false false",
			tags.Field("a").InPrior(), tags.Field("b").InPrior(), tags.InPrior())
	}
}
