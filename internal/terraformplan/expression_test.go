package terraformplan

import (
	"reflect"
	"testing"
)

// expressionPlan builds a plan with one root resource and one resource inside
// module.m, so the variable each expression names can be resolved in either
// scope.
func expressionPlan(t *testing.T, variables, rootExpressions, after, call, moduleVariables, moduleExpressions string) Plan {
	t.Helper()
	raw := `{
	  "format_version": "1.2",
	  "variables": ` + variables + `,
	  "resource_changes": [
	    {"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	     "provider_name": "registry.terraform.io/hashicorp/x",
	     "change": {"actions": ["update"], "before": ` + after + `, "after": ` + after + `}},
	    {"address": "module.m.x_thing.t", "module_address": "module.m", "mode": "managed",
	     "type": "x_thing", "name": "t", "provider_name": "registry.terraform.io/hashicorp/x",
	     "change": {"actions": ["update"], "before": ` + after + `, "after": ` + after + `}}
	  ],
	  "configuration": {"root_module": {
	    "resources": [{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	                   "provider_config_key": "x", "expressions": ` + rootExpressions + `}],
	    "module_calls": {"m": {"source": "./m", "expressions": ` + call + `,
	      "module": {"variables": ` + moduleVariables + `,
	        "resources": [{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	                       "provider_config_key": "m:x", "expressions": ` + moduleExpressions + `}]}}}
	  }}
	}`
	plan, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return plan
}

func expressionAt(t *testing.T, plan Plan, address, path string) (Expression, bool) {
	t.Helper()
	for _, change := range plan.ResourceChanges {
		if change.Address == address {
			return change.Expression(path)
		}
	}
	t.Fatalf("no change at %s", address)
	return Expression{}, false
}

// A written argument is not a written value when its expression evaluates to
// null: Terraform treats null exactly as an omitted argument. The plan records
// enough to tell offline only for a literal null and for a variable whose value
// it records -- the root module's in `variables`, a module's in the call that
// sets it or in its default. Anything else it records is either something only
// Terraform evaluates, or a variable it does not say the value of.
func TestAnExpressionSaysWhatItEvaluatesToOffline(t *testing.T) {
	const after = `{"flag": false, "name": "t"}`
	cases := map[string]struct {
		variables, root, call, moduleVariables, module string
		address                                        string
		want                                           Evaluation
	}{
		"a literal null": {
			`{}`, `{"flag": {"constant_value": null}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationNull,
		},
		"a literal value": {
			`{}`, `{"flag": {"constant_value": false}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationConstant,
		},
		"a root variable recorded as null": {
			`{"v": {"value": null}}`, `{"flag": {"references": ["var.v"]}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationNull,
		},
		"a root variable recorded with a value": {
			`{"v": {"value": true}}`, `{"flag": {"references": ["var.v"]}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationDeferred,
		},
		"a root variable the plan does not record": {
			`{}`, `{"flag": {"references": ["var.v"]}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationUnresolved,
		},
		"an attribute of a root variable recorded as null": {
			`{"v": {"value": {"on": null}}}`, `{"flag": {"references": ["var.v.on", "var.v"]}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationNull,
		},
		"an attribute of a root variable recorded as null itself": {
			`{"v": {"value": null}}`, `{"flag": {"references": ["var.v.on", "var.v"]}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationUnresolved,
		},
		"an element of a root variable": {
			`{"v": {"value": [null]}}`, `{"flag": {"references": ["var.v[0]", "var.v"]}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationUnresolved,
		},
		"two root variables, one null and one not": {
			`{"a": {"value": null}, "b": {"value": true}}`, `{"flag": {"references": ["var.a", "var.b"]}}`,
			`{}`, `{}`, `{}`,
			"x_thing.t", EvaluationUnresolved,
		},
		"a resource reference": {
			`{}`, `{"flag": {"references": ["x_other.o.flag", "x_other.o"]}}`, `{}`, `{}`, `{}`,
			"x_thing.t", EvaluationDeferred,
		},
		"a variable beside a resource reference": {
			`{"v": {"value": null}}`, `{"flag": {"references": ["var.v", "x_other.o.flag", "x_other.o"]}}`,
			`{}`, `{}`, `{}`,
			"x_thing.t", EvaluationDeferred,
		},
		"a module variable nobody sets, defaulting to null": {
			`{}`, `{}`, `{}`, `{"v": {"default": null}}`, `{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationNull,
		},
		"a module variable nobody sets, defaulting to a value": {
			`{}`, `{}`, `{}`, `{"v": {"default": true}}`, `{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationDeferred,
		},
		"a module variable set to a constant": {
			`{}`, `{}`, `{"v": {"constant_value": true}}`, `{"v": {}}`, `{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationDeferred,
		},
		// The plan does not record `nullable`: a null passed to a variable
		// with a default is null when the variable is nullable, and the default
		// when it is not.
		"a module variable set to null, with a default": {
			`{}`, `{}`, `{"v": {"constant_value": null}}`, `{"v": {"default": true}}`,
			`{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationUnresolved,
		},
		"a module variable set to null, defaulting to null": {
			`{}`, `{}`, `{"v": {"constant_value": null}}`, `{"v": {"default": null}}`,
			`{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationNull,
		},
		"a module variable set from a root variable recorded as null": {
			`{"r": {"value": null}}`, `{}`, `{"v": {"references": ["var.r"]}}`, `{"v": {}}`,
			`{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationNull,
		},
		// The same expression written in the module itself would be one only
		// Terraform evaluates; passing it through a variable changes nothing.
		"a module variable set from a resource": {
			`{}`, `{}`, `{"v": {"references": ["x_other.o.flag", "x_other.o"]}}`, `{"v": {}}`,
			`{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationDeferred,
		},
		"a module variable the module does not declare": {
			`{}`, `{}`, `{}`, `{}`, `{"flag": {"references": ["var.v"]}}`,
			"module.m.x_thing.t", EvaluationUnresolved,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			plan := expressionPlan(t, c.variables, c.root, after, c.call, c.moduleVariables, c.module)
			got, found := expressionAt(t, plan, c.address, "flag")
			if !found {
				t.Fatalf("no expression recorded for flag")
			}
			if got.Evaluation != c.want {
				t.Errorf("Evaluation = %v, want %v", got.Evaluation, c.want)
			}
		})
	}
}

// Under `lifecycle { ignore_changes }` Terraform keeps the prior value in
// `after` whatever the configuration writes, and the plan's configuration does
// not record the lifecycle block. A constant the configuration records that is
// not the value in `after` is the only trace it leaves.
//
// The comparison is Terraform's encoding of a written constant: an attribute
// written as blocks records every attribute of the block, null where the author
// wrote nothing, and a set is unordered.
func TestAConstantNotInAfterIsContradicted(t *testing.T) {
	cases := map[string]struct {
		expressions, after string
		path               string
		want               bool
	}{
		"the same string": {
			`{"acl": {"constant_value": "private"}}`, `{"acl": "private"}`, "acl", false,
		},
		"another string": {
			`{"acl": {"constant_value": "private"}}`, `{"acl": "public-read"}`, "acl", true,
		},
		"a number written as a string": {
			`{"port": {"constant_value": "5432"}}`, `{"port": 5432}`, "port", false,
		},
		"a map with another key": {
			`{"tags": {"constant_value": {}}}`, `{"tags": {"environment": "prod"}}`, "tags", true,
		},
		"the same map": {
			`{"tags": {"constant_value": {"env": "a"}}}`, `{"tags": {"env": "a"}}`, "tags", false,
		},
		"blocks, nulls where nothing was written": {
			`{"ingress": {"constant_value": [{"cidr_blocks": ["10.0.0.0/8"], "description": null, "from_port": 443}]}}`,
			`{"ingress": [{"cidr_blocks": ["10.0.0.0/8"], "description": "", "from_port": 443}]}`,
			"ingress", false,
		},
		"blocks, another rule": {
			`{"ingress": {"constant_value": [{"cidr_blocks": ["10.0.0.0/8"], "description": null, "from_port": 443}]}}`,
			`{"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "description": "", "from_port": 22}]}`,
			"ingress", true,
		},
		"a set in another order": {
			`{"source_ranges": {"constant_value": ["10.0.0.0/8", "192.168.0.0/16"]}}`,
			`{"source_ranges": ["192.168.0.0/16", "10.0.0.0/8"]}`,
			"source_ranges", false,
		},
		"a list of another length": {
			`{"source_ranges": {"constant_value": ["10.0.0.0/8"]}}`,
			`{"source_ranges": ["0.0.0.0/0", "10.0.0.0/8"]}`,
			"source_ranges", true,
		},
		"nested in a single block": {
			`{"settings": [{"ip": [{"enabled": {"constant_value": false}}]}]}`,
			`{"settings": [{"ip": [{"enabled": true}]}]}`,
			"settings.ip.enabled", true,
		},
		// A static block beside a dynamic one: the configuration records one
		// block and the plan carries two, so no single value is the one
		// written.
		"one block recorded, two planned": {
			`{"rule": [{"port": {"constant_value": 22}}]}`,
			`{"rule": [{"port": 80}, {"port": 22}]}`,
			"rule.port", false,
		},
		"a reference cannot be compared": {
			`{"acl": {"references": ["x_other.o.acl", "x_other.o"]}}`, `{"acl": "public-read"}`, "acl", false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			plan := expressionPlan(t, `{}`, c.expressions, c.after, `{}`, `{}`, `{}`)
			got, found := expressionAt(t, plan, "x_thing.t", c.path)
			if !found {
				t.Fatalf("no expression recorded for %s", c.path)
			}
			if got.Contradicted != c.want {
				t.Errorf("Contradicted = %v, want %v", got.Contradicted, c.want)
			}
		})
	}
}

// A repeated block writes the same path more than once, and one record cannot
// describe them all; so does a block, which is not an expression.
func TestOnlyAnArgumentWrittenOnceHasAnExpression(t *testing.T) {
	plan := expressionPlan(t, `{}`,
		`{"rule": [{"port": {"constant_value": 22}}, {"port": {"constant_value": null}}], "name": {"constant_value": "t"}}`,
		`{"name": "t"}`, `{}`, `{}`, `{}`)
	if _, found := expressionAt(t, plan, "x_thing.t", "rule.port"); found {
		t.Error("a path written in two blocks has an expression")
	}
	if _, found := expressionAt(t, plan, "x_thing.t", "rule"); found {
		t.Error("a block has an expression")
	}
	if _, found := expressionAt(t, plan, "x_thing.t", "name"); !found {
		t.Error("an argument written once has no expression")
	}
}

// What the configuration records is read, never kept: a constant can be a
// password, and a variable's value a secret. Only what this build concluded
// about it survives the parse.
func TestNoRecordedValueIsRetained(t *testing.T) {
	const canary = "EXPRESSION-CANARY-5d1e"
	plan := expressionPlan(t, `{"v": {"value": "`+canary+`-var"}}`,
		`{"password": {"constant_value": "`+canary+`-const"}, "name": {"references": ["var.v"]}}`,
		`{"name": "t", "password": "x"}`, `{"v": {"constant_value": "`+canary+`-call"}}`,
		`{"v": {"default": "`+canary+`-default"}}`, `{"name": {"references": ["var.v"]}}`)
	for _, suffix := range []string{"-var", "-const", "-call", "-default"} {
		if found := findCanary(reflect.ValueOf(plan), "plan", canary+suffix); found != "" {
			t.Errorf("a recorded value was retained at %s", found)
		}
	}
}

// A value the plan does not know, or withholds, is never contradicted: there is
// nothing to compare the constant with.
func TestAValueThePlanDoesNotShowIsNeverContradicted(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	    "provider_name": "registry.terraform.io/hashicorp/x",
	    "change": {"actions": ["update"], "before": {"acl": "a", "tag": "a"}, "after": {"acl": null, "tag": "b"},
	               "after_unknown": {"acl": true}, "after_sensitive": {"tag": true}}}],
	  "configuration": {"root_module": {"resources": [{"address": "x_thing.t", "mode": "managed",
	    "type": "x_thing", "name": "t", "provider_config_key": "x",
	    "expressions": {"acl": {"constant_value": "private"}, "tag": {"constant_value": "private"}}}]}}
	}`
	plan, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, path := range []string{"acl", "tag"} {
		got, found := plan.ResourceChanges[0].Expression(path)
		if !found || got.Evaluation != EvaluationConstant {
			t.Fatalf("%s: %+v, found %v", path, got, found)
		}
		if got.Contradicted {
			t.Errorf("%s: a value the plan does not show was contradicted", path)
		}
	}
}
