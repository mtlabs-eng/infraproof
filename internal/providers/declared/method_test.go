package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// planned builds a resource change from a plan, so the shapes below are the
// ones the parser produces rather than structs assembled by hand.
func planned(t *testing.T, actions, before, configuration string) terraformplan.ResourceChange {
	t.Helper()
	return plannedWith(t, actions, before, current, configuration, `{}`)
}

func plannedWith(t *testing.T, actions, before, after, configuration, variables string) terraformplan.ResourceChange {
	t.Helper()
	raw := `{
	  "format_version": "1.2",
	  "variables": ` + variables + `,
	  "resource_changes": [{
	    "address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	    "provider_name": "registry.terraform.io/hashicorp/x",
	    "change": {"actions": ` + actions + `, "before": ` + before + `,
	               "after": ` + after + `}
	  }]`
	if configuration != "" {
		raw += `, "configuration": {"root_module": {"resources": [` + configuration + `]}}`
	}
	plan, err := terraformplan.Parse([]byte(raw + `}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return plan.ResourceChanges[0]
}

const (
	create  = `["create"]`
	update  = `["update"]`
	noOp    = `["no-op"]`
	replace = `["delete", "create"]`
	noPrior = `null`
	// current is the value every change below plans; hasPrior is the same
	// object in state, so an update of it carries every argument, and
	// changed is a state an update moves away from.
	current  = `{"name": "t", "flag": true, "settings": [{"ip": [{"enabled": true}]}]}`
	hasPrior = current
	changed  = `{"name": "t", "flag": false, "settings": [{"ip": [{"enabled": false}]}]}`
)

func entry(expressions string) string {
	out := `{"address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	         "provider_config_key": "x"`
	if expressions != "" {
		out += `, "expressions": ` + expressions
	}
	return out + `}`
}

// The method of a value follows what the configuration records about writing
// it, and "stated" is only ever the answer to a positive record of a value.
// Every other way of not knowing has its own method, so a reader can tell a
// default from a value carried from state from a plan that does not say.
//
// Carried is decided by comparing the prior state with the planned value, not
// by the schema: under lifecycle { ignore_changes } Terraform carries any
// argument, Computed or not, and the configuration does not record the
// lifecycle block.
func TestTheMethodFollowsWhatTheConfigurationRecords(t *testing.T) {
	flag := declared.Argument{Path: "flag"}
	rules := declared.Argument{Path: "rule", Block: true}
	nested := declared.Argument{Path: "settings.ip.enabled"}
	required := declared.Argument{Path: "flag", Required: true}
	requiredNested := declared.Argument{Path: "settings.flag", Required: true}

	unwritten := entry(`{"name": {"constant_value": "t"}}`)
	cases := map[string]struct {
		argument declared.Argument
		change   terraformplan.ResourceChange
		want     model.Method
	}{
		"written": {
			flag, planned(t, create, noPrior, entry(`{"flag": {"constant_value": true}}`)),
			model.MethodStated,
		},
		"written, on an update that keeps it": {
			flag, planned(t, update, hasPrior, entry(`{"flag": {"constant_value": true}}`)),
			model.MethodStated,
		},
		"written, on an update that sets it": {
			flag, planned(t, update, changed, entry(`{"flag": {"constant_value": true}}`)),
			model.MethodStated,
		},
		// ignore_changes: the configuration writes false, the plan keeps the
		// true it had. The value is not the one written.
		"written as another constant, carried": {
			flag, planned(t, noOp, hasPrior, entry(`{"flag": {"constant_value": false}}`)),
			model.MethodPriorState,
		},
		// Not carried, so whatever the provider made of the constant, the
		// plan is applying what the author wrote.
		"written as another constant, on a create": {
			flag, planned(t, create, noPrior, entry(`{"flag": {"constant_value": false}}`)),
			model.MethodStated,
		},
		// The plan holds a value at the argument that is not the constant
		// written: whatever moved it, it is not the author's value, moved or
		// not. The principle recorded in milestone 10's fifth-review
		// amendment.
		"written as another constant, on an update that moves it": {
			flag, planned(t, update, changed, entry(`{"flag": {"constant_value": false}}`)),
			model.MethodPriorState,
		},
		// The plan records no value for a reference, so on an update that
		// keeps the value nothing separates the write from a value
		// ignore_changes kept: unrecorded, by the decision recorded in
		// milestone 10, even where the write is what the object had.
		"written from a resource, carried": {
			flag, planned(t, noOp, hasPrior, entry(`{"flag": {"references": ["x_other.o.flag", "x_other.o"]}}`)),
			model.MethodConfigurationUnrecorded,
		},
		"written from a resource, on a create": {
			flag, planned(t, create, noPrior, entry(`{"flag": {"references": ["x_other.o.flag", "x_other.o"]}}`)),
			model.MethodStated,
		},
		// ignore_changes keeps the prior value, so a value the update moves
		// is the configuration's.
		"written from a resource, on an update that moves it": {
			flag, planned(t, update, changed, entry(`{"flag": {"references": ["x_other.o.flag", "x_other.o"]}}`)),
			model.MethodStated,
		},
		// A function of constants records neither a value nor a reference.
		"written as a function, carried": {
			flag, planned(t, noOp, hasPrior, entry(`{"flag": {}}`)),
			model.MethodConfigurationUnrecorded,
		},
		"written as null, on a create": {
			flag, planned(t, create, noPrior, entry(`{"flag": {"constant_value": null}}`)),
			model.MethodProviderDefault,
		},
		"written as null, carried": {
			flag, planned(t, update, hasPrior, entry(`{"flag": {"constant_value": null}}`)),
			model.MethodPriorState,
		},
		"written as a variable recorded as null": {
			flag, plannedWith(t, update, hasPrior, current, entry(`{"flag": {"references": ["var.v"]}}`),
				`{"v": {"value": null}}`),
			model.MethodPriorState,
		},
		// The plan records the variable's value, not what the expression
		// makes of it: `!var.v` is recorded exactly as `var.v`.
		"written as a variable recorded with a value, carried": {
			flag, plannedWith(t, update, hasPrior, current, entry(`{"flag": {"references": ["var.v"]}}`),
				`{"v": {"value": true}}`),
			model.MethodConfigurationUnrecorded,
		},
		"written as a variable recorded with a value, on a create": {
			flag, plannedWith(t, create, noPrior, current, entry(`{"flag": {"references": ["var.v"]}}`),
				`{"v": {"value": true}}`),
			model.MethodStated,
		},
		"written as a variable recorded with a value, moved": {
			flag, plannedWith(t, update, changed, current, entry(`{"flag": {"references": ["var.v"]}}`),
				`{"v": {"value": true}}`),
			model.MethodStated,
		},
		"written as a variable the plan does not resolve": {
			flag, planned(t, create, noPrior, entry(`{"flag": {"references": ["var.v"]}}`)),
			model.MethodConfigurationUnrecorded,
		},
		"unwritten, on a create": {
			flag, planned(t, create, noPrior, unwritten),
			model.MethodProviderDefault,
		},
		"unwritten, carried": {
			flag, planned(t, update, hasPrior, unwritten),
			model.MethodPriorState,
		},
		"unwritten, on a no-op": {
			flag, planned(t, noOp, hasPrior, unwritten),
			model.MethodPriorState,
		},
		// The plan moves the value: it is not carried, it is the value the
		// provider plans for an argument nobody wrote.
		"unwritten, on an update that moves it": {
			flag, planned(t, update, changed, unwritten),
			model.MethodProviderDefault,
		},
		// A replacement creates a new object: nothing is carried.
		"unwritten, on a replace": {
			flag, planned(t, replace, hasPrior, unwritten),
			model.MethodProviderDefault,
		},
		// An empty body: Terraform omits expressions. No dynamic block can
		// write a top-level attribute, so it is unwritten.
		"an empty body": {
			flag, planned(t, create, noPrior, entry("")),
			model.MethodProviderDefault,
		},
		"an empty body, carried": {
			flag, planned(t, update, hasPrior, entry("")),
			model.MethodPriorState,
		},
		"no configuration at all": {
			flag, planned(t, create, noPrior, ""),
			model.MethodConfigurationUnrecorded,
		},
		"no configuration, carried": {
			flag, planned(t, update, hasPrior, ""),
			model.MethodConfigurationUnrecorded,
		},
		"a resource the configuration omits": {
			flag, planned(t, create, noPrior, `{"address": "x_other.o", "mode": "managed",
			  "type": "x_other", "name": "o", "provider_config_key": "x"}`),
			model.MethodConfigurationUnrecorded,
		},
		// A block missing from the configuration may be a dynamic block, which
		// Terraform does not record.
		"a block nobody recorded": {
			rules, planned(t, update, hasPrior, unwritten),
			model.MethodConfigurationUnrecorded,
		},
		"a block in an empty body": {
			rules, planned(t, create, noPrior, entry("")),
			model.MethodConfigurationUnrecorded,
		},
		"a block written": {
			rules, planned(t, create, noPrior, entry(`{"rule": [{"port": {"constant_value": 22}}]}`)),
			model.MethodStated,
		},
		// An attribute inside a block is recorded only when the block holding it
		// is: the block itself may be dynamic.
		"nested, its block not recorded": {
			nested, planned(t, create, noPrior, entry(`{"settings": [{"tier": {"constant_value": "a"}}]}`)),
			model.MethodConfigurationUnrecorded,
		},
		"nested, its block written": {
			nested, planned(t, create, noPrior, entry(`{"settings": [{"ip": [{"other": {"constant_value": 1}}]}]}`)),
			model.MethodProviderDefault,
		},
		"nested, its block written, carried": {
			nested, planned(t, update, hasPrior, entry(`{"settings": [{"ip": [{"other": {"constant_value": 1}}]}]}`)),
			model.MethodPriorState,
		},
		"nested, its block written, moved": {
			nested, planned(t, update, changed, entry(`{"settings": [{"ip": [{"other": {"constant_value": 1}}]}]}`)),
			model.MethodProviderDefault,
		},
		"nested and written": {
			nested, planned(t, create, noPrior, entry(`{"settings": [{"ip": [{"enabled": {"constant_value": true}}]}]}`)),
			model.MethodStated,
		},
		"nested, written as another constant, carried": {
			nested, planned(t, update, hasPrior, entry(`{"settings": [{"ip": [{"enabled": {"constant_value": false}}]}]}`)),
			model.MethodPriorState,
		},
		// Terraform refuses a body that omits a Required argument, and no
		// dynamic block writes an attribute, so wherever the body holding it is
		// recorded, so is the argument -- even by an entry with no expressions.
		"required, the body recorded without it": {
			required, planned(t, create, noPrior, unwritten),
			model.MethodStated,
		},
		"required, an entry without expressions": {
			required, planned(t, create, noPrior, entry("")),
			model.MethodStated,
		},
		"required, no configuration": {
			required, planned(t, create, noPrior, ""),
			model.MethodConfigurationUnrecorded,
		},
		"required, inside a block not recorded": {
			requiredNested, planned(t, create, noPrior, unwritten),
			model.MethodConfigurationUnrecorded,
		},
		"required, inside a block written": {
			requiredNested, planned(t, create, noPrior, entry(`{"settings": [{"tier": {"constant_value": "a"}}]}`)),
			model.MethodStated,
		},
		// Written, but the configuration records no expression to compare
		// with the value the update keeps.
		"required, an entry without expressions, carried": {
			required, planned(t, update, hasPrior, entry("")),
			model.MethodConfigurationUnrecorded,
		},
		"required, written as another constant, carried": {
			required, planned(t, noOp, hasPrior, entry(`{"flag": {"constant_value": false}}`)),
			model.MethodPriorState,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := c.argument.Method(c.change); got != c.want {
				t.Errorf("Method = %q, want %q", got, c.want)
			}
		})
	}
}

// A fact resting on several inputs takes the method of the least established
// one among those the configuration decides, so naming it is not a matter of
// which input a mapper happened to read first.
func TestTheWeakestConfigurationMethodWins(t *testing.T) {
	cases := []struct {
		in   []model.Method
		want model.Method
	}{
		{[]model.Method{model.MethodStated}, model.MethodStated},
		{[]model.Method{model.MethodStated, model.MethodProviderDefault}, model.MethodProviderDefault},
		{[]model.Method{model.MethodProviderDefault, model.MethodStated}, model.MethodProviderDefault},
		{[]model.Method{model.MethodProviderDefault, model.MethodPriorState}, model.MethodPriorState},
		{[]model.Method{model.MethodPriorState, model.MethodProviderDefault}, model.MethodPriorState},
		{[]model.Method{model.MethodPriorState, model.MethodConfigurationUnrecorded, model.MethodStated},
			model.MethodConfigurationUnrecorded},
		{[]model.Method{model.MethodConfigurationUnrecorded, model.MethodPriorState},
			model.MethodConfigurationUnrecorded},
		// A method this build derived is not stated, and gives way only to the
		// configuration's own ways of not knowing.
		{[]model.Method{model.MethodStated, model.MethodDocumentedTable}, model.MethodDocumentedTable},
		{[]model.Method{model.MethodDocumentedTable, model.MethodProviderDefault}, model.MethodProviderDefault},
	}
	for _, c := range cases {
		if got := declared.Weakest(c.in...); got != c.want {
			t.Errorf("Weakest(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A grant proven several ways at once takes the method of the best proof: the
// verdict needs only one, and the finding can cite the one that is stated.
func TestTheStrongestProofOfADisjunctionWins(t *testing.T) {
	cases := []struct {
		in   []model.Method
		want model.Method
	}{
		{[]model.Method{model.MethodProviderDefault, model.MethodStated}, model.MethodStated},
		{[]model.Method{model.MethodConfigurationUnrecorded, model.MethodPriorState}, model.MethodPriorState},
		{[]model.Method{model.MethodPriorState, model.MethodProviderDefault}, model.MethodProviderDefault},
		{[]model.Method{model.MethodConfigurationUnrecorded}, model.MethodConfigurationUnrecorded},
		{[]model.Method{model.MethodPolicyDocument, model.MethodProviderDefault}, model.MethodPolicyDocument},
	}
	for _, c := range cases {
		if got := declared.Strongest(c.in...); got != c.want {
			t.Errorf("Strongest(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A value the configuration does not record as written is never stated. The
// caller that knows the provider's default says whether the value is it: an
// argument nobody wrote, not Computed, on a new object holding something else
// is a shape no real plan has shown -- a hand-written plan whose configuration
// lists only references makes it -- and the plan then does not record who
// wrote the value. Carried from state, it is prior state whatever it holds.
func TestAValueNobodyRecordedWritingIsNeverStated(t *testing.T) {
	flag := declared.Argument{Path: "flag"}
	rules := declared.Argument{Path: "rule", Block: true}
	unwritten := entry(`{"name": {"constant_value": "t"}}`)

	cases := map[string]struct {
		argument  declared.Argument
		change    terraformplan.ResourceChange
		isDefault bool
		want      model.Method
	}{
		"unwritten, holding the default":            {flag, planned(t, create, noPrior, unwritten), true, model.MethodProviderDefault},
		"unwritten, holding something else":         {flag, planned(t, create, noPrior, unwritten), false, model.MethodConfigurationUnrecorded},
		"unwritten, carried, something else":        {flag, planned(t, update, hasPrior, unwritten), false, model.MethodPriorState},
		"unwritten, moved, something else":          {flag, planned(t, update, changed, unwritten), false, model.MethodConfigurationUnrecorded},
		"unwritten, moved, the default":             {flag, planned(t, update, changed, unwritten), true, model.MethodProviderDefault},
		"written as null, something else":           {flag, planned(t, create, noPrior, entry(`{"flag": {"constant_value": null}}`)), false, model.MethodConfigurationUnrecorded},
		"written, something else":                   {flag, planned(t, create, noPrior, entry(`{"flag": {"constant_value": true}}`)), false, model.MethodStated},
		"written as another constant, carried":      {flag, planned(t, noOp, hasPrior, entry(`{"flag": {"constant_value": false}}`)), false, model.MethodPriorState},
		"unrecorded stays unrecorded":               {flag, planned(t, create, noPrior, ""), false, model.MethodConfigurationUnrecorded},
		"a block stays what the configuration says": {rules, planned(t, create, noPrior, unwritten), false, model.MethodConfigurationUnrecorded},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := c.argument.MethodFor(c.change, c.isDefault); got != c.want {
				t.Errorf("MethodFor = %q, want %q", got, c.want)
			}
		})
	}
}

// A method outside the closed set, the empty one included, is a mapper that
// forgot to say how it knows. Neither order may rank it: the weakest of several
// inputs and the best of several proofs both come back empty, which fails
// validation at the bundle boundary instead of hiding behind a valid method.
func TestAMethodOutsideTheSetIsNeverHidden(t *testing.T) {
	cases := [][]model.Method{
		{""},
		{"", model.MethodStated},
		{model.MethodStated, ""},
		{"", model.MethodConfigurationUnrecorded},
		{model.MethodPolicyDocument, "not-a-method"},
		{},
	}
	for _, in := range cases {
		if got := declared.Weakest(in...); got != "" {
			t.Errorf("Weakest(%q) = %q, want the empty method", in, got)
		}
		if got := declared.Strongest(in...); got != "" {
			t.Errorf("Strongest(%q) = %q, want the empty method", in, got)
		}
	}
}

// A declared environment says what the configuration records about the tags
// or labels. Neither is Computed on any provider here and neither has a
// default, so tags nobody wrote on a new object are a value the plan does not
// record anybody writing; kept from state, they are prior state.
func TestADeclaredEnvironmentSaysWhatTheConfigurationRecords(t *testing.T) {
	const tagged = `{"name": "t", "tags": {"environment": "prod"}}`
	cases := map[string]struct {
		change terraformplan.ResourceChange
		want   model.Method
	}{
		"written": {plannedWith(t, create, noPrior, tagged,
			entry(`{"tags": {"constant_value": {"environment": "prod"}}}`), `{}`), model.MethodStated},
		"unwritten, on a create": {plannedWith(t, create, noPrior, tagged,
			entry(`{"name": {"constant_value": "t"}}`), `{}`), model.MethodConfigurationUnrecorded},
		"unwritten, carried": {plannedWith(t, noOp, tagged, tagged,
			entry(`{"name": {"constant_value": "t"}}`), `{}`), model.MethodPriorState},
		"written as another map, carried": {plannedWith(t, noOp, tagged, tagged,
			entry(`{"tags": {"constant_value": {"environment": "dev"}}}`), `{}`), model.MethodPriorState},
		"no configuration": {plannedWith(t, create, noPrior, tagged, "", `{}`), model.MethodConfigurationUnrecorded},
		// ignore_changes = [tags["environment"]]: another key moves, the one
		// the declaration is read from does not.
		"written as another value, the key kept while another moves": {plannedWith(t, update,
			`{"name": "t", "tags": {"environment": "prod", "team": "a"}}`,
			`{"name": "t", "tags": {"environment": "prod", "team": "b"}}`,
			entry(`{"tags": {"constant_value": {"environment": "staging", "team": "b"}}}`), `{}`), model.MethodPriorState},
		// Two keys of the name with one value: the declaration rests on both.
		"two keys of the name, one kept against its constant": {plannedWith(t, noOp,
			`{"name": "t", "tags": {"environment": "prod", "Environment": "prod"}}`,
			`{"name": "t", "tags": {"environment": "prod", "Environment": "prod"}}`,
			entry(`{"tags": {"constant_value": {"environment": "prod", "Environment": "dev"}}}`), `{}`), model.MethodPriorState},
		"two keys of the name, the other kept against its constant": {plannedWith(t, noOp,
			`{"name": "t", "tags": {"environment": "prod", "Environment": "prod"}}`,
			`{"name": "t", "tags": {"environment": "prod", "Environment": "prod"}}`,
			entry(`{"tags": {"constant_value": {"environment": "dev", "Environment": "prod"}}}`), `{}`), model.MethodPriorState},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fact := declared.Environment(c.change, "tags", model.CloudAWS)
			if !fact.IsKnown() || fact.Method() != c.want {
				t.Errorf("%s method = %q, want known %q", fact.State, fact.Method(), c.want)
			}
		})
	}
}

// Carried means the whole value at the path is the one the object had: an
// object that gains or loses a key, or a list that changes, is not carried.
func TestCarriedComparesTheWholeValue(t *testing.T) {
	cases := map[string]struct {
		before, after string
		want          bool
	}{
		"the same map":           {`{"tags": {"a": "1"}}`, `{"tags": {"a": "1"}}`, true},
		"a map that gains a key": {`{"tags": {"a": "1"}}`, `{"tags": {"a": "1", "b": "2"}}`, false},
		"a map that loses a key": {`{"tags": {"a": "1", "b": "2"}}`, `{"tags": {"a": "1"}}`, false},
		"another value":          {`{"tags": {"a": "1"}}`, `{"tags": {"a": "2"}}`, false},
		"a list that grows":      {`{"tags": ["a"]}`, `{"tags": ["a", "b"]}`, false},
		"the same list":          {`{"tags": ["a", "b"]}`, `{"tags": ["a", "b"]}`, true},
		"absent on both sides":   {`{}`, `{}`, false},
		"null on both sides":     {`{"tags": null}`, `{"tags": null}`, true},
		"a number that moves":    {`{"tags": 500}`, `{"tags": 1000}`, false},
		"a bool that moves":      {`{"tags": true}`, `{"tags": false}`, false},
		"a string becoming null": {`{"tags": "a"}`, `{"tags": null}`, false},
		"a list of another kind": {`{"tags": ["1"]}`, `{"tags": {"0": "1"}}`, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := plannedWith(t, update, c.before, c.after, "", `{}`)
			if got := declared.Carried(change, "tags"); got != c.want {
				t.Errorf("Carried = %v, want %v", got, c.want)
			}
		})
	}
}

// Block syntax is decided by the attributes written inside the block, the same
// rule as an attribute: on an update that keeps the blocks, constants are
// compared with what the plan keeps -- stated where they are it, prior-state
// where they are not -- and an attribute written as anything the plan does not
// evaluate leaves nothing to compare, so the block is unrecorded. A new object,
// or an update that moves the blocks, applies what the configuration writes.
func TestABlockIsDecidedByWhatIsWrittenInsideIt(t *testing.T) {
	rules := declared.Argument{Path: "rule", Block: true}
	inner := declared.Argument{Path: "settings.ip", Block: true}
	leaf := declared.Argument{Path: "rule.port"}
	const (
		two      = `{"rule": [{"port": 22, "cidr": "0.0.0.0/0"}, {"port": 80, "cidr": "0.0.0.0/0"}]}`
		moved    = `{"rule": [{"port": 22, "cidr": "10.0.0.0/8"}, {"port": 80, "cidr": "0.0.0.0/0"}]}`
		nestedIP = `{"settings": [{"ip": [{"enabled": true, "cidr": "0.0.0.0/0"}]}]}`
		empties  = `{"rule": [{"port": 22, "cidr": []}, {"port": 80, "cidr": ""}]}`
	)
	constants := entry(`{"rule": [{"port": {"constant_value": 80}, "cidr": {"constant_value": "0.0.0.0/0"}}, {"port": {"constant_value": 22}, "cidr": {"constant_value": "0.0.0.0/0"}}]}`)
	cases := map[string]struct {
		argument      declared.Argument
		before, after string
		actions       string
		configuration string
		want          model.Method
	}{
		"constants, carried, in another order": {rules, two, two, noOp, constants, model.MethodStated},
		"constants, on a create":               {rules, noPrior, two, create, constants, model.MethodStated},
		"constants the plan does not keep": {rules, two, two, noOp,
			entry(`{"rule": [{"port": {"constant_value": 443}}, {"port": {"constant_value": 22}}]}`),
			model.MethodPriorState},
		"a constant inside a block the plan does not keep": {rules, two, two, noOp,
			entry(`{"rule": [{"port": {"constant_value": 80}}, {"port": {"constant_value": 22}, "cidr": {"constant_value": "10.0.0.0/8"}}]}`),
			model.MethodPriorState},
		"more blocks written than kept": {rules, two, two, noOp,
			entry(`{"rule": [{"port": {"constant_value": 80}}, {"port": {"constant_value": 22}}, {"port": {"constant_value": 22}}]}`),
			model.MethodPriorState},
		// ignore_changes keeps a block the author no longer writes.
		"fewer blocks written than kept": {rules, two, two, noOp,
			entry(`{"rule": [{"port": {"constant_value": 22}, "cidr": {"constant_value": "0.0.0.0/0"}}]}`),
			model.MethodPriorState},
		// Terraform plans an attribute nobody wrote as an empty value, so a
		// value the plan keeps there is not one the configuration wrote:
		// written as null, or not written in the block at all.
		"null inside a block matches only an empty value": {rules, two, two, noOp,
			entry(`{"rule": [{"port": {"constant_value": 80}, "cidr": {"constant_value": null}}, {"port": {"constant_value": 22}, "cidr": {"constant_value": "0.0.0.0/0"}}]}`),
			model.MethodPriorState},
		"an attribute nobody wrote, which the plan keeps": {rules, two, two, noOp,
			entry(`{"rule": [{"port": {"constant_value": 80}}, {"port": {"constant_value": 22}, "cidr": {"constant_value": "0.0.0.0/0"}}]}`),
			model.MethodPriorState},
		"an attribute nobody wrote, which the plan keeps empty": {rules, empties, empties, noOp,
			entry(`{"rule": [{"port": {"constant_value": 80}, "cidr": {"constant_value": null}}, {"port": {"constant_value": 22}}]}`),
			model.MethodStated},
		"a variable inside a block, carried": {rules, two, two, noOp,
			entry(`{"rule": [{"port": {"constant_value": 80}}, {"port": {"references": ["var.p"]}}]}`),
			model.MethodConfigurationUnrecorded},
		"a reference inside a block, carried": {rules, two, two, update,
			entry(`{"rule": [{"port": {"constant_value": 80}}, {"port": {"constant_value": 22}, "cidr": {"references": ["local.c"]}}]}`),
			model.MethodConfigurationUnrecorded},
		"a reference inside a block, on a create": {rules, noPrior, two, create,
			entry(`{"rule": [{"port": {"constant_value": 80}}, {"port": {"references": ["local.p"]}}]}`),
			model.MethodStated},
		"a reference inside a block, moved": {rules, moved, two, update,
			entry(`{"rule": [{"port": {"constant_value": 80}}, {"port": {"references": ["local.p"]}}]}`),
			model.MethodStated},
		"a block inside a block, constants, carried": {inner, nestedIP, nestedIP, noOp,
			entry(`{"settings": [{"ip": [{"enabled": {"constant_value": true}, "cidr": {"constant_value": "0.0.0.0/0"}}]}]}`),
			model.MethodStated},
		"a block inside a block, contradicted": {inner, nestedIP, nestedIP, noOp,
			entry(`{"settings": [{"ip": [{"cidr": {"constant_value": "10.0.0.0/8"}}]}]}`),
			model.MethodPriorState},
		"a block inside a block, a reference, carried": {inner, nestedIP, nestedIP, noOp,
			entry(`{"settings": [{"ip": [{"cidr": {"references": ["var.c"]}}]}]}`),
			model.MethodConfigurationUnrecorded},
		// An attribute written in more than one block has no one expression to
		// compare, so where the plan keeps it, nothing says it was the write.
		"an attribute of a repeated block, carried": {leaf, two, two, noOp, constants,
			model.MethodConfigurationUnrecorded},
		"an attribute of a repeated block, on a create": {leaf, noPrior, two, create, constants,
			model.MethodStated},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := plannedWith(t, c.actions, c.before, c.after, c.configuration, `{}`)
			if got := c.argument.Method(change); got != c.want {
				t.Errorf("Method = %q, want %q", got, c.want)
			}
		})
	}
}

// plannedMasked is plannedWith with the plan's sensitive masks.
func plannedMasked(t *testing.T, actions, before, after, beforeSensitive, afterSensitive, configuration string) terraformplan.ResourceChange {
	t.Helper()
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	    "provider_name": "registry.terraform.io/hashicorp/x",
	    "change": {"actions": ` + actions + `, "before": ` + before + `, "after": ` + after + `,
	               "before_sensitive": ` + beforeSensitive + `, "after_sensitive": ` + afterSensitive + `}
	  }],
	  "configuration": {"root_module": {"resources": [` + configuration + `]}}
	}`
	plan, err := terraformplan.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return plan.ResourceChanges[0]
}

// A verdict that reads one key of a map rests on what was written at that key,
// decided at that key: under ignore_changes = [tags["environment"]] the state
// keeps the key while the configuration moves another, so the map moves and
// the key does not. A sensitive mark on a sibling key must not make a map the
// plan keeps look moved either.
func TestAKeyOfAMapIsDecidedAtTheKey(t *testing.T) {
	environment := declared.Argument{Path: "tags", Key: "environment"}
	team := declared.Argument{Path: "tags", Key: "team"}
	const (
		kept      = `{"tags": {"environment": "prod", "team": "a"}}`
		teamMoved = `{"tags": {"environment": "prod", "team": "b"}}`
		envMoved  = `{"tags": {"environment": "staging", "team": "a"}}`
		written   = `{"tags": {"constant_value": {"environment": "staging", "team": "b"}}}`
		reference = `{"tags": {"references": ["x_other.o.tags", "x_other.o"]}}`
	)
	cases := map[string]struct {
		argument      declared.Argument
		before, after string
		actions       string
		expressions   string
		isDefault     bool
		want          model.Method
	}{
		"the key the lifecycle keeps, another moving":    {environment, kept, teamMoved, update, written, false, model.MethodPriorState},
		"the key the configuration moves":                {team, kept, teamMoved, update, written, false, model.MethodStated},
		"the key written and kept":                       {environment, `{"tags": {"environment": "staging", "team": "b"}}`, `{"tags": {"environment": "staging", "team": "b"}}`, noOp, written, false, model.MethodStated},
		"the key on a create":                            {environment, noPrior, `{"tags": {"environment": "staging", "team": "b"}}`, create, written, false, model.MethodStated},
		"a key the constant does not write, kept":        {environment, kept, teamMoved, update, `{"tags": {"constant_value": {"team": "b"}}}`, false, model.MethodPriorState},
		"a key the constant does not write, on a create": {environment, noPrior, kept, create, `{"tags": {"constant_value": {"team": "a"}}}`, false, model.MethodConfigurationUnrecorded},
		"a key written as null, kept":                    {environment, kept, teamMoved, update, `{"tags": {"constant_value": {"environment": null, "team": "b"}}}`, false, model.MethodPriorState},
		"a map from a reference, the key kept":           {environment, kept, teamMoved, update, reference, false, model.MethodConfigurationUnrecorded},
		"a map from a reference, the key moved":          {environment, kept, envMoved, update, reference, false, model.MethodStated},
		"a map from a reference, on a create":            {environment, noPrior, kept, create, reference, false, model.MethodStated},
		"the map unwritten, the key kept":                {environment, kept, teamMoved, update, `{"name": {"constant_value": "t"}}`, false, model.MethodPriorState},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := plannedWith(t, c.actions, c.before, c.after, entry(c.expressions), `{}`)
			if got := c.argument.MethodFor(change, c.isDefault); got != c.want {
				t.Errorf("MethodFor = %q, want %q", got, c.want)
			}
		})
	}

	// ignore_changes = [tags], one tag written from a sensitive variable: the
	// plan is a no-op, and the mark is on the sibling.
	const owned = `{"tags": {"environment": "prod", "owner": "team-old"}}`
	sensitive := plannedMasked(t, noOp, owned, owned, `{"tags": {"owner": true}}`, `{"tags": {"owner": true}}`,
		entry(`{"tags": {"references": ["var.owner"]}}`))
	if got := environment.MethodFor(sensitive, false); got != model.MethodConfigurationUnrecorded {
		t.Errorf("a sensitive sibling on a no-op: %q, want %q", got, model.MethodConfigurationUnrecorded)
	}
	if !declared.Carried(sensitive, "tags") {
		t.Error("a map the no-op keeps, one key sensitive, is not carried")
	}
}

// A constant compared with a value the plan withholds cannot be shown to be the
// value the update keeps: the comparison is undecided, and so is the method.
// The same constant on a create, or on an update the plan moves, is applied.
func TestAConstantThePlanCannotCompareIsUnrecordedWhereItIsKept(t *testing.T) {
	flag := declared.Argument{Path: "flag"}
	marked := `{"flag": true}`
	cases := map[string]struct {
		actions, before string
		want            model.Method
	}{
		"kept":     {noOp, current, model.MethodConfigurationUnrecorded},
		"moved":    {update, changed, model.MethodStated},
		"a create": {create, noPrior, model.MethodStated},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := plannedMasked(t, c.actions, c.before, current, marked, marked,
				entry(`{"flag": {"constant_value": true}}`))
			if got := flag.Method(change); got != c.want {
				t.Errorf("Method = %q, want %q", got, c.want)
			}
		})
	}
}

// A block the path passes through is followed into its one element on both
// sides; where either side holds other than one, the whole block is what the
// plan keeps or not.
func TestCarriedFollowsABlockOnlyThroughItsOneElement(t *testing.T) {
	const path = "settings.ip.enabled"
	cases := map[string]struct {
		before, after string
		want          bool
	}{
		"one block, kept": {`{"settings": [{"ip": [{"enabled": true}]}]}`,
			`{"settings": [{"ip": [{"enabled": true}]}]}`, true},
		"one block, moved": {`{"settings": [{"ip": [{"enabled": false}]}]}`,
			`{"settings": [{"ip": [{"enabled": true}]}]}`, false},
		"one block, a sibling moved": {`{"settings": [{"tier": "a", "ip": [{"enabled": true}]}]}`,
			`{"settings": [{"tier": "b", "ip": [{"enabled": true}]}]}`, true},
		"a block the update drops": {`{"settings": [{"ip": [{"enabled": true}]}, {"ip": [{"enabled": false}]}]}`,
			`{"settings": [{"ip": [{"enabled": true}]}]}`, false},
		"a block the update adds": {`{"settings": [{"ip": [{"enabled": true}]}]}`,
			`{"settings": [{"ip": [{"enabled": true}]}, {"ip": [{"enabled": false}]}]}`, false},
		"two blocks, both kept": {`{"settings": [{"ip": [{"enabled": true}]}, {"ip": [{"enabled": false}]}]}`,
			`{"settings": [{"ip": [{"enabled": true}]}, {"ip": [{"enabled": false}]}]}`, true},
		"no block before":           {`{"settings": []}`, `{"settings": [{"ip": [{"enabled": true}]}]}`, false},
		"a block before, not after": {`{"settings": [{"ip": [{"enabled": true}]}]}`, `{"settings": null}`, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			change := plannedWith(t, update, c.before, c.after, "", `{}`)
			if got := declared.Carried(change, path); got != c.want {
				t.Errorf("Carried = %v, want %v", got, c.want)
			}
		})
	}
}
