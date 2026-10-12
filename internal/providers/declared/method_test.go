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
		"written from a resource, carried": {
			flag, planned(t, noOp, hasPrior, entry(`{"flag": {"references": ["x_other.o.flag", "x_other.o"]}}`)),
			model.MethodStated,
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
		"written as a variable recorded with a value": {
			flag, plannedWith(t, update, hasPrior, current, entry(`{"flag": {"references": ["var.v"]}}`),
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
