package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// change builds a resource change from a plan, so the shapes below are the ones
// the parser produces rather than structs assembled by hand.
func planned(t *testing.T, actions, before, configuration string) terraformplan.ResourceChange {
	t.Helper()
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [{
	    "address": "x_thing.t", "mode": "managed", "type": "x_thing", "name": "t",
	    "provider_name": "registry.terraform.io/hashicorp/x",
	    "change": {"actions": ` + actions + `, "before": ` + before + `,
	               "after": {"name": "t", "flag": true}}
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
	create   = `["create"]`
	update   = `["update"]`
	replace  = `["delete", "create"]`
	noPrior  = `null`
	hasPrior = `{"name": "t", "flag": true}`
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
// it, and "stated" is only ever the answer to a positive record. Every other way
// of not knowing has its own method, so a reader can tell a default from a value
// carried from state from a plan that does not say.
func TestTheMethodFollowsWhatTheConfigurationRecords(t *testing.T) {
	flag := declared.Argument{Path: "flag"}
	carried := declared.Argument{Path: "flag", Computed: true}
	rules := declared.Argument{Path: "rule", Block: true, Computed: true}
	nested := declared.Argument{Path: "settings.ip.enabled", Computed: true}
	required := declared.Argument{Path: "flag", Required: true}
	requiredNested := declared.Argument{Path: "settings.flag", Required: true}

	cases := map[string]struct {
		argument declared.Argument
		change   terraformplan.ResourceChange
		want     model.Method
	}{
		"written": {
			flag, planned(t, create, noPrior, entry(`{"flag": {"constant_value": true}}`)),
			model.MethodStated,
		},
		"written, on an update": {
			carried, planned(t, update, hasPrior, entry(`{"flag": {"constant_value": true}}`)),
			model.MethodStated,
		},
		"unwritten, on a create": {
			carried, planned(t, create, noPrior, entry(`{"name": {"constant_value": "t"}}`)),
			model.MethodProviderDefault,
		},
		"unwritten and computed, on an update": {
			carried, planned(t, update, hasPrior, entry(`{"name": {"constant_value": "t"}}`)),
			model.MethodPriorState,
		},
		// Terraform plans an Optional argument that is not Computed back to its
		// default when nobody writes it, so on an update the value is still the
		// default and not what the object had.
		"unwritten and not computed, on an update": {
			flag, planned(t, update, hasPrior, entry(`{"name": {"constant_value": "t"}}`)),
			model.MethodProviderDefault,
		},
		// A replacement creates a new object: nothing is carried.
		"unwritten and computed, on a replace": {
			carried, planned(t, replace, hasPrior, entry(`{"name": {"constant_value": "t"}}`)),
			model.MethodProviderDefault,
		},
		// An empty body: Terraform omits expressions. No dynamic block can
		// write a top-level attribute, so it is unwritten.
		"an empty body": {
			flag, planned(t, create, noPrior, entry("")),
			model.MethodProviderDefault,
		},
		"an empty body, on an update": {
			carried, planned(t, update, hasPrior, entry("")),
			model.MethodPriorState,
		},
		"no configuration at all": {
			flag, planned(t, create, noPrior, ""),
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
			rules, planned(t, update, hasPrior, entry(`{"name": {"constant_value": "t"}}`)),
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
		"nested, its block written, on an update": {
			nested, planned(t, update, hasPrior, entry(`{"settings": [{"ip": [{"other": {"constant_value": 1}}]}]}`)),
			model.MethodPriorState,
		},
		// Terraform refuses a body that omits a Required argument, and no
		// dynamic block writes an attribute, so wherever the body holding it is
		// recorded, so is the argument -- even by an entry with no expressions.
		"required, the body recorded without it": {
			required, planned(t, create, noPrior, entry(`{"name": {"constant_value": "t"}}`)),
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
			requiredNested, planned(t, create, noPrior, entry(`{"name": {"constant_value": "t"}}`)),
			model.MethodConfigurationUnrecorded,
		},
		"required, inside a block written": {
			requiredNested, planned(t, create, noPrior, entry(`{"settings": [{"tier": {"constant_value": "a"}}]}`)),
			model.MethodStated,
		},
		"nested and written": {
			nested, planned(t, create, noPrior, entry(`{"settings": [{"ip": [{"enabled": {"constant_value": true}}]}]}`)),
			model.MethodStated,
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

// Terraform plans an unwritten argument that is not Computed to its documented
// default on every change, and no dynamic block writes an attribute. So a
// configuration recording such an argument as unwritten beside a value that is
// not the default records something Terraform cannot produce, and the value is
// the one somebody wrote. Only that contradiction is settled this way: an
// unrecorded argument stays unrecorded, and a Computed one may be carried.
func TestANonDefaultValueOfAnArgumentNotComputedWasWritten(t *testing.T) {
	flag := declared.Argument{Path: "flag"}
	carried := declared.Argument{Path: "flag", Computed: true}
	rules := declared.Argument{Path: "rule", Block: true}
	unwritten := entry(`{"name": {"constant_value": "t"}}`)

	cases := map[string]struct {
		argument  declared.Argument
		change    terraformplan.ResourceChange
		isDefault bool
		want      model.Method
	}{
		"unwritten, holding the default": {flag, planned(t, create, noPrior, unwritten), true, model.MethodProviderDefault},
		"unwritten, holding something else": {flag, planned(t, create, noPrior, unwritten), false, model.MethodStated},
		"unwritten, on an update, something else": {flag, planned(t, update, hasPrior, unwritten), false, model.MethodStated},
		"computed, carried from state": {carried, planned(t, update, hasPrior, unwritten), false, model.MethodPriorState},
		"unrecorded stays unrecorded": {flag, planned(t, create, noPrior, ""), false, model.MethodConfigurationUnrecorded},
		"a block stays what it records": {rules, planned(t, create, noPrior, unwritten), false, model.MethodConfigurationUnrecorded},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := c.argument.MethodFor(c.change, c.isDefault); got != c.want {
				t.Errorf("MethodFor = %q, want %q", got, c.want)
			}
		})
	}
}
