package providers_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Ten review rounds found the same defect nine times, in four dimensions, and
// the rule they converged on is this:
//
//	The mapper concludes only from facts the plan states. An absent value, a
//	value whose kind it did not check, a correlation the configuration does not
//	declare, and an identity the configuration does not attribute are all
//	unstated — and an unstated fact never matches another unstated fact.
//
// Only one answer can be wrong in the way that matters: Known(false), which
// says a resource is provably not public. This enumerates every route to that
// answer, every input each route reads, and requires that unstating any of them
// stops the answer.
//
// The table is worth only its membership. An earlier version listed four of the
// six routes and perturbed one of the four dimensions, and a one-token change
// to a route it did not list produced a false Known(false) that the whole suite
// missed. Both gaps are why the routes below are written out rather than
// derived from the code: a table derived from the code cannot notice that the
// code grew a route.
func TestNothingUnstatedProvesPrivate(t *testing.T) {
	for _, route := range provenRoutes() {
		t.Run(route.name, func(t *testing.T) {
			// The unperturbed plan must actually prove the subject private, or
			// every case below passes for the wrong reason.
			baseline := publicAccessOf(t, route.render(route.stated, nil), route.subject)
			if !baseline.IsKnown() || baseline.Get() {
				t.Fatalf("the baseline must prove the subject private, got state=%q value=%v",
					baseline.State, baseline.Get())
			}

			for name, m := range route.mutations() {
				t.Run(name, func(t *testing.T) {
					subject := route.subject
					if m.subject != "" {
						subject = m.subject
					}
					got := publicAccessOf(t, route.render(route.stated, &m), subject)
					if got.IsKnown() && !got.Get() {
						t.Fatalf("an unstated %s still proved the subject private", m.dimension)
					}
				})
			}
		})
	}
}

// The four dimensions earlier rounds established: a conclusion can rest on a
// value, on the identity of the resource carrying it, on that resource still
// existing after the change, and on a correlation the configuration declares.
const (
	dimValue       = "value"
	dimIdentity    = "identity"
	dimLifecycle   = "lifecycle"
	dimCorrelation = "correlation"
	dimAmbiguity   = "ambiguity"
)

// How a value can be unstated. Each is a distinct way for a fact to be missing
// while still reading as present to code that does not check.
type valueKind int

const (
	valueStated valueKind = iota
	valueAbsent
	valueIllTyped
	valueNotYetKnown
	valueSensitive
)

// mutation removes exactly one stated fact.
type mutation struct {
	dimension string

	// value dimension
	field string
	kind  valueKind

	// structural dimensions
	destroyControl   bool
	otherProvider    bool
	unattributed     bool
	uncorrelated     bool
	partialRepeat    bool
	outerModule      bool
	crossInstance    bool
	wrongNamedKey    bool
	keyedInModule    bool
	nestedInstance   bool
	twoBucketBlocks  bool
	twoAccountBlocks bool
	twoAccounts      bool

	// subject overrides the address to read when the perturbation changes it,
	// as repeating a resource does.
	subject string
}

type route struct {
	name    string
	subject string
	// deciding are the attributes this route reads to reach Known(false).
	deciding []string
	// stated gives each deciding attribute the value that proves the subject
	// private, so the sensitive perturbation can mark it without also changing
	// it — otherwise the route could pass by having been handed a different
	// answer rather than by handling redaction.
	stated map[string]string
	// structural lists the non-value perturbations this route admits.
	structural []mutation
	render     func(stated map[string]string, m *mutation) string
}

func (r route) mutations() map[string]mutation {
	out := map[string]mutation{}
	for _, field := range r.deciding {
		for label, kind := range map[string]valueKind{
			"absent":        valueAbsent,
			"ill-typed":     valueIllTyped,
			"not yet known": valueNotYetKnown,
			"sensitive":     valueSensitive,
		} {
			out[field+": "+label] = mutation{dimension: dimValue, field: field, kind: kind}
		}
	}
	for _, structural := range r.structural {
		out[structural.dimension+": "+structuralName(structural)] = structural
	}
	return out
}

func structuralName(m mutation) string {
	switch {
	case m.destroyControl:
		return "the change removes the control"
	case m.otherProvider:
		return "the control belongs to another provider instance"
	case m.unattributed:
		return "the configuration attributes no provider"
	case m.uncorrelated:
		return "the reference names no instance"
	case m.partialRepeat:
		return "the reference reaches a repeated resource the plan only partly lists"
	case m.outerModule:
		return "the reference reaches into a repeated module from outside it"
	case m.crossInstance:
		return "the control sits in another instance of the same module"
	case m.wrongNamedKey:
		return "the reference names a different instance"
	case m.keyedInModule:
		return "the named key belongs to the module, not the resource"
	case m.nestedInstance:
		return "the control sits in another instance of the inner module"
	case m.twoBucketBlocks, m.twoAccountBlocks, m.twoAccounts:
		return "two controls of one kind disagree about the subject"
	}
	return "unnamed"
}

func provenRoutes() []route {
	// All four flags, because each closes one route to the public and the
	// mapper must require all four; perturbing only the first would leave the
	// other three unheld.
	awsFlags := []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"}
	allBlocked := map[string]string{}
	for _, flag := range awsFlags {
		allBlocked[flag] = "true"
	}

	return []route{
		{
			name:     "the AWS bucket block shuts every route",
			subject:  "aws_s3_bucket.assets",
			deciding: awsFlags,
			stated:   allBlocked,
			structural: []mutation{
				{dimension: dimCorrelation, uncorrelated: true, subject: `aws_s3_bucket.assets["a"]`},
				{dimension: dimCorrelation, partialRepeat: true, subject: `aws_s3_bucket.assets["z"]`},
				{dimension: dimCorrelation, outerModule: true,
					subject: `module.m["eu"].module.n["x"].aws_s3_bucket.assets`},
				{dimension: dimCorrelation, crossInstance: true,
					subject: `module.m["z"].aws_s3_bucket.assets`},
				{dimension: dimCorrelation, wrongNamedKey: true,
					subject: `aws_s3_bucket.assets["z"]`},
				{dimension: dimCorrelation, keyedInModule: true,
					subject: `module.m["a"].aws_s3_bucket.assets["z"]`},
				{dimension: dimCorrelation, nestedInstance: true,
					subject: `module.m["eu"].module.n["y"].aws_s3_bucket.assets`},
				{dimension: dimAmbiguity, twoBucketBlocks: true},
			},
			render: func(stated map[string]string, m *mutation) string {
				return awsBucketRoute(awsFlags, stated, m)
			},
		},
		{
			name:     "the AWS account block shuts every route",
			subject:  "aws_s3_bucket.assets",
			deciding: awsFlags,
			stated:   allBlocked,
			structural: []mutation{
				{dimension: dimLifecycle, destroyControl: true},
				{dimension: dimIdentity, otherProvider: true},
				{dimension: dimIdentity, unattributed: true},
				{dimension: dimAmbiguity, twoAccountBlocks: true},
			},
			render: func(stated map[string]string, m *mutation) string {
				return awsAccountRoute(awsFlags, stated, m)
			},
		},
		{
			name:     "the Azure account forbids anonymous access to its containers",
			subject:  "azurerm_storage_container.assets",
			deciding: []string{"allow_nested_items_to_be_public"},
			stated:   map[string]string{"allow_nested_items_to_be_public": "false"},
			structural: []mutation{
				{dimension: dimCorrelation, uncorrelated: true},
				{dimension: dimAmbiguity, twoAccounts: true},
			},
			render: azureGateRoute,
		},
		{
			name:     "the Azure container is private",
			subject:  "azurerm_storage_container.assets",
			deciding: []string{"container_access_type"},
			stated:   map[string]string{"container_access_type": `"private"`},
			render:   azureContainerRoute,
		},
		{
			// The route round ten found unheld: the account answers for itself
			// when no container is in the plan.
			name:     "the Azure account answers for itself",
			subject:  "azurerm_storage_account.sa",
			deciding: []string{"allow_nested_items_to_be_public"},
			stated:   map[string]string{"allow_nested_items_to_be_public": "false"},
			render:   azureAccountRoute,
		},
		{
			name:     "GCP prevention is enforced",
			subject:  "google_storage_bucket.assets",
			deciding: []string{"public_access_prevention"},
			stated:   map[string]string{"public_access_prevention": `"enforced"`},
			render:   gcpRoute,
		},
	}
}

// changeBody renders a resource change, applying a value perturbation to
// whichever deciding attribute it names. The three masks are built together so
// a perturbed attribute lands in the right one whatever its position.
type changeBody struct {
	after, unknown, sensitive []string
}

func (b *changeBody) set(field, stated string, m *mutation) {
	kind := valueStated
	if m != nil && m.dimension == dimValue && m.field == field {
		kind = m.kind
	}
	switch kind {
	case valueAbsent:
		// nothing: the plan never mentions it
	case valueIllTyped:
		b.after = append(b.after, fmt.Sprintf("%q: %s", field, otherKind(stated)))
	case valueNotYetKnown:
		b.after = append(b.after, fmt.Sprintf("%q: null", field))
		b.unknown = append(b.unknown, fmt.Sprintf("%q: true", field))
	case valueSensitive:
		b.after = append(b.after, fmt.Sprintf("%q: %s", field, stated))
		b.sensitive = append(b.sensitive, fmt.Sprintf("%q: true", field))
	default:
		b.after = append(b.after, fmt.Sprintf("%q: %s", field, stated))
	}
}

func (b *changeBody) setAll(order []string, stated map[string]string, m *mutation) {
	for _, field := range order {
		b.set(field, stated[field], m)
	}
}

func (b *changeBody) create() string {
	out := `"actions": ["create"], "before": null, "after": {` + strings.Join(b.after, ", ") + `}`
	if len(b.unknown) > 0 {
		out += `, "after_unknown": {` + strings.Join(b.unknown, ", ") + `}`
	}
	if len(b.sensitive) > 0 {
		out += `, "after_sensitive": {` + strings.Join(b.sensitive, ", ") + `}`
	}
	return out
}

func (b *changeBody) destroy() string {
	return `"actions": ["delete"], "before": {` + strings.Join(b.after, ", ") + `}, "after": null`
}

// otherKind returns a value of a different JSON kind, so a route reading it
// without checking gets the zero value of the kind it expected.
func otherKind(stated string) string {
	if strings.HasPrefix(stated, `"`) {
		return "[" + stated + "]"
	}
	return `"` + strings.Trim(stated, `"`) + `"`
}

func awsBucketRoute(flags []string, stated map[string]string, m *mutation) string {
	block := &changeBody{}
	block.setAll(flags, stated, m)

	if m != nil && m.partialRepeat {
		return awsPartialRepeat(block)
	}
	if m != nil && m.outerModule {
		return awsOuterModule(block)
	}
	if m != nil && m.crossInstance {
		return awsCrossInstance(block)
	}
	if m != nil && m.wrongNamedKey {
		return awsWrongNamedKey(block)
	}
	if m != nil && m.keyedInModule {
		return awsKeyedInModule(block)
	}
	if m != nil && m.nestedInstance {
		return awsNestedInstance(block)
	}
	if m != nil && m.twoBucketBlocks {
		return awsTwoBucketBlocks(block)
	}

	buckets := `{"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	             "name": "assets", "provider_name": "p",
	             "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}}`
	blocks := `{"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	            "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	            "change": {` + block.create() + `}}`
	bucketConfig := `{"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	                  "name": "assets", "expressions": {}}`
	blockConfig := `{"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	                 "type": "aws_s3_bucket_public_access_block", "name": "assets",
	                 "expressions": {"bucket": {"references": [
	                   "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}`

	if m != nil && m.uncorrelated {
		// Both resources repeated, and the reference names neither instance.
		// Round seven established that the plan format cannot say which block
		// belongs to which bucket, so the answer must be that it does not know.
		buckets = `{"address": "aws_s3_bucket.assets[\"a\"]", "mode": "managed", "type": "aws_s3_bucket",
		            "name": "assets", "index": "a", "provider_name": "p",
		            "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
		           {"address": "aws_s3_bucket.assets[\"z\"]", "mode": "managed", "type": "aws_s3_bucket",
		            "name": "assets", "index": "z", "provider_name": "p",
		            "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}}`
		blocks = `{"address": "aws_s3_bucket_public_access_block.assets[\"a\"]", "mode": "managed",
		           "type": "aws_s3_bucket_public_access_block", "name": "assets", "index": "a",
		           "provider_name": "p", "change": {` + block.create() + `}},
		          {"address": "aws_s3_bucket_public_access_block.assets[\"z\"]", "mode": "managed",
		           "type": "aws_s3_bucket_public_access_block", "name": "assets", "index": "z",
		           "provider_name": "p", "change": {` + block.create() + `}}`
		bucketConfig = `{"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
		                 "name": "assets", "for_each_expression": {"constant_value": ["a", "z"]},
		                 "expressions": {}}`
		blockConfig = `{"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
		                "type": "aws_s3_bucket_public_access_block", "name": "assets",
		                "for_each_expression": {"constant_value": ["a", "z"]},
		                "expressions": {"bucket": {"references": ["aws_s3_bucket.assets"]}}}`
	}

	return `{
	  "format_version": "1.2",
	  "resource_changes": [` + buckets + `, ` + blocks + `],
	  "configuration": {"root_module": {"resources": [` + bucketConfig + `, ` + blockConfig + `]}}
	}`
}

// awsPartialRepeat plans one instance of a repeated bucket and a single block
// reaching it by a reference that names no instance. One instance in the plan
// is not one instance in the configuration: the reference may have meant the
// instance that is not changing.
func awsPartialRepeat(block *changeBody) string {
	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets[\"z\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {` + block.create() + `}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "for_each_expression": {"constant_value": ["a", "z"]}, "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "expressions": {"bucket": {"references": ["aws_s3_bucket.assets"]}}}
	  ]}}
	}`
}

// awsOuterModule puts the block in the enclosing module and the buckets in a
// repeated inner one. The block reaches the inner resource by name, but the
// configuration cannot say which instance of the inner module it meant.
func awsOuterModule(block *changeBody) string {
	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"eu\"].module.n[\"x\"].aws_s3_bucket.assets",
	     "module_address": "module.m[\"eu\"].module.n[\"x\"]", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "x"}}},
	    {"address": "module.m[\"eu\"].module.n[\"y\"].aws_s3_bucket.assets",
	     "module_address": "module.m[\"eu\"].module.n[\"y\"]", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "y"}}},
	    {"address": "module.m[\"eu\"].aws_s3_bucket_public_access_block.outer",
	     "module_address": "module.m[\"eu\"]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "outer", "provider_name": "p",
	     "change": {` + block.create() + `}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {
	    "resources": [
	      {"address": "aws_s3_bucket_public_access_block.outer", "mode": "managed",
	       "type": "aws_s3_bucket_public_access_block", "name": "outer",
	       "expressions": {"bucket": {"references": ["module.n.aws_s3_bucket.assets"]}}}
	    ],
	    "module_calls": {"n": {"source": "./n", "module": {"resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", "expressions": {}}
	    ]}}}
	  }}}}}
	}`
}

// awsCrossInstance plans two instances of one module and a block in only the
// first. Both buckets answer to the same configuration address, so a rule that
// forgets which module instance a resource sits in will let the first
// instance's block speak for the second's bucket.
func awsCrossInstance(block *changeBody) string {
	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"a\"].aws_s3_bucket.assets", "module_address": "module.m[\"a\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "module.m[\"z\"].aws_s3_bucket.assets", "module_address": "module.m[\"z\"]",
	     "mode": "managed", "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}},
	    {"address": "module.m[\"a\"].aws_s3_bucket_public_access_block.assets",
	     "module_address": "module.m[\"a\"]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {` + block.create() + `}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {
	    "resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", "expressions": {}},
	      {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	       "type": "aws_s3_bucket_public_access_block", "name": "assets",
	       "expressions": {"bucket": {"references": [
	         "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	    ]
	  }}}}}
	}`
}

// awsWrongNamedKey plans two instances and a block whose reference names the
// other one. A reference that says which instance it means must be believed
// about the instance it excludes as well as the one it includes.
func awsWrongNamedKey(block *changeBody) string {
	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets[\"a\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket.assets[\"z\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "z"}}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {` + block.create() + `}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "for_each_expression": {"constant_value": ["a", "z"]}, "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets[\"a\"].id", "aws_s3_bucket.assets[\"a\"]",
	       "aws_s3_bucket.assets"]}}}
	  ]}}
	}`
}

// awsKeyedInModule repeats the bucket inside a repeated module, so each
// instance carries two keys: the module's and its own. A reference naming one
// key names the resource's, which is the last; reading the first would let a
// block bound to one bucket speak for its sibling.
func awsKeyedInModule(block *changeBody) string {
	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"a\"].aws_s3_bucket.assets[\"a\"]",
	     "module_address": "module.m[\"a\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "index": "a", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "aa"}}},
	    {"address": "module.m[\"a\"].aws_s3_bucket.assets[\"z\"]",
	     "module_address": "module.m[\"a\"]", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "index": "z", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "az"}}},
	    {"address": "module.m[\"a\"].aws_s3_bucket_public_access_block.assets",
	     "module_address": "module.m[\"a\"]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {` + block.create() + `}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {
	    "resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", "for_each_expression": {"constant_value": ["a", "z"]},
	       "expressions": {}},
	      {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	       "type": "aws_s3_bucket_public_access_block", "name": "assets",
	       "expressions": {"bucket": {"references": [
	         "aws_s3_bucket.assets[\"a\"].id", "aws_s3_bucket.assets[\"a\"]",
	         "aws_s3_bucket.assets"]}}}
	    ]
	  }}}}}
	}`
}

// awsNestedInstance repeats an inner module inside an outer one and puts the
// block in only one inner instance. The two instances agree on the outer key
// and differ on the inner, so a comparison that stops at the first key will
// hand one instance's block to the other's bucket.
func awsNestedInstance(block *changeBody) string {
	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "module.m[\"eu\"].module.n[\"x\"].aws_s3_bucket.assets",
	     "module_address": "module.m[\"eu\"].module.n[\"x\"]", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "x"}}},
	    {"address": "module.m[\"eu\"].module.n[\"y\"].aws_s3_bucket.assets",
	     "module_address": "module.m[\"eu\"].module.n[\"y\"]", "mode": "managed",
	     "type": "aws_s3_bucket", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "y"}}},
	    {"address": "module.m[\"eu\"].module.n[\"x\"].aws_s3_bucket_public_access_block.assets",
	     "module_address": "module.m[\"eu\"].module.n[\"x\"]", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "assets", "provider_name": "p",
	     "change": {` + block.create() + `}}
	  ],
	  "configuration": {"root_module": {"module_calls": {"m": {"source": "./m", "module": {
	    "module_calls": {"n": {"source": "./n", "module": {"resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", "expressions": {}},
	      {"address": "aws_s3_bucket_public_access_block.assets", "mode": "managed",
	       "type": "aws_s3_bucket_public_access_block", "name": "assets",
	       "expressions": {"bucket": {"references": [
	         "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	    ]}}}
	  }}}}}
	}`
}

// awsTwoBucketBlocks attaches two public-access blocks to one bucket, one
// permissive and one not. Which of them the provider would apply is not a fact
// the plan states, so neither may be believed: a rule that takes the last one
// it happens to see will read a contradiction as proof.
func awsTwoBucketBlocks(block *changeBody) string {
	permissive := &changeBody{after: []string{
		`"block_public_acls": false`, `"block_public_policy": false`,
		`"ignore_public_acls": false`, `"restrict_public_buckets": false`}}

	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_public_access_block.open", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "open", "provider_name": "p",
	     "change": {` + permissive.create() + `}},
	    {"address": "aws_s3_bucket_public_access_block.shut", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "shut", "provider_name": "p",
	     "change": {` + block.create() + `}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "expressions": {}},
	    {"address": "aws_s3_bucket_public_access_block.open", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "open",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	    {"address": "aws_s3_bucket_public_access_block.shut", "mode": "managed",
	     "type": "aws_s3_bucket_public_access_block", "name": "shut",
	     "expressions": {"bucket": {"references": [
	       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
	  ]}}
	}`
}

// awsTwoAccountBlocks gives one provider instance two account-wide blocks that
// disagree. The account block is the control most often absent from a plan, so
// a rule that resolves a contradiction between two of them by order would be
// deciding the most consequential case by accident.
func awsTwoAccountBlocks(account *changeBody) string {
	permissive := &changeBody{after: []string{
		`"block_public_acls": false`, `"block_public_policy": false`,
		`"ignore_public_acls": false`, `"restrict_public_buckets": false`}}

	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}},
	    {"address": "aws_s3_account_public_access_block.open", "mode": "managed",
	     "type": "aws_s3_account_public_access_block", "name": "open", "provider_name": "p",
	     "change": {` + permissive.create() + `}},
	    {"address": "aws_s3_account_public_access_block.shut", "mode": "managed",
	     "type": "aws_s3_account_public_access_block", "name": "shut", "provider_name": "p",
	     "change": {` + account.create() + `}}
	  ],
	  "configuration": {
	    "provider_config": {"aws": {"name": "aws", "full_name": "p"}},
	    "root_module": {"resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", "provider_config_key": "aws", "expressions": {}},
	      {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	       "name": "assets", "provider_config_key": "aws",
	       "expressions": {"bucket": {"references": [
	         "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	      {"address": "aws_s3_account_public_access_block.open", "mode": "managed",
	       "type": "aws_s3_account_public_access_block", "name": "open",
	       "provider_config_key": "aws", "expressions": {}},
	      {"address": "aws_s3_account_public_access_block.shut", "mode": "managed",
	       "type": "aws_s3_account_public_access_block", "name": "shut",
	       "provider_config_key": "aws", "expressions": {}}
	    ]}
	  }
	}`
}

func awsAccountRoute(flags []string, stated map[string]string, m *mutation) string {
	account := &changeBody{}
	account.setAll(flags, stated, m)

	if m != nil && m.twoAccountBlocks {
		return awsTwoAccountBlocks(account)
	}

	change := account.create()
	if m != nil && m.destroyControl {
		// A block being removed is not in force after the change. What holds
		// that here is the absence of an after value, not the beingRemoved
		// filter: removing that filter loses a true positive rather than
		// proving anything private, so it is outside this table's contract and
		// held by the AWS package's own tests instead.
		unperturbed := &changeBody{}
		unperturbed.setAll(flags, stated, nil)
		change = unperturbed.destroy()
	}

	bucketKey, accountKey := `"provider_config_key": "aws"`, `"provider_config_key": "aws"`
	if m != nil && m.otherProvider {
		// An account block in another account says nothing about this bucket.
		accountKey = `"provider_config_key": "aws.other"`
	}
	if m != nil && m.unattributed {
		// Neither is attributed, so sameness cannot be established — and two
		// unstated provider identities must not match each other.
		bucketKey, accountKey = `"schema_version": 0`, `"schema_version": 0`
	}

	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket", "name": "assets",
	     "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"bucket": "a"}}},
	    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	     "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null, "after": {"acl": "public-read"}}},
	    {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	     "type": "aws_s3_account_public_access_block", "name": "this", "provider_name": "p",
	     "change": {` + change + `}}
	  ],
	  "configuration": {
	    "provider_config": {
	      "aws": {"name": "aws", "full_name": "p"},
	      "aws.other": {"name": "aws", "alias": "other", "full_name": "p"}
	    },
	    "root_module": {"resources": [
	      {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
	       "name": "assets", ` + bucketKey + `, "expressions": {}},
	      {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
	       "name": "assets", ` + bucketKey + `,
	       "expressions": {"bucket": {"references": [
	         "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}},
	      {"address": "aws_s3_account_public_access_block.this", "mode": "managed",
	       "type": "aws_s3_account_public_access_block", "name": "this", ` + accountKey + `,
	       "expressions": {}}
	    ]}
	  }
	}`
}

func azureGateRoute(stated map[string]string, m *mutation) string {
	gate := &changeBody{}
	gate.after = append(gate.after, `"name": "s"`)
	gate.set("allow_nested_items_to_be_public", stated["allow_nested_items_to_be_public"], m)

	accounts := `{"address": "azurerm_storage_account.sa", "mode": "managed",
	              "type": "azurerm_storage_account", "name": "sa", "provider_name": "p",
	              "change": {` + gate.create() + `}}`
	accountConfig := `{"address": "azurerm_storage_account.sa", "mode": "managed",
	                   "type": "azurerm_storage_account", "name": "sa", "expressions": {}}`
	reference := `{"references": ["azurerm_storage_account.sa.id", "azurerm_storage_account.sa"]}`

	if m != nil && m.twoAccounts {
		return azureTwoAccounts(gate)
	}

	if m != nil && m.uncorrelated {
		// Two accounts, one forbidding and one permitting, and a reference that
		// names neither. The container cannot be said to sit under the
		// forbidding one.
		permissive := &changeBody{after: []string{`"name": "z"`, `"allow_nested_items_to_be_public": true`}}
		accounts = `{"address": "azurerm_storage_account.sa[\"a\"]", "mode": "managed",
		             "type": "azurerm_storage_account", "name": "sa", "index": "a",
		             "provider_name": "p", "change": {` + gate.create() + `}},
		            {"address": "azurerm_storage_account.sa[\"z\"]", "mode": "managed",
		             "type": "azurerm_storage_account", "name": "sa", "index": "z",
		             "provider_name": "p", "change": {` + permissive.create() + `}}`
		accountConfig = `{"address": "azurerm_storage_account.sa", "mode": "managed",
		                  "type": "azurerm_storage_account", "name": "sa",
		                  "for_each_expression": {"constant_value": ["a", "z"]}, "expressions": {}}`
		reference = `{"references": ["azurerm_storage_account.sa"]}`
	}

	// The container asks to be public; only the account gate makes it private.
	return `{
	  "format_version": "1.2",
	  "resource_changes": [` + accounts + `,
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [` + accountConfig + `,
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": ` + reference + `}}
	  ]}}
	}`
}

// azureTwoAccounts points one container at two storage accounts that disagree
// about anonymous access. Which account the container belongs to is not stated
// once two are named, so the forbidding one may not answer for it.
func azureTwoAccounts(gate *changeBody) string {
	permissive := &changeBody{after: []string{`"name": "z"`, `"allow_nested_items_to_be_public": true`}}

	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.open", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "open", "provider_name": "p",
	     "change": {` + permissive.create() + `}},
	    {"address": "azurerm_storage_account.shut", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "shut", "provider_name": "p",
	     "change": {` + gate.create() + `}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "assets", "container_access_type": "blob"}}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.open", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "open", "expressions": {}},
	    {"address": "azurerm_storage_account.shut", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "shut", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {
	       "storage_account_id": {"references": [
	         "azurerm_storage_account.open.id", "azurerm_storage_account.open"]},
	       "storage_account_name": {"references": [
	         "azurerm_storage_account.shut.name", "azurerm_storage_account.shut"]}}}
	  ]}}
	}`
}

func azureContainerRoute(stated map[string]string, m *mutation) string {
	container := &changeBody{}
	container.after = append(container.after, `"name": "assets"`)
	container.set("container_access_type", stated["container_access_type"], m)

	// The account permits public containers; only the container makes it private.
	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.sa", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "sa", "provider_name": "p",
	     "change": {"actions": ["create"], "before": null,
	                "after": {"name": "s", "allow_nested_items_to_be_public": true}}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets", "provider_name": "p",
	     "change": {` + container.create() + `}}
	  ],
	  "configuration": {"root_module": {"resources": [
	    {"address": "azurerm_storage_account.sa", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "sa", "expressions": {}},
	    {"address": "azurerm_storage_container.assets", "mode": "managed",
	     "type": "azurerm_storage_container", "name": "assets",
	     "expressions": {"storage_account_id": {"references": [
	       "azurerm_storage_account.sa.id", "azurerm_storage_account.sa"]}}}
	  ]}}
	}`
}

func azureAccountRoute(stated map[string]string, m *mutation) string {
	account := &changeBody{}
	account.after = append(account.after, `"name": "s"`)
	account.set("allow_nested_items_to_be_public", stated["allow_nested_items_to_be_public"], m)

	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "azurerm_storage_account.sa", "mode": "managed",
	     "type": "azurerm_storage_account", "name": "sa", "provider_name": "p",
	     "change": {` + account.create() + `}}
	  ]
	}`
}

func gcpRoute(stated map[string]string, m *mutation) string {
	bucket := &changeBody{}
	bucket.after = append(bucket.after, `"name": "a"`)
	bucket.set("public_access_prevention", stated["public_access_prevention"], m)

	return `{
	  "format_version": "1.2",
	  "resource_changes": [
	    {"address": "google_storage_bucket.assets", "mode": "managed",
	     "type": "google_storage_bucket", "name": "assets", "provider_name": "p",
	     "change": {` + bucket.create() + `}}
	  ]
	}`
}

func publicAccessOf(t *testing.T, raw, address string) model.Fact[bool] {
	t.Helper()
	plan, err := terraformplan.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, raw)
	}
	resource, ok := providers.Normalize(plan, providers.Default()).At(address)
	if !ok || resource.ObjectStorage == nil {
		t.Fatalf("no normalized object storage at %s", address)
	}
	return resource.ObjectStorage.PublicAccess
}
