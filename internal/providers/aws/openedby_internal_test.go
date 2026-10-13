package aws

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// A separate rule's grant is a disjunction over the address arguments that
// admit every address: each one alone opens the rule, so the grant takes the
// best established of them -- the documented rule for a disjunctive grant
// (EVIDENCE-BUNDLE.md), not the weakest-input rule for a fact that rests on
// all of its inputs. The provider accepts exactly one of cidr_ipv4 and
// cidr_ipv6 on aws_vpc_security_group_ingress_rule, so no real plan opens a
// rule through both; the choice is pinned here, at the function, rather than
// with a fixture Terraform could not produce.
func TestASeparateRuleOpenedTwiceTakesTheBestProof(t *testing.T) {
	raw := `{
	  "format_version": "1.2",
	  "resource_changes": [{"address": "aws_vpc_security_group_ingress_rule.r", "mode": "managed",
	    "type": "aws_vpc_security_group_ingress_rule", "name": "r",
	    "provider_name": "registry.terraform.io/hashicorp/aws",
	    "change": {"actions": ["create"], "before": null,
	               "after": {"cidr_ipv4": "0.0.0.0/0", "cidr_ipv6": "::/0", "ip_protocol": "-1"}}}],
	  "configuration": {"root_module": {"resources": [{"address": "aws_vpc_security_group_ingress_rule.r",
	    "mode": "managed", "type": "aws_vpc_security_group_ingress_rule", "name": "r",
	    "provider_config_key": "aws",
	    "expressions": {"cidr_ipv4": {"constant_value": "0.0.0.0/0"}, "ip_protocol": {"constant_value": "-1"}}}]}}
	}`
	plan, err := terraformplan.Parse([]byte(raw))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	rule := plan.ResourceChanges[0]
	// cidr_ipv4 is written; cidr_ipv6 holds ::/0 on a new rule with nothing
	// recorded writing it, which is unrecorded.
	if got := openedBy(rule, []string{"cidr_ipv6", "cidr_ipv4"}); got != model.MethodStated {
		t.Errorf("openedBy = %q, want %q", got, model.MethodStated)
	}
	if got := openedBy(rule, []string{"cidr_ipv6"}); got != model.MethodConfigurationUnrecorded {
		t.Errorf("openedBy(cidr_ipv6) = %q, want %q", got, model.MethodConfigurationUnrecorded)
	}
}
