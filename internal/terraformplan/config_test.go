package terraformplan

import "testing"

func changeAt(t *testing.T, plan Plan, address string) ResourceChange {
	t.Helper()
	for _, change := range plan.ResourceChanges {
		if change.Address == address {
			return change
		}
	}
	t.Fatalf("no resource change at %q", address)
	return ResourceChange{}
}

// TestProviderAliasesAreResolved covers the reason the configuration block is
// walked at all: provider_name alone reports the same source address for every
// instance, so "aws" and "aws.west" are indistinguishable without it.
func TestProviderAliasesAreResolved(t *testing.T) {
	plan := parseFixture(t, "provider-aliases")

	def := changeAt(t, plan, "aws_s3_bucket.default_region")
	west := changeAt(t, plan, "aws_s3_bucket.west_region")

	if def.ProviderName != west.ProviderName {
		t.Fatal("this fixture is meant to use one provider source address for both resources")
	}
	if def.ProviderConfigKey != "aws" || def.ProviderAlias != "" {
		t.Fatalf("default instance: key = %q alias = %q", def.ProviderConfigKey, def.ProviderAlias)
	}
	if west.ProviderConfigKey != "aws.west" || west.ProviderAlias != "west" {
		t.Fatalf("west instance: key = %q alias = %q", west.ProviderConfigKey, west.ProviderAlias)
	}
}

// TestAliasResolvesThroughModuleCallsAndIndices covers the two things that make
// the walk non-trivial: configuration addresses are module-relative, and
// resource_changes addresses carry count and for_each keys that configuration
// does not.
func TestAliasResolvesThroughModuleCallsAndIndices(t *testing.T) {
	plan := parseFixture(t, "provider-aliases")

	inner := changeAt(t, plan, "module.storage.aws_s3_bucket.inner[0]")
	if inner.ProviderConfigKey != "storage:aws.inner" {
		t.Fatalf("module resource config key = %q", inner.ProviderConfigKey)
	}
	if inner.ProviderAlias != "inner" {
		t.Fatalf("module resource alias = %q, want inner", inner.ProviderAlias)
	}
}

func TestProviderConfigsAreExposed(t *testing.T) {
	plan := parseFixture(t, "provider-aliases")

	west, ok := plan.ProviderConfigs["aws.west"]
	if !ok {
		t.Fatalf("provider configs = %v, want a key aws.west", plan.ProviderConfigs)
	}
	if west.Name != "aws" || west.Alias != "west" {
		t.Fatalf("aws.west = %+v", west)
	}
	if west.FullName != "registry.terraform.io/hashicorp/aws" {
		t.Fatalf("aws.west full name = %q", west.FullName)
	}
	if def := plan.ProviderConfigs["aws"]; def.Alias != "" {
		t.Fatalf("the default instance should have no alias, got %q", def.Alias)
	}
}

// TestMissingConfigurationDegradesGracefully matters because sanitized plans
// routinely omit the configuration block. Losing alias information is expected;
// failing to parse is not.
func TestMissingConfigurationDegradesGracefully(t *testing.T) {
	plan := parseFixture(t, "create")

	if len(plan.ProviderConfigs) != 0 {
		t.Fatalf("provider configs = %v, want empty", plan.ProviderConfigs)
	}
	change := plan.ResourceChanges[0]
	if change.ProviderConfigKey != "" || change.ProviderAlias != "" {
		t.Fatalf("key = %q alias = %q, want both empty", change.ProviderConfigKey, change.ProviderAlias)
	}
	if change.ProviderName == "" {
		t.Fatal("provider_name must still be captured without a configuration block")
	}
}
