package terraformplan

import (
	"reflect"
	"strings"
	"testing"
)

// realCanary is the sensitive value in the committed real plan. It is an
// invented string from a throwaway configuration, not a credential.
const realCanary = "REALPLAN-CANARY-9f3a2b7c-DO-NOT-LEAK"

// TestRealTerraformPlan parses output produced by Terraform 1.14.0 itself
// rather than by hand. Every other fixture in this package was written from the
// documented schema, which validates the parser against what the documentation
// says; this one validates it against what Terraform actually emits.
//
// The plan came from a configuration using only the random, null, local, and
// builtin terraform providers, so producing it needed no cloud account and no
// credentials, and it was never applied.
func TestRealTerraformPlan(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	if plan.FormatVersion != "1.2" || plan.TerraformVersion != "1.14.0" {
		t.Fatalf("format %q terraform %q", plan.FormatVersion, plan.TerraformVersion)
	}
	if len(plan.ResourceChanges) != 13 {
		t.Fatalf("resource changes = %d, want 13", len(plan.ResourceChanges))
	}
}

// TestRealSensitiveValueIsNotRetained is the acceptance criterion applied to a
// genuine plan: Terraform wrote the value into after and marked it in
// after_sensitive, and it must appear nowhere in the parsed structure.
func TestRealSensitiveValueIsNotRetained(t *testing.T) {
	raw := fixtureBytes(t, "real-terraform-1.14")
	if !strings.Contains(string(raw), realCanary) {
		t.Fatal("the real plan no longer contains its sensitive value; this test would pass vacuously")
	}

	plan, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if found := findCanary(reflect.ValueOf(plan), "plan", realCanary); found != "" {
		t.Fatalf("a real sensitive value was retained at %s", found)
	}

	change := changeAt(t, plan, "terraform_data.known_secret")
	input := change.After.Field("input")

	token := input.Field("token")
	if token.State() != StateRedacted {
		t.Fatalf("input.token state = %q, want %q", token.State(), StateRedacted)
	}
	if token.Text() != "" {
		t.Fatalf("input.token retained text")
	}
	if got := input.Field("public").Text(); got != "not-a-secret" {
		t.Fatalf("the non-sensitive sibling was lost: input.public = %q", got)
	}
}

// TestRealPlanUsesTheUnionRule is the strongest justification for the union key
// set: Terraform omits a value that is both unknown and sensitive from after
// entirely, so a parser that reads only after would report the field absent.
func TestRealPlanUsesTheUnionRule(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")
	after := changeAt(t, plan, "random_password.secret").After

	result := after.Field("result")
	if result.State() != StateRedacted {
		t.Fatalf("result state = %q, want %q", result.State(), StateRedacted)
	}
	if !result.Unknown() {
		t.Fatal("result is unknown until apply and must report it")
	}
	if got := after.Field("length").Number().String(); got != "16" {
		t.Fatalf("length = %q, want 16", got)
	}
	if got := after.Field("min_lower").Number().String(); got != "0" {
		t.Fatalf("min_lower = %q, want 0 — zero must survive as a value", got)
	}
	if got := after.Field("keepers").State(); got != StateKnown {
		t.Fatalf("keepers state = %q; an explicit null is a known value", got)
	}
	if got := after.Field("keepers").Kind(); got != KindNull {
		t.Fatalf("keepers kind = %q, want %q", got, KindNull)
	}
}

func TestRealPlanIndicesAndModules(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	counted := changeAt(t, plan, "null_resource.counted[0]")
	if !counted.HasIndex || counted.Index != "0" {
		t.Fatalf("count index = %q (set %v), want 0", counted.Index, counted.HasIndex)
	}

	keyed := changeAt(t, plan, `null_resource.keyed["eu"]`)
	if !keyed.HasIndex || keyed.Index != "eu" {
		t.Fatalf("for_each key = %q (set %v), want eu", keyed.Index, keyed.HasIndex)
	}

	deep := changeAt(t, plan, "module.storage.module.inner.terraform_data.deep")
	if deep.ModuleAddress != "module.storage.module.inner" {
		t.Fatalf("nested module address = %q", deep.ModuleAddress)
	}
}

// TestRealPlanResolvesAnAliasThroughAModule covers the case the configuration
// walk exists for, on real output: the resource lives in a module, carries a
// count-free configuration address, and inherits a provider instance declared
// at the root.
func TestRealPlanResolvesAnAliasThroughAModule(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	inner := changeAt(t, plan, "module.storage.random_pet.inner")
	if inner.ProviderConfigKey != "random.west" {
		t.Fatalf("provider config key = %q, want random.west", inner.ProviderConfigKey)
	}
	if inner.ProviderAlias != "west" {
		t.Fatalf("provider alias = %q, want west", inner.ProviderAlias)
	}

	def := changeAt(t, plan, "random_pet.default_instance")
	if def.ProviderName != inner.ProviderName {
		t.Fatal("this case is only meaningful when both resources share a provider source address")
	}
	if def.ProviderAlias != "" {
		t.Fatalf("the default instance alias = %q, want empty", def.ProviderAlias)
	}
}

func TestRealPlanDataSourceRead(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	change := changeAt(t, plan, "data.local_file.dynamic")
	if change.Mode != ModeData {
		t.Fatalf("mode = %q, want %q", change.Mode, ModeData)
	}
	if len(change.Actions) != 1 || change.Actions[0] != ActionRead {
		t.Fatalf("actions = %v, want [read]", change.Actions)
	}
	if change.ActionReason != "read_because_config_unknown" {
		t.Fatalf("action reason = %q", change.ActionReason)
	}
}

// TestRealPlanTopLevelFieldsAreIgnored keeps forward compatibility honest: a
// real plan carries timestamp, applyable, planned_values, prior_state and more,
// none of which this parser reads.
func TestRealPlanTopLevelFieldsAreIgnored(t *testing.T) {
	raw := fixtureBytes(t, "real-terraform-1.14")
	for _, field := range []string{"timestamp", "applyable", "planned_values", "prior_state", "relevant_attributes", "output_changes", "variables"} {
		if !strings.Contains(string(raw), `"`+field+`"`) {
			t.Fatalf("the real plan no longer carries %q; this test would pass vacuously", field)
		}
	}
	if _, err := Parse(raw); err != nil {
		t.Fatalf("unread top-level fields must not fail the parse: %v", err)
	}
}

// TestRealReplaceOrdering validates the acceptance criterion against output
// Terraform produced, not against the schema documentation. The two fixtures
// differ only by a create_before_destroy lifecycle block, and Terraform
// expresses that difference solely through the order of the actions array — so
// a parser that collapsed it into a synthetic "replace" would erase the
// distinction entirely.
func TestRealReplaceOrdering(t *testing.T) {
	deleteFirst := changeAt(t, parseFixture(t, "real-actions-terraform-1.14"), "null_resource.replaced")
	createFirst := changeAt(t, parseFixture(t, "real-create-before-destroy-terraform-1.14"), "null_resource.replaced")

	if want := []Action{ActionDelete, ActionCreate}; !equalActions(deleteFirst.Actions, want) {
		t.Fatalf("actions = %v, want %v", deleteFirst.Actions, want)
	}
	if want := []Action{ActionCreate, ActionDelete}; !equalActions(createFirst.Actions, want) {
		t.Fatalf("actions = %v, want %v", createFirst.Actions, want)
	}
	if deleteFirst.CreateBeforeDestroy() {
		t.Fatal("the default ordering is not create_before_destroy")
	}
	if !createFirst.CreateBeforeDestroy() {
		t.Fatal("the lifecycle ordering is create_before_destroy")
	}
	for _, change := range []ResourceChange{deleteFirst, createFirst} {
		if !change.IsReplace() || !change.IsDestructive() {
			t.Fatalf("%v should be a destructive replace", change.Actions)
		}
	}

	if len(deleteFirst.ReplacePaths) != 1 || len(deleteFirst.ReplacePaths[0]) != 1 ||
		deleteFirst.ReplacePaths[0][0] != "triggers" {
		t.Fatalf("replace paths = %v, want [[triggers]]", deleteFirst.ReplacePaths)
	}
	if deleteFirst.ActionReason != "replace_because_cannot_update" {
		t.Fatalf("action reason = %q", deleteFirst.ActionReason)
	}
}

// TestRealSingleActionShapes covers the remaining action shapes on real output.
// Producing them needed a prior state, which was written by hand; the plan JSON
// under test is still Terraform's own.
func TestRealSingleActionShapes(t *testing.T) {
	plan := parseFixture(t, "real-actions-terraform-1.14")

	removed := changeAt(t, plan, "terraform_data.removed")
	if !equalActions(removed.Actions, []Action{ActionDelete}) {
		t.Fatalf("actions = %v, want [delete]", removed.Actions)
	}
	if removed.ActionReason != "delete_because_no_resource_config" {
		t.Fatalf("action reason = %q", removed.ActionReason)
	}
	if removed.After.State() != StateKnown || removed.After.Kind() != KindNull {
		t.Fatalf("a delete has a known null after, got %q/%q", removed.After.State(), removed.After.Kind())
	}
	if got := removed.Before.Field("input").Text(); got != "gone" {
		t.Fatalf("the prior state was lost: before.input = %q", got)
	}

	unchanged := changeAt(t, plan, "terraform_data.unchanged")
	if !equalActions(unchanged.Actions, []Action{ActionNoOp}) {
		t.Fatalf("actions = %v, want [no-op]", unchanged.Actions)
	}
	if unchanged.IsDestructive() {
		t.Fatal("a no-op is not destructive")
	}

	updated := changeAt(t, plan, "terraform_data.updated")
	if !equalActions(updated.Actions, []Action{ActionUpdate}) {
		t.Fatalf("actions = %v, want [update]", updated.Actions)
	}
	if updated.IsReplace() || updated.IsDestructive() {
		t.Fatal("an in-place update neither replaces nor destroys")
	}
	if got := updated.Before.Field("input").Text(); got != "old-input" {
		t.Fatalf("before.input = %q, want old-input", got)
	}
	if got := updated.After.Field("input").Text(); got != "new-input" {
		t.Fatalf("after.input = %q, want new-input", got)
	}
}

func equalActions(got, want []Action) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
