package terraformplan

import (
	"strings"
	"testing"
)

// TestModuleCallSourcesAreCaptured covers the one thing a plan says about where
// a declaration is written: the source of each module call. A resource inside
// module.storage is declared in whatever directory that call points at, and
// without the source there is no way from an address to a file.
func TestModuleCallSourcesAreCaptured(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	want := map[string]string{
		"module.storage":              "./modules/storage",
		"module.storage.module.inner": "./inner",
	}
	if len(plan.ModuleCalls) != len(want) {
		t.Fatalf("captured %d module calls, want %d: %v", len(plan.ModuleCalls), len(want), plan.ModuleCalls)
	}
	for address, source := range want {
		call, present := plan.ModuleCalls[address]
		if !present {
			t.Fatalf("no module call at %q", address)
		}
		if call.Address != address {
			t.Errorf("call keyed %q reports address %q", address, call.Address)
		}
		if call.Source != source {
			t.Errorf("module call %q source = %q, want %q", address, call.Source, source)
		}
	}
}

// TestModuleCallsAreEmptyWithoutConfiguration covers the plans that carry no
// configuration block at all, which sanitized plans routinely do not. Nothing
// is known about where those declarations live, and the answer is an empty map
// rather than a guess from the addresses.
func TestModuleCallsAreEmptyWithoutConfiguration(t *testing.T) {
	plan := parseFixture(t, "nested-modules")

	if len(plan.ModuleCalls) != 0 {
		t.Fatalf("a plan with no configuration block reported module calls: %v", plan.ModuleCalls)
	}
}

// TestConfigModuleAddressDropsRepetitionKeys covers the join between the two
// halves of the plan: resource_changes carries module.storage["eu"], and
// configuration keys the same call module.storage. Stripping the keys belongs
// here, in the package that owns the address grammar, because a caller that did
// it itself would be writing a second grammar that is almost this one.
func TestConfigModuleAddressDropsRepetitionKeys(t *testing.T) {
	plan := parseFixture(t, "nested-modules")

	cases := map[string]string{
		"module.storage[\"eu\"].aws_s3_bucket.keyed":     "module.storage",
		"module.storage.module.inner.aws_s3_bucket.logs": "module.storage.module.inner",
		"module.storage.aws_s3_bucket.replicas[0]":       "module.storage",
	}
	for address, want := range cases {
		change := changeAt(t, plan, address)
		if got := change.ConfigModuleAddress(); got != want {
			t.Errorf("%s: config module address = %q, want %q", address, got, want)
		}
	}
}

// TestRootResourceHasNoConfigModuleAddress covers the root module, which has no
// address and must not acquire one.
func TestRootResourceHasNoConfigModuleAddress(t *testing.T) {
	change := onlyChange(t, "create")

	if got := change.ConfigModuleAddress(); got != "" {
		t.Fatalf("a root resource reports config module address %q", got)
	}
}

// TestModuleCallWithoutSourceIsNotRecorded covers the permissive reading this
// build must not take. An absent source is not the empty string: joining the
// empty string onto a parent directory resolves to the parent, so a call whose
// source the plan never stated would silently claim the declarations of the
// module that calls it.
func TestModuleCallWithoutSourceIsNotRecorded(t *testing.T) {
	raw := `{"format_version": "1.2", "configuration": {"root_module": {"module_calls": {
		"storage": {"module": {"resources": []}}}}}}`

	plan, err := Parse([]byte(raw))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if _, present := plan.ModuleCalls["module.storage"]; present {
		t.Fatalf("a module call with no source was recorded: %v", plan.ModuleCalls)
	}
}

// TestModuleCallSourceIsValidatedAtTheBoundary covers the rule the rest of this
// package follows: a field that is not the type the format defines is reported
// with its path, and never coerced.
func TestModuleCallSourceIsValidatedAtTheBoundary(t *testing.T) {
	raw := `{"format_version": "1.2", "configuration": {"root_module": {"module_calls": {
		"storage": {"source": 7, "module": {"resources": []}}}}}}`

	_, err := Parse([]byte(raw))
	if err == nil {
		t.Fatal("a non-string module source should be rejected")
	}
	if !strings.Contains(err.Error(), "module_calls.storage.source") {
		t.Fatalf("error %q should name the field", err.Error())
	}
}

// TestModuleCallsRecordTheirCaller covers what resolving a module to a directory
// needs and an address cannot give without being parsed. module.storage.module
// .inner is reached by following module.storage first, and the walk that read
// the calls already knew which one that was.
func TestModuleCallsRecordTheirCaller(t *testing.T) {
	plan := parseFixture(t, "real-terraform-1.14")

	outer, present := plan.ModuleCalls["module.storage"]
	if !present || outer.Parent != "" {
		t.Fatalf("module.storage parent = %q, want the root", outer.Parent)
	}
	inner, present := plan.ModuleCalls["module.storage.module.inner"]
	if !present || inner.Parent != "module.storage" {
		t.Fatalf("module.storage.module.inner parent = %q, want module.storage", inner.Parent)
	}
}
