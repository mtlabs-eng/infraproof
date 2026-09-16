package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// inspectReport is the development view of a parsed plan. It reports what the
// parser understood — addresses, actions, and which fields are unreadable — and
// is structurally incapable of showing a plan value: there is no field to put
// one in.
type inspectReport struct {
	FormatVersion    string          `json:"format_version"`
	TerraformVersion string          `json:"terraform_version"`
	PlanDigest       string          `json:"plan_digest"`
	ResourceChanges  []inspectChange `json:"resource_changes"`
}

type inspectChange struct {
	Address       string   `json:"address"`
	ModuleAddress string   `json:"module_address,omitempty"`
	Mode          string   `json:"mode"`
	Type          string   `json:"type"`
	Provider      string   `json:"provider"`
	ProviderAlias string   `json:"provider_alias,omitempty"`
	Actions       []string `json:"actions"`
	Replace       bool     `json:"replace"`
	Destructive   bool     `json:"destructive"`
	UnknownPaths  []string `json:"unknown_paths"`
	RedactedPaths []string `json:"redacted_paths"`
	// ObjectStorage appears only for a resource a mapper normalized. It reports
	// what was understood about exposure and what could not be determined; it
	// is not a verdict, and inspect still reaches none.
	ObjectStorage *inspectObjectStorage `json:"object_storage,omitempty"`
}

type inspectObjectStorage struct {
	PublicAccess       string   `json:"public_access"`
	GrantsPublicAccess bool     `json:"grants_public_access"`
	DeterminedFrom     []string `json:"determined_from"`
	Unresolved         []string `json:"unresolved_controls"`
}

// runInspect parses a plan and prints what it found. It verifies nothing.
func runInspect(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	planPath := flags.String("plan", "", "path to a Terraform or OpenTofu plan JSON file")

	if err := flags.Parse(args); err != nil {
		return evidence.ExitInvalidInput
	}
	if flags.NArg() > 0 {
		return usageError(stderr, fmt.Sprintf("inspect takes no positional arguments, got %q", flags.Arg(0)))
	}
	if *planPath == "" {
		return usageError(stderr, "inspect requires --plan")
	}

	raw, err := os.ReadFile(*planPath)
	if err != nil {
		fmt.Fprintf(stderr, "infraproof: cannot read the plan file: %v\n", err)
		return evidence.ExitInvalidInput
	}

	plan, err := terraformplan.Parse(raw)
	if err != nil {
		fmt.Fprintf(stderr, "infraproof: cannot parse the plan: %v\n", err)
		return evidence.ExitInvalidInput
	}

	graph := providers.Normalize(plan, providers.Default())

	encoded, err := json.MarshalIndent(buildInspectReport(plan, graph), "", "  ")
	if err != nil {
		fmt.Fprintf(stderr, "infraproof: cannot render the report: %v\n", err)
		return evidence.ExitInternal
	}
	fmt.Fprintf(stdout, "%s\n", encoded)
	return evidence.ExitPass
}

func buildInspectReport(plan terraformplan.Plan, graph model.Graph) inspectReport {
	report := inspectReport{
		FormatVersion:    plan.FormatVersion,
		TerraformVersion: plan.TerraformVersion,
		PlanDigest:       plan.Digest,
		ResourceChanges:  make([]inspectChange, 0, len(plan.ResourceChanges)),
	}

	for _, change := range plan.ResourceChanges {
		actions := make([]string, 0, len(change.Actions))
		for _, action := range change.Actions {
			actions = append(actions, string(action))
		}

		var unknown, redacted []string
		collectPaths("before", change.Before, &unknown, &redacted)
		collectPaths("after", change.After, &unknown, &redacted)
		slices.Sort(unknown)
		slices.Sort(redacted)

		var storage *inspectObjectStorage
		if normalized, ok := graph.At(change.Address); ok {
			storage = describeObjectStorage(normalized)
		}

		report.ResourceChanges = append(report.ResourceChanges, inspectChange{
			Address:       change.Address,
			ModuleAddress: change.ModuleAddress,
			Mode:          string(change.Mode),
			Type:          change.Type,
			Provider:      change.ProviderName,
			ProviderAlias: change.ProviderAlias,
			Actions:       actions,
			Replace:       change.IsReplace(),
			Destructive:   change.IsDestructive(),
			UnknownPaths:  orEmpty(unknown),
			RedactedPaths: orEmpty(redacted),
			ObjectStorage: storage,
		})
	}

	slices.SortFunc(report.ResourceChanges, func(a, b inspectChange) int {
		return strings.Compare(a.Address, b.Address)
	})
	return report
}

// describeObjectStorage reports what a mapper made of a resource. It shows the
// state of the determination and the provider attributes it rested on, so a
// reader can see both what was concluded and how far the evidence reached.
func describeObjectStorage(resource model.NormalizedResource) *inspectObjectStorage {
	if resource.ObjectStorage == nil {
		return nil
	}
	capabilities := resource.ObjectStorage.PublicAccess.Canonical()

	out := &inspectObjectStorage{
		PublicAccess:       string(capabilities.State),
		GrantsPublicAccess: capabilities.Get(),
		DeterminedFrom:     []string{},
		Unresolved:         []string{},
	}
	for _, source := range capabilities.Sources {
		out.DeterminedFrom = append(out.DeterminedFrom, source.ResourceAddress+"."+source.AttributePath)
	}
	for _, control := range resource.ObjectStorage.Unresolved {
		out.Unresolved = append(out.Unresolved, control.CheckID)
	}
	return out
}

// collectPaths records where a value is unreadable. A path locates a field; it
// can never carry what the field contained.
//
// Object keys are joined with dots, which is ambiguous for a key that itself
// contains a dot. That is acceptable for a development view and is the reason
// this output is not a product surface.
func collectPaths(path string, value terraformplan.Value, unknown, redacted *[]string) {
	if value.Unknown() {
		*unknown = append(*unknown, path)
	}
	if value.Sensitive() {
		*redacted = append(*redacted, path)
	}

	switch value.Kind() {
	case terraformplan.KindObject:
		for _, key := range value.Keys() {
			collectPaths(path+"."+key, value.Field(key), unknown, redacted)
		}
	case terraformplan.KindArray:
		for i := range value.Len() {
			collectPaths(path+"["+strconv.Itoa(i)+"]", value.At(i), unknown, redacted)
		}
	}
}

// orEmpty keeps an absent list rendering as [] rather than null, so a consumer
// never has to handle both spellings.
func orEmpty(paths []string) []string {
	if paths == nil {
		return []string{}
	}
	return paths
}
