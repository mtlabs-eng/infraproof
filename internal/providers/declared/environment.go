// Package declared reads facts that every cloud states in the same shape under
// a different name.
//
// It exists so that the reading rule is written once and the provider-specific
// part is reduced to what it genuinely is: the name of an attribute. A mapper
// passes its own key and gets back a fact with provenance.
package declared

import (
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// environmentKey is the tag or label name treated as an explicit environment
// declaration. It is a single conventional name, matched without regard to
// case: a key literally called "environment" is a statement, while inferring
// the environment from a module path, a workspace or a file name is a guess
// about a name, which docs/INTENT-CONTRACT.md excludes as evidence for
// blocking.
const environmentKey = "environment"

// Environment reads the environment a resource declares, from the attribute the
// provider uses for user-supplied labels — "tags" in AWS and Azure, "labels" in
// GCP.
//
// Every way of not saying something returns a fact that is not Known: an absent
// attribute, an attribute of the wrong kind, a value of the wrong kind, an
// empty string, a value not yet known, and a value the plan marked sensitive.
// An unstated environment agrees with nothing, least of all with whatever the
// contract happens to say, so the caller can never mistake silence for assent.
func Environment(change terraformplan.ResourceChange, attribute string, cloud model.Cloud) model.Fact[string] {
	source := model.Provenance{
		ResourceAddress: change.Address,
		AttributePath:   attribute + "." + environmentKey,
		Cloud:           cloud,
	}

	labels := change.After.Field(attribute)
	if state := unreadable(labels); state != "" {
		return unreadableFact(state, source)
	}
	if labels.Kind() != terraformplan.KindObject {
		// Absent, or present as something that is not a map of labels. Either
		// way the resource did not declare an environment here.
		return model.Absent[string](source)
	}

	for _, key := range labels.Keys() {
		if !strings.EqualFold(key, environmentKey) {
			continue
		}

		value := labels.Field(key)
		if state := unreadable(value); state != "" {
			return unreadableFact(state, source)
		}
		if value.Kind() != terraformplan.KindString || strings.TrimSpace(value.Text()) == "" {
			// A key of the right name holding something that is not a name.
			return model.Absent[string](source)
		}
		return model.Known(strings.TrimSpace(value.Text()), source)
	}

	return model.Absent[string](source)
}

// unreadable reports the fact state for a value the plan withheld, and the
// empty string for one it did not.
func unreadable(value terraformplan.Value) model.FactState {
	switch value.State() {
	case terraformplan.StateRedacted:
		return model.FactRedacted
	case terraformplan.StateUnknown:
		return model.FactUnknown
	default:
		return ""
	}
}

func unreadableFact(state model.FactState, source model.Provenance) model.Fact[string] {
	if state == model.FactRedacted {
		return model.Redacted[string](source)
	}
	return model.Unknown[string](source)
}
