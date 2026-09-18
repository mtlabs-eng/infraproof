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

	// Every key that could be the declaration, not the first one found.
	// Keys() is sorted, so taking the first would resolve a disagreement by
	// byte order: "Environment" precedes "environment", and a resource tagged
	// with both would report whichever sorted first. Two controls of one kind
	// over one subject is not a fact stated twice — it is a fact the plan does
	// not state, because which one the provider applies is not recorded.
	var stated string
	var found bool
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
			// Where it is the only one, the resource declared nothing usable.
			// Where it sits beside a readable sibling, the resource declared
			// two things and did not say which applies, which is a question
			// the plan raised and did not answer.
			if found {
				return model.Unknown[string](source)
			}
			return model.Absent[string](source)
		}

		text := strings.TrimSpace(value.Text())
		if found && text != stated {
			// Two declarations that disagree. Neither may be believed, and the
			// disagreement is not an absence: the plan said something about the
			// environment and did not say which.
			return model.Unknown[string](source)
		}
		stated, found = text, true
	}
	if found {
		return model.Known(stated, source)
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
