// Package declared holds what a mapper states about its own provider, in forms
// the correlation and normalization layers can use without knowing any cloud.
//
// Two kinds of statement live here. A fact every cloud states in the same shape
// under a different name — an environment carried in tags or labels — is read
// once here, so the provider-specific part is reduced to what it genuinely is:
// the name of an attribute. And a governance relation a mapper declares is
// described here because the mappers that declare them cannot import the
// package that assembles them.
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
	path := attribute + "." + environmentKey

	// The object the attribute is read out of, before the attribute itself.
	// Field on a non-object receiver returns the zero value, so a whole "after"
	// this run could not see collapsed to "the attribute is absent" one level
	// down — and absent is the answer that passes.
	if state := unreadable(change.After); state != "" {
		return unreadableFact(state, Source(cloud, change.Address, path, change.After))
	}

	labels := change.After.Field(attribute)
	if state := unreadable(labels); state != "" {
		return unreadableFact(state, Source(cloud, change.Address, path, labels))
	}

	// The reference locates the declaration, not the block holding it. Asking
	// the whole block would mark this reference for a secret in some unrelated
	// tag, which is the error of reporting a value the mapper read as one it
	// was not permitted to.
	source := Source(cloud, change.Address, path, declaredEnvironment(labels))

	if labels.Kind() != terraformplan.KindObject {
		// Absent, or present as something that is not a map of labels. Either
		// way the resource did not declare an environment here.
		return model.Absent[string](source)
	}

	// Every key that could be the declaration is examined, and the verdict is
	// formed after all of them.
	//
	// Returning at the first key that could not be used decided the answer by
	// where the alphabet puts a name: Keys is sorted, so an empty
	// "Environment" was seen before a readable "environment" and discarded it.
	// A map has no order, and a verdict that depends on one depends on
	// something the plan did not say.
	var stated string
	var readable, unusable bool

	for _, key := range labels.Keys() {
		if !strings.EqualFold(key, environmentKey) {
			continue
		}

		value := labels.Field(key)
		if state := unreadable(value); state != "" {
			// Withheld outright. Nothing later can restore it: the resource
			// declared something this run was not permitted to see.
			return unreadableFact(state, source)
		}
		if value.Kind() != terraformplan.KindString || strings.TrimSpace(value.Text()) == "" {
			// A key of the right name holding something that is not a name.
			unusable = true
			continue
		}

		text := strings.TrimSpace(value.Text())
		if readable && text != stated {
			// Two declarations that disagree. Neither may be believed.
			return model.Unknown[string](source)
		}
		stated, readable = text, true
	}

	switch {
	case readable && unusable:
		// The resource declared an environment and also declared something
		// unusable under the same name. Which one applies is not stated, and
		// taking the readable one would be choosing on the plan's behalf.
		return model.Unknown[string](source)
	case readable:
		return model.Known(stated, source)
	}

	return model.Absent[string](source)
}

// declaredEnvironment returns the value of the key that could be the
// declaration, matched the way the scan below matches it. Absent when the
// resource names no such key, which is not a secret.
func declaredEnvironment(labels terraformplan.Value) terraformplan.Value {
	for _, key := range labels.Keys() {
		if strings.EqualFold(key, environmentKey) {
			if value := labels.Field(key); value.HoldsSensitive() {
				return value
			}
		}
	}
	return terraformplan.Value{}
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
