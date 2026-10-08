package declared

import "github.com/mtlabs-eng/infraproof/internal/terraformplan"

// Removed reports that a change destroys its object and does not recreate it,
// with the plan's own state agreeing that nothing is there afterwards.
//
// A rule reading this suppresses the question it would otherwise ask, because a
// change that removes a resource permits nothing through it. That makes the
// predicate load-bearing in the permissive direction, and a plan is input: two
// declarations inside one that contradict each other must not be resolved by
// taking the half that reports less. So the action list is not enough. A real
// destroy states nothing -- `after` is JSON null, measured on genuine plan output
// for AWS and GCP and pinned by fixtures -- and a change claiming to delete while
// still stating its attributes is not a removal this build will believe.
//
// A replacement is never a removal: it destroys and creates, and the object it
// creates is what a verdict is about.
//
// This is the reasoning behind HasUnrecognizedAction and ModeContradictsActions
// in the plan reader. What a contradiction means is Terraform's to say, and this
// build refuses to guess rather than picking the reading that reports less.
func Removed(change terraformplan.ResourceChange) bool {
	if !change.IsDestructive() || change.IsReplace() {
		return false
	}
	return Unstated(change)
}

// Unstated reports that a change's after-object states no attributes at all.
//
// A mapper reading an absent attribute as a provider default is answering "the
// author did not write it". That is sound on a create. It is not sound here,
// where nobody wrote *anything*: a destroy states nothing because the object is
// going away, and a `removed` block with `lifecycle { destroy = false }` states
// nothing because the object is leaving Terraform's management while staying
// exactly as it is. Terraform emits the second as `actions: ["forget"]` with
// `after` null, and a forget is not destructive, so a removal guard does not
// cover it and should not -- the object survives.
//
// Measured: without this, a forgotten database that stays publicly accessible
// read as a determined private endpoint, and the rule said nothing. PASS, exit 0.
func Unstated(change terraformplan.ResourceChange) bool {
	if change.After.Kind() != terraformplan.KindObject {
		return true
	}
	return len(change.After.Keys()) == 0
}
