package providers

import (
	"fmt"
	"slices"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Mapper interprets one provider's resources.
//
// Implementations live in subpackages and depend only on the model and the
// plan types, never on this package, so the registry below can assemble them
// without a cycle.
type Mapper interface {
	// Cloud is the cloud this mapper interprets.
	Cloud() model.Cloud
	// Interprets reports whether the mapper understands a resource type at all,
	// including the control resources it folds into a subject.
	Interprets(resourceType string) bool
	// IsSubject reports whether a resource type is one this mapper normalizes
	// in its own right, as opposed to a control over another resource.
	IsSubject(resourceType string) bool
	// Map normalizes a subject.
	//
	// related holds the changes joined to the subject by a configuration
	// reference, in either direction.
	// scope holds every change in the plan, because some controls — an
	// account-wide block, for instance — refer to nothing and still decide the
	// answer.
	Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource
}

// Governor is implemented by a mapper whose resources govern subjects the
// configuration does not connect them to by reference.
//
// The default is reference-based, which is right for a control naming the
// bucket it applies to. It is wrong for a control that applies by something
// else: an account-wide block governs every bucket in its provider instance and
// names none of them, and a storage account governs the containers that name
// it rather than the other way round. In both cases the mapper is the only
// thing that knows, so the mapper is asked.
type Governor interface {
	// Governs returns the addresses of the subjects this resource's meaning
	// belongs to, beyond those the configuration connects it to.
	Governs(resource terraformplan.ResourceChange, scope []terraformplan.ResourceChange) []string
}

// Roles is implemented by a mapper that reaches an answer by choosing between
// candidates.
//
// Whether a resource this build may not use was a candidate for the same
// question as one it did use is the whole of admissibility, and only the mapper
// knows. Everything else is a proxy. The resource type is the proxy this took
// four attempts to stop using, and it fails in both directions: one type
// answers for one subject and not another, because an account-wide block
// governs the buckets in its own account and no others, and two types can
// answer one question -- the three GCP IAM resources are read together, so a
// grant through any of them is the same grant.
//
// A mapper that does not implement this cannot have its choices checked, so
// every source it may not use is treated as contesting. That is the safe
// reading of silence, and the alternative is a verdict nothing can second-guess.
type Roles interface {
	// RoleOf names the question the candidate would answer for the subject, or
	// the empty string if it would answer none.
	//
	// The name is the mapper's own. It is compared with other names from the
	// same mapper, and it reaches a reader only as the path of an evidence
	// reference, so it should read as the thing being asked about.
	RoleOf(subject, candidate terraformplan.ResourceChange) string
}

// Normalize builds the graph. Every change in the plan appears in it: a subject
// with its capabilities, a control resource marked as understood, and anything
// no mapper claimed as an opaque entry.
func Normalize(plan terraformplan.Plan, mappers []Mapper) model.Graph {
	// Two lists, because a plan's contents and a verdict's inputs are
	// different things. Everything appears in the graph; only what the change
	// controls may answer for it.
	//
	// A read observes live state the change does not govern, so it is not
	// admissible evidence about that change — and applying that at the rules,
	// where it was, let every rule decline to judge a read while none could
	// stop a read from having already judged something else. An Azure
	// container set to blob access, beside a data source reporting its account
	// forbids anonymous access, came back proven private.
	//
	// Drawing the boundary here is what makes it hold: a mapper cannot use
	// what it is not given, and the control the change lacks goes back to
	// being reported missing, which is the true and actionable answer.
	present := plan.ResourceChanges
	admissible := admissibleChanges(present)

	// Correlation runs over everything. A reference is a reference whoever
	// wrote it, and an edge that is not built is a candidate that was never
	// counted — which is how excluding a read resolved an ambiguity by
	// deletion: two accounts became one and the survivor became authoritative.
	edges, unresolved := relate(present, mappers)

	// Hoisted: the admissible view of the graph does not depend on which
	// change is being normalized, and rebuilding it per change made
	// normalization quadratic — eight seconds on a four-megabyte plan.
	visible := admissibleEdges(edges)
	// Hoisted for the same reason: which reads a mapper could have consulted
	// is a property of the plan, not of the resource being normalized, and
	// scanning every change per change is the quadratic this fixed once
	// already, one loop further in.
	reads, scopedReads := interpretedByScope(present, mappers)
	byAddress := changesByAddress(present)

	graph := model.Graph{Resources: make([]model.NormalizedResource, 0, len(present))}
	for _, change := range present {
		resource := normalizeOne(change, visible, edges, admissible, present, byAddress, mappers)
		withhold(&resource, change,
			withheldCandidates(change, edges, reads, scopedReads),
			byAddress, mapperFor(change, mappers))
		if unresolved[change.Address] && resource.ObjectStorage != nil {
			// Saying only "undetermined" would leave a reader with nowhere to
			// go. Naming the reason lets them fix it: an argument that names
			// the instance outright — b["a"] rather than b[each.key] — is
			// resolvable, and this says so.
			resource.ObjectStorage.Unresolved = append(resource.ObjectStorage.Unresolved, model.MissingControl{
				CheckID: "CORRELATION_UNRESOLVED",
				Reason: "A resource repeated alongside this one refers to it without naming an instance, " +
					"so the plan does not record which of them applies here.",
				Cloud: resource.Cloud,
			})
		}
		graph.Resources = append(graph.Resources, resource)
	}
	return graph
}

// admissibleChanges returns the changes that may contribute to a verdict.
//
// A read is excluded: it observes state the change does not control, so it can
// explain nothing about what the change does — in either direction. It cannot
// prove prevention, and it cannot prove a grant either, because what it
// describes is what is there already rather than what the change will do.
//
// Exclusion alone is not enough, and withhold below is the other half. A source
// this build declines to use is not a source that is absent: leaving it out of
// a mapper's view without recording that it was left out let a candidate
// disappear and the survivor answer alone.
func admissibleChanges(changes []terraformplan.ResourceChange) []terraformplan.ResourceChange {
	admissible := make([]terraformplan.ResourceChange, 0, len(changes))
	for _, change := range changes {
		if change.IsRead() {
			continue
		}
		admissible = append(admissible, change)
	}
	return admissible
}

// admissibleEdges is the correlation graph with the inadmissible targets
// removed, which is what a mapper is allowed to reason from.
func admissibleEdges(edges map[string][]terraformplan.ResourceChange) map[string][]terraformplan.ResourceChange {
	out := make(map[string][]terraformplan.ResourceChange, len(edges))
	for address, related := range edges {
		out[address] = admissibleChanges(related)
	}
	return out
}

// governsOnlyReads reports a control whose every subject is one the verdict may
// not read.
//
// Such a control defers to nobody, which coverage reports as "it controls a
// resource that is not part of this plan" — a sentence that is false when the
// resource is right there and merely inadmissible. Telling a reader to add what
// they have already added is the mistake this repository names elsewhere.
//
// It counts what the control governs however it governs it. Asking the edge set
// alone left out the one kind of control that reaches its subjects through the
// scope: an account-wide block names no bucket, has no edges by construction,
// and so was never found to govern anything at all.
//
// The governed addresses are resolved through an index rather than by scanning
// the plan for each one. Scanning cost (controls × subjects × plan) and turned
// a two-thousand-bucket plan with a hundred account-wide blocks from a tenth of
// a second into nine.
func governsOnlyReads(change terraformplan.ResourceChange,
	related, scope []terraformplan.ResourceChange,
	byAddress map[string]terraformplan.ResourceChange, mapper Mapper) bool {

	governed := map[string]bool{}
	for _, candidate := range related {
		if mapper.IsSubject(candidate.Type) && candidate.Address != change.Address {
			governed[candidate.Address] = candidate.IsRead()
		}
	}
	if governor, ok := mapper.(Governor); ok {
		for _, address := range governor.Governs(change, scope) {
			if address == change.Address {
				continue
			}
			if candidate, ok := byAddress[address]; ok {
				governed[address] = candidate.IsRead()
			}
		}
	}

	if len(governed) == 0 {
		return false
	}
	for _, isRead := range governed {
		if !isRead {
			return false
		}
	}
	return true
}

// withhold refuses a verdict that was reached by choosing between a source this
// build may use and one it may not, and records every source it declined.
//
// Which reads bear on a verdict has been answered five ways in five rounds. By
// type, by direction, by re-mapping the subject with each candidate restored,
// by the type of the resources the verdict cites, and by whether some
// admissible resource answers the same question. The last is this function's
// own previous form, and it was wrong because "some admissible resource
// answers it" is what was available to the mapper rather than what the answer
// rested on: a bucket that blocks every route proves prevention from its own
// control, and a read of the account-wide block answers a question that proof
// never consulted. Plans that were settled came back undetermined.
//
// So the comparison is against what the verdict cited. A withheld source
// answering a question some cited source answered is one the verdict chose
// against, and an answer reached by choosing is not reached. A withheld source
// answering anything else chose against nothing.
//
// It is still recorded, unless the verdict proved prevention. A proof from a
// control the change itself sets is not weakened by what exists alongside it,
// so there is no open question for the read to bear on; a grant is another
// matter, because what else is in force is exactly what a reader will ask
// about. docs/PRODUCT.md promises the withheld source is named, and this is
// where that promise is kept.
//
// Nothing a read says is consulted here, so no value of one can reach a bundle
// by construction rather than by care.
func withhold(resource *model.NormalizedResource, subject terraformplan.ResourceChange,
	withheld []terraformplan.ResourceChange, cited map[string]terraformplan.ResourceChange,
	mapper Mapper) {

	if resource.ObjectStorage == nil || resource.ReadOnly || len(withheld) == 0 {
		return
	}

	roles, declares := mapper.(Roles)
	exposure := resource.ObjectStorage.PublicAccess

	answered := map[string]bool{}
	if declares {
		for _, source := range exposure.Canonical().Sources {
			change, ok := cited[source.ResourceAddress]
			if !ok {
				continue
			}
			if role := roles.RoleOf(subject, change); role != "" {
				answered[role] = true
			}
		}
	}

	var contested, alongside, suppressed []model.Provenance
	for _, candidate := range withheld {
		role := roleUnstated
		if declares {
			role = roles.RoleOf(subject, candidate)
			if role == "" {
				// The mapper says this resource answers nothing for this
				// subject. A block governing another account and a control
				// belonging to another cloud both land here, and neither is a
				// relation the configuration declares.
				continue
			}
		}
		// Withheld is not set: the bundle defines it as the located value being
		// sensitive, and a source this build declined to consult is not a
		// secret. What happened to it is what the record says.
		source := model.Provenance{
			ResourceAddress: candidate.Address,
			AttributePath:   role,
			Cloud:           resource.Cloud,
		}
		switch {
		case answered[role] || !declares:
			contested = append(contested, source)
		case exposure.IsKnown() && !exposure.Get():
			// Prevention proved by the change itself. Nothing here is open —
			// unless something else in this loop withdraws that proof, which is
			// what the list below is for.
			suppressed = append(suppressed, source)
		default:
			alongside = append(alongside, source)
		}
	}

	if len(contested) > 0 {
		if exposure.IsKnown() {
			resource.ObjectStorage.PublicAccess = model.Unknown[bool](exposure.Canonical().Sources...)
			resource.ObjectStorage.Withdrawn = true
		}
		resource.ObjectStorage.Unresolved = append(resource.ObjectStorage.Unresolved,
			withheldControl(resource.Cloud, contested,
				"A source this verdict may not rest on answers the same question as one it does rest on, "+
					"so which of them governs here is not settled."))
		// The proof those were dropped against no longer stands, so the
		// assumption that nothing was open for them to bear on no longer holds.
		alongside = append(alongside, suppressed...)
	}

	if len(alongside) > 0 {
		resource.ObjectStorage.Unresolved = append(resource.ObjectStorage.Unresolved,
			withheldControl(resource.Cloud, alongside,
				"A source this verdict may not rest on bears on this change and was not used as "+
					"evidence, so what it says is neither confirmed nor ruled out here."))
	}
}

// roleUnstated is the question a mapper that declares no roles is treated as
// having been asked. It is not a question: it records that nobody said.
const roleUnstated = "unstated"

// withheldSourceLimit bounds how many sources one record locates.
//
// A plan may hold a control per subject, and the record is per subject, so the
// pairing is quadratic in the plan and so is the report. Truncating silently
// would read as "these are the sources", so the count is stated instead.
const withheldSourceLimit = 10

// withheldControl builds the record, with the sources located rather than
// narrated. A resource address carries a for_each key, an author writes that
// key, and a free-text field is rendered as prose.
func withheldControl(cloud model.Cloud, sources []model.Provenance, reason string) model.MissingControl {
	slices.SortStableFunc(sources, compareSources)
	sources = slices.CompactFunc(sources, func(a, b model.Provenance) bool {
		return compareSources(a, b) == 0
	})

	if len(sources) > withheldSourceLimit {
		reason += fmt.Sprintf(" %d sources were withheld and the first %d are located here.",
			len(sources), withheldSourceLimit)
		sources = sources[:withheldSourceLimit]
	}

	return model.MissingControl{
		CheckID: "SOURCE_WITHHELD",
		Reason:  reason,
		Sources: sources,
		Cloud:   cloud,
	}
}

func compareSources(a, b model.Provenance) int {
	if c := strings.Compare(a.ResourceAddress, b.ResourceAddress); c != 0 {
		return c
	}
	return strings.Compare(a.AttributePath, b.AttributePath)
}

// withheldCandidates returns the reads a subject could have been judged with:
// those the configuration relates to it, and those that govern by scope rather
// than by reference, which no edge records.
//
// It walks the subject's own edges rather than the plan's reads, because a plan
// of n subjects and n reads otherwise costs n² — which is the shape that made
// this quadratic twice.
func withheldCandidates(change terraformplan.ResourceChange,
	edges map[string][]terraformplan.ResourceChange,
	reads map[string]terraformplan.ResourceChange,
	scoped []terraformplan.ResourceChange) []terraformplan.ResourceChange {

	if len(reads) == 0 && len(scoped) == 0 {
		return nil
	}

	var candidates []terraformplan.ResourceChange
	for _, related := range edges[change.Address] {
		if read, ok := reads[related.Address]; ok {
			candidates = append(candidates, read)
		}
	}
	return append(candidates, scoped...)
}

// changesByAddress indexes the plan so a verdict's provenance can be read back
// as the resources it cites. Provenance names an address; the mapper is asked
// about a change.
func changesByAddress(changes []terraformplan.ResourceChange) map[string]terraformplan.ResourceChange {
	index := make(map[string]terraformplan.ResourceChange, len(changes))
	for _, change := range changes {
		index[change.Address] = change
	}
	return index
}

// mapperFor returns the mapper that claims a resource type, or nil.
func mapperFor(change terraformplan.ResourceChange, mappers []Mapper) Mapper {
	for _, mapper := range mappers {
		if mapper.Interprets(change.Type) {
			return mapper
		}
	}
	return nil
}

// governsByScope reports a control that reaches its subjects through the scope
// rather than through a reference — an account-wide block names no bucket at
// all — and which is therefore invisible to the edge map.
//
// A subject declares no relation either, and treating one as scope-governed
// made every read of a subject type a candidate for every subject in the plan.
// That is what turned an ordinary plan cubic.
func governsByScope(change terraformplan.ResourceChange, mappers []Mapper) bool {
	for _, mapper := range mappers {
		if !mapper.Interprets(change.Type) {
			continue
		}
		if mapper.IsSubject(change.Type) {
			return false
		}
	}
	spoken, declared := declarationsFor(change.Type, mappers)
	return spoken && len(declared) == 0
}

// interpretedByScope returns the reads some mapper understands, indexed by
// address, and separately those of them that reach their subjects through the
// scope rather than through a reference.
//
// The index is what keeps the walk above linear; the scope-governed list is
// short by construction, because only a control that names no subject at all
// belongs to it.
func interpretedByScope(changes []terraformplan.ResourceChange, mappers []Mapper) (
	map[string]terraformplan.ResourceChange, []terraformplan.ResourceChange) {

	reads := map[string]terraformplan.ResourceChange{}
	var scopedReads []terraformplan.ResourceChange

	for _, change := range changes {
		if !change.IsRead() {
			continue
		}
		var interpreted bool
		for _, mapper := range mappers {
			if mapper.Interprets(change.Type) {
				interpreted = true
				break
			}
		}
		if !interpreted {
			continue
		}
		reads[change.Address] = change
		if governsByScope(change, mappers) {
			scopedReads = append(scopedReads, change)
		}
	}
	return reads, scopedReads
}

// normalizeOne builds one entry. edges is the admissible view a mapper may
// reason from; every is the whole correlation graph, and present is the whole
// plan — both of which only the bookkeeping about what was withheld may look
// at.
func normalizeOne(change terraformplan.ResourceChange,
	edges, every map[string][]terraformplan.ResourceChange,
	scope, present []terraformplan.ResourceChange,
	byAddress map[string]terraformplan.ResourceChange, mappers []Mapper) model.NormalizedResource {

	if change.IsRead() {
		// A data source is read, not changed. It is kept, because nothing in a
		// plan is filtered away, and it is given no capabilities, because a
		// verdict is about a change and this is not one.
		//
		// IsRead asks the pair, not the mode: a change claiming to read while
		// its actions say delete has not said it is a read, and believing the
		// mode alone erased it from the report entirely.
		return model.NormalizedResource{
			Address:  change.Address,
			Provider: change.ProviderName,
			Cloud:    model.CloudUnknown,
			Family:   model.FamilyUnknown,
			ReadOnly: true,
		}
	}

	for _, mapper := range mappers {
		if !mapper.Interprets(change.Type) {
			continue
		}
		if !mapper.IsSubject(change.Type) {
			// A control resource is understood, but its meaning belongs to the
			// subject it controls rather than to itself. Which subject is
			// recorded, because "it was judged through its subject" is a claim
			// nothing downstream can check without it — and a control whose
			// subject is managed elsewhere defers to nobody.
			// A control carries tags like anything else. Leaving the fact at
			// its zero value made the rule say the resource declared no
			// environment, which is a statement about a resource nothing had
			// read.
			return model.NormalizedResource{
				Address:            change.Address,
				Provider:           change.ProviderName,
				Cloud:              mapper.Cloud(),
				Family:             model.FamilyObjectStorage,
				Destructive:        change.IsDestructive(),
				Interpreted:        true,
				UnrecognizedAction: change.HasUnrecognizedAction(),
				Environment:        environmentOf(change, mapper),
				DefersTo:           defersTo(change, edges[change.Address], scope, mapper),
				GovernsWithheld:    governsOnlyReads(change, every[change.Address], present, byAddress, mapper),
			}
		}
		resource := mapper.Map(change, edges[change.Address], scope)
		resource.Interpreted = true
		resource.UnrecognizedAction = change.HasUnrecognizedAction()
		if resource.ObjectStorage == nil {
			// A subject that reached no verdict of its own has deferred to
			// something. An Azure account with a container in the plan is the
			// case: the container carries the verdict and the account defers.
			resource.DefersTo = defersTo(change, edges[change.Address], scope, mapper)
		}
		return resource
	}

	// No mapper claimed this resource, so there is no provider vocabulary to
	// read an environment by: whichever attribute a tag block would sit in is
	// this build's guess, not a fact. The answer is that none was reachable,
	// which is not the same as the resource having said nothing — and not the
	// same as no answer at all, which is what a zero fact reports.
	return model.NormalizedResource{
		Address:            change.Address,
		Provider:           change.ProviderName,
		Cloud:              model.CloudUnknown,
		Family:             model.FamilyUnknown,
		Destructive:        change.IsDestructive(),
		UnrecognizedAction: change.HasUnrecognizedAction(),
		// The fact is left at its zero state deliberately. "Nobody looked" is
		// not "looked and could not determine": no mapper claimed this
		// resource, so whichever attribute a tag block would sit in is this
		// build's guess, and there is nothing to cite either.
	}
}

// environmentOf reads a control resource's declared environment, using the
// vocabulary of the mapper that claimed it.
//
// A mapper that does not offer one leaves the answer unreachable rather than
// absent: this build did not look, which is not the same as the resource
// having said nothing.
func environmentOf(change terraformplan.ResourceChange, mapper Mapper) model.Fact[string] {
	reader, ok := mapper.(interface {
		Environment(terraformplan.ResourceChange) model.Fact[string]
	})
	if !ok {
		// The zero fact: this mapper offers no reader, so nobody looked. A
		// reference that locates nothing is not evidence, and "could not
		// determine" is not what happened.
		return model.Fact[string]{}
	}
	return reader.Environment(change)
}

// defersTo returns the addresses whose judgement answers for this resource.
//
// A control resource's meaning belongs to the subject it governs, and so does a
// subject's when it reaches no verdict of its own. Recording which is what
// makes "it was judged through something else" a claim that can be checked
// rather than believed — and a resource governing something that is not in this
// plan defers to nobody.
func defersTo(change terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange,
	mapper Mapper) []string {

	var subjects []string
	for _, candidate := range related {
		// A control is not a subject. Two controls correlated through the
		// bucket they both name would otherwise vouch for each other, and the
		// question of whether anything judged them would never be answered.
		if mapper.IsSubject(candidate.Type) && candidate.Address != change.Address {
			subjects = append(subjects, candidate.Address)
		}
	}

	if governor, ok := mapper.(Governor); ok {
		for _, address := range governor.Governs(change, scope) {
			if address != change.Address {
				subjects = append(subjects, address)
			}
		}
	}

	slices.Sort(subjects)
	return slices.Compact(subjects)
}

// relate groups changes joined by a configuration reference, in both
// directions and instance by instance.
//
// Direction is not a property of the relationship, only of how a particular
// provider happens to write it. An S3 public access block names its bucket,
// while an Azure container names the storage account that gates it — the same
// control relationship, pointing opposite ways.
//
// Instances matter just as much. A reference targets a configuration address,
// which every instance of a repeated resource shares, so matching on it alone
// hands one bucket's public access block to its sibling. Two resources are
// related only when their instance keys agree as far as both have them.
func relate(changes []terraformplan.ResourceChange, mappers []Mapper) (map[string][]terraformplan.ResourceChange, map[string]bool) {
	byConfigAddress := map[string][]terraformplan.ResourceChange{}
	for _, change := range changes {
		address := change.ConfigAddress()
		byConfigAddress[address] = append(byConfigAddress[address], change)
	}

	edges := map[string][]terraformplan.ResourceChange{}
	unresolved := map[string]bool{}
	for _, change := range changes {
		for _, reference := range change.References {
			candidates := byConfigAddress[reference.Target]
			for _, target := range candidates {
				if !governs(change, target, reference, mappers) {
					continue
				}
				switch relates(change, target, reference, len(candidates)) {
				case relationUndecidable:
					// The reference reaches this target but cannot say which
					// instance of it. Recording that is what keeps the
					// resulting UNKNOWN actionable: the reader has something
					// to change.
					unresolved[change.Address] = true
					unresolved[target.Address] = true
				case relationBinds:
					edges[change.Address] = append(edges[change.Address], target)
					edges[target.Address] = append(edges[target.Address], change)
				}
			}
		}
	}

	for address, list := range edges {
		slices.SortStableFunc(list, func(a, b terraformplan.ResourceChange) int {
			return strings.Compare(a.Address, b.Address)
		})
		edges[address] = slices.CompactFunc(list, func(a, b terraformplan.ResourceChange) bool {
			return a.Address == b.Address
		})
	}
	return edges, unresolved
}

// Binder is implemented by a mapper that declares governance relations between
// its resource types.
//
// A mapper that implements it and declares nothing for a type is saying that
// the type makes no governance claims — a subject in its own right, or a
// control scoped to something that is not a resource. That is a statement, not
// a silence, and it is why a type this build understands cannot acquire a
// relation by accident.
type Binder interface {
	// Bindings returns every governance relation this mapper declares.
	Bindings() []declared.Binding
}

// orderingAttribute is the meta-argument Terraform writes an explicit ordering
// dependency under. No binding names it, so nothing has to exclude it.
const orderingAttribute = "depends_on"

// governs reports whether a reference is a claim about what controls what,
// rather than merely a mention of one resource by another.
//
// A mention is not a relation. An ordering dependency sequences two resources
// and says nothing about governance; a policy document interpolating a bucket's
// ARN names that bucket without being applied to it; and a bucket tagged with
// another resource's name names it without being governed by it. Each of those
// was read as a correlation at some point, and each produced a public bucket
// reported as provably private.
//
// The test is whether some mapper declares this exact relation: this type,
// through this argument, to that type. A relation nobody declared is not one.
func governs(from, to terraformplan.ResourceChange,
	reference terraformplan.ExpressionReference, mappers []Mapper) bool {

	spoken, declared := declarationsFor(from.Type, mappers)
	if !spoken {
		// No mapper has said anything about what this type's references mean,
		// so this build has no grounds to judge them. Every argument is
		// admitted, because narrowing what is not understood would drop
		// correlations it cannot reason about either way — except an ordering
		// dependency, which is sequencing whoever wrote it.
		return reference.Attribute != orderingAttribute
	}

	// Both ends of the relation are checked, and both matter. An earlier
	// comment here claimed neither was observable, reasoning that every mapper
	// re-filters its related set by type. That misses the case where both ends
	// are the declared To type — two buckets, one naming the other through the
	// very argument all four AWS relations name — and the case where the
	// claimed type belongs to another cloud entirely. Both admit an edge that
	// reaches the undecidability record, which tells a reader their plan
	// leaves a correlation open between resources the configuration never
	// related.
	var declaredBetween bool
	for _, binding := range declared {
		if binding.To != to.Type {
			continue
		}
		declaredBetween = true
		if binding.Attribute == reference.Attribute {
			return true
		}
	}

	// A control repeated over the resources it governs names them only in a
	// meta-argument: its own arguments refer to each.value, which names
	// nothing. The meta-argument carries a binding declared between these two
	// types; it does not create one that was not.
	return declaredBetween && isMetaArgument(reference.Attribute)
}

// isMetaArgument reports the arguments Terraform repeats a resource with, which
// internal/terraformplan records references under for that reason.
func isMetaArgument(attribute string) bool {
	return attribute == "for_each" || attribute == "count"
}

// declarationsFor returns the relations declared from a type, and whether any
// mapper has spoken about that type at all.
//
// The two answers are kept apart deliberately, and keeping them apart is the
// point of this design. "No mapper describes this type" licenses admitting
// every argument; "a mapper describes it and declares no relation from it"
// forbids every argument, because the mapper has said the type makes no
// governance claims. Storing both as one empty value is what let a bucket's own
// tag stand as a claim about the block that governs it.
func declarationsFor(resourceType string, mappers []Mapper) (bool, []declared.Binding) {
	var spoken bool
	var relations []declared.Binding

	for _, mapper := range mappers {
		if !mapper.Interprets(resourceType) {
			continue
		}
		binder, ok := mapper.(Binder)
		if !ok {
			// The mapper understands the type but has not declared how it
			// relates to anything. Silence is not a statement.
			continue
		}
		spoken = true
		for _, binding := range binder.Bindings() {
			// Filtering by From here and by To at the call site checks both
			// ends of the relation. Both are observable, and both have tests.
			if binding.From == resourceType {
				relations = append(relations, binding)
			}
		}
	}
	return spoken, relations
}

// relation is what a reference establishes about one candidate target. Not
// reaching a target and reaching it without being able to say which instance
// was meant are different facts, and only the second is worth reporting: the
// first is the configuration answering, the second is the configuration
// declining to.
type relation int

const (
	// relationNone: the reference does not reach this target at all.
	relationNone relation = iota
	// relationBinds: the configuration says this target is the one meant.
	relationBinds
	// relationUndecidable: the reference reaches this target, but which
	// instance of it cannot be derived from the plan.
	relationUndecidable
)

// relates reports whether a reference actually joins these two changes.
//
// The rule is exact where the plan is exact, and declines to guess where it is
// not. A reference naming an instance — aws_s3_bucket.b["a"] — joins that
// instance and no other. A bare reference joins by position, but only where
// position means something: either the target has a single instance, so there
// is nothing to choose between, or the referring resource is repeated at least
// as deeply as its target and the two were written to pair up, which is what
// "for_each = aws_s3_bucket.b" says.
//
// Pairing repeated resources by position is not decidable from a plan, so it is
// not attempted.
//
// The configuration block records which values take part in an expression,
// never how they are combined, and a string literal is not a value that takes
// part. So "b[each.key]" and "b[each.key == \"a\" ? \"z\" : \"a\"]" emit an
// identical reference list, as do "for_each = aws_s3_bucket.b" and a
// comprehension over it that permutes the keys. One pairs instance to instance
// and the other pairs every control with its sibling's bucket, and nothing in
// the plan tells them apart.
//
// What remains is what the plan does state: a reference that names an instance
// outright, a target with a single instance, and the module keys two resources
// share by sitting in the same module instance. Everything else is a question
// the plan leaves open, and CLAUDE.md is explicit about what to do with those.
func relates(from, to terraformplan.ResourceChange, reference terraformplan.ExpressionReference, candidates int) relation {
	if !sameInstance(from, to) {
		return relationNone
	}
	if len(reference.TargetKeys) > 0 {
		// A reference that names an instance has answered, both about the
		// instance it names and about the ones it excludes.
		if namesInstance(to, reference.TargetKeys) {
			return relationBinds
		}
		return relationNone
	}
	if candidates == 1 && !to.DeclaredRepeated {
		// One instance and one declared, so there is nothing to choose
		// between. A repeated resource with a single instance in the plan is
		// not the same thing: the reference may have meant one that is absent.
		return relationBinds
	}
	if len(from.InstanceKeys()) < len(to.InstanceKeys()) {
		// The target is repeated more deeply than the resource referring to
		// it, so the reference cannot carry enough keys to reach one instance.
		return relationUndecidable
	}
	// A target repeated in its own right needs the reference to say which
	// instance is meant. Repetition that comes only from an enclosing module is
	// different: those keys are shared by everything in the module instance and
	// cannot disagree.
	if hasOwnKey(to) {
		return relationUndecidable
	}
	return relationBinds
}

// hasOwnKey reports whether a resource is repeated in its own right, as opposed
// to sitting inside a repeated module. Only the first needs a reference to say
// which instance is meant: module keys are shared by everything in the module
// instance, so they cannot disagree.
func hasOwnKey(change terraformplan.ResourceChange) bool {
	return len(change.InstanceKeys()) > len(change.ModuleKeys())
}

// sameInstance reports whether two changes sit in the same repetition of their
// enclosing modules and, where both are repeated, the same repetition of
// themselves.
//
// Keys are compared as far as both have them, so an unrepeated control still
// pairs with a repeated bucket — a real shape — while two instances of one
// module never see into each other.
func sameInstance(a, b terraformplan.ResourceChange) bool {
	left, right := a.InstanceKeys(), b.InstanceKeys()
	for i := 0; i < len(left) && i < len(right); i++ {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

// namesInstance reports whether a change is the instance a keyed reference
// names. The reference is written inside some module, so its keys describe the
// end of the address rather than the whole of it.
func namesInstance(change terraformplan.ResourceChange, keys []string) bool {
	actual := change.InstanceKeys()
	if len(actual) < len(keys) {
		return false
	}
	trailing := actual[len(actual)-len(keys):]
	for i := range keys {
		if trailing[i] != keys[i] {
			return false
		}
	}
	return true
}
