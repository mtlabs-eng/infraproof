// Package gcp interprets Google Cloud Storage resources.
//
// A bucket is public when an IAM binding names allUsers or
// allAuthenticatedUsers and public access prevention does not stop it. The
// catch is the default: public_access_prevention is "inherited", which the
// provider documents as taking effect only if an organization policy constraint
// applies — and that constraint is never in a plan. So "enforced" proves a
// bucket is private, while "inherited" proves nothing either way.
package gcp

import (
	"encoding/json"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeBucket     = "google_storage_bucket"
	typeIAMMember  = "google_storage_bucket_iam_member"
	typeIAMBinding = "google_storage_bucket_iam_binding"
	typeIAMPolicy  = "google_storage_bucket_iam_policy"

	attrPrevention = "public_access_prevention"
	preventionOn   = "enforced"
)

// everyone holds the two IAM principals that mean "anyone".
// allAuthenticatedUsers is any Google account at all, which is public in every
// sense that matters.
var everyone = map[string]bool{"allUsers": true, "allAuthenticatedUsers": true}

// Mapper normalizes Cloud Storage buckets.
type Mapper struct{}

// Cloud identifies the cloud this mapper interprets.
func (Mapper) Cloud() model.Cloud { return model.CloudGCP }

// Interprets reports the resource types this mapper understands.
func (Mapper) Interprets(resourceType string) bool {
	switch resourceType {
	case typeBucket, typeIAMMember, typeIAMBinding, typeIAMPolicy, typeFirewall,
		typeSQLInstance:
		return true
	}
	return false
}

// IsSubject reports the resources normalized in their own right: a bucket, and a
// firewall, which on this cloud is a rule and a subject at once.
func (Mapper) IsSubject(resourceType string) bool {
	switch resourceType {
	case typeBucket, typeFirewall, typeSQLInstance:
		return true
	}
	return false
}

// FamilyOf names the family a resource type belongs to.
//
// The normalizer asks because a control resource cannot be placed by what Map
// returned: an IAM member is placed by the bucket it names, and a firewall rule
// by the network it is on. Assuming one family was invisible until a second one
// existed, which is what this milestone added.
func (Mapper) FamilyOf(resourceType string) model.Family {
	switch resourceType {
	case typeBucket, typeIAMMember, typeIAMBinding, typeIAMPolicy:
		return model.FamilyObjectStorage
	case typeFirewall:
		return model.FamilyNetwork
	case typeSQLInstance:
		return model.FamilyDatabase
	default:
		return model.FamilyUnknown
	}
}

// The questions this mapper answers about a bucket. Prevention is read from the
// bucket itself, so the subject answers for it and nothing else can.
const (
	roleIAMGrant   = "iam_grant"
	rolePrevention = attrPrevention
)

// RoleOf names the question a resource would answer about a bucket.
func (Mapper) RoleOf(subject, candidate terraformplan.ResourceChange) string {
	if subject.Type != typeBucket {
		return ""
	}
	switch candidate.Type {
	case typeBucket:
		return rolePrevention
	case typeIAMMember, typeIAMBinding, typeIAMPolicy:
		return roleIAMGrant
	}
	return ""
}

// attrLabels is where GCP carries user-supplied labels; the other two clouds
// call the same thing tags.
const attrLabels = "labels"

// Map normalizes a bucket together with the IAM resources bound to it.
func (m Mapper) Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource {
	if subject.Type == typeSQLInstance {
		return m.database(subject)
	}
	if subject.Type == typeFirewall {
		return m.firewall(subject, scope)
	}

	prevention, preventionSources := preventionState(subject)

	capabilities := model.ObjectStorageCapabilities{
		PublicAccess: publicAccess(prevention, preventionSources, related),
	}
	if prevention != answerYes {
		capabilities.Unresolved = []model.MissingControl{{
			CheckID: "GCP_ORGANIZATION_PUBLIC_ACCESS_POLICY",
			Reason:  "Public access prevention is inherited, and the organization policy it inherits from is not part of this plan.",
			Cloud:   model.CloudGCP,
		}}
	}

	return model.NormalizedResource{
		Address:       subject.Address,
		Provider:      subject.ProviderName,
		Cloud:         model.CloudGCP,
		Family:        model.FamilyObjectStorage,
		Destructive:   subject.IsDestructive(),
		Environment:   declared.Environment(subject, attrLabels, model.CloudGCP),
		ObjectStorage: &capabilities,
	}
}

type answer int

const (
	answerNo answer = iota
	answerYes
	answerUnknown
	answerRedacted
)

// publicAccess decides whether the change grants public access to the bucket.
func publicAccess(prevention answer, preventionSources []model.Provenance,
	related []terraformplan.ResourceChange) model.Fact[bool] {

	// Enforced prevention settles it, whatever the bindings say — which is why
	// a plan granting allUsers alongside enforced prevention is not public.
	if prevention == answerYes {
		return model.Known(false, preventionSources...).Canonical()
	}

	grant, grantSources := publicBinding(related)
	sources := append(preventionSources, grantSources...)

	switch grant {
	case answerYes:
		return model.Known(true, grantSources...).Canonical()
	case answerRedacted:
		return model.Redacted[bool](sources...).Canonical()
	case answerUnknown:
		return model.Unknown[bool](sources...).Canonical()
	}

	// No public binding in this plan, and prevention is not enforced. A binding
	// made outside this change could still expose the bucket, and nothing here
	// would stop it.
	if prevention == answerRedacted {
		return model.Redacted[bool](sources...).Canonical()
	}
	return model.Unknown[bool](sources...).Canonical()
}

// preventionState reads public_access_prevention. Only "enforced" proves
// anything: "inherited" defers to an organization policy this plan cannot see.
func preventionState(bucket terraformplan.ResourceChange) (answer, []model.Provenance) {
	sources := []model.Provenance{declared.Source(model.CloudGCP, bucket.Address, attrPrevention, bucket.After.Field(attrPrevention))}

	value := bucket.After.Field(attrPrevention)
	switch value.State() {
	case terraformplan.StateKnown:
		if value.Text() == preventionOn {
			return answerYes, sources
		}
		return answerNo, sources
	case terraformplan.StateRedacted:
		return answerRedacted, sources
	default:
		return answerUnknown, sources
	}
}

// publicBinding reports whether any related IAM resource names everyone.
func publicBinding(related []terraformplan.ResourceChange) (answer, []model.Provenance) {
	var sources []model.Provenance
	result := answerNo

	escalate := func(candidate answer) {
		if candidate == answerYes || result == answerNo ||
			(candidate == answerRedacted && result == answerUnknown) {
			result = candidate
		}
	}

	for _, change := range related {
		switch change.Type {
		case typeIAMMember:
			sources = append(sources, declared.Source(model.CloudGCP, change.Address, "member", change.After.Field("member")))
			escalate(memberIsEveryone(change.After.Field("member")))
		case typeIAMBinding:
			sources = append(sources, declared.Source(model.CloudGCP, change.Address, "members", change.After.Field("members")))
			escalate(membersIncludeEveryone(change.After.Field("members")))
		case typeIAMPolicy:
			sources = append(sources, declared.Source(model.CloudGCP, change.Address, "policy_data", change.After.Field("policy_data")))
			escalate(policyDataGrantsPublic(change.After.Field("policy_data")))
		}
	}
	return result, sources
}

func memberIsEveryone(value terraformplan.Value) answer {
	switch value.State() {
	case terraformplan.StateKnown:
		if everyone[value.Text()] {
			return answerYes
		}
		return answerNo
	case terraformplan.StateRedacted:
		return answerRedacted
	default:
		return answerUnknown
	}
}

func membersIncludeEveryone(value terraformplan.Value) answer {
	if value.State() != terraformplan.StateKnown || value.Kind() != terraformplan.KindArray {
		return unreadable(value)
	}

	result := answerNo
	for i := range value.Len() {
		switch member := value.At(i); member.State() {
		case terraformplan.StateKnown:
			if everyone[member.Text()] {
				return answerYes
			}
		case terraformplan.StateRedacted:
			result = answerRedacted
		default:
			if result != answerRedacted {
				result = answerUnknown
			}
		}
	}
	return result
}

// policyDataGrantsPublic reads an authoritative IAM policy document. It is
// usually produced by a data source and therefore unknown at plan time.
func policyDataGrantsPublic(value terraformplan.Value) answer {
	if value.State() != terraformplan.StateKnown {
		return unreadable(value)
	}

	var document struct {
		Bindings []struct {
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal([]byte(value.Text()), &document); err != nil {
		return answerUnknown
	}
	for _, binding := range document.Bindings {
		for _, member := range binding.Members {
			if everyone[member] {
				return answerYes
			}
		}
	}
	return answerNo
}

func unreadable(value terraformplan.Value) answer {
	if value.State() == terraformplan.StateRedacted {
		return answerRedacted
	}
	return answerUnknown
}

// Bindings declares which IAM resources grant on which buckets, and through
// what.
//
// A member, a binding and a policy all carry the bucket in "bucket". A
// condition expression or an ordering dependency may name a bucket without
// granting anything on it. A bucket declares nothing.
func (Mapper) Bindings() []declared.Binding {
	var relations []declared.Binding
	for _, grant := range []string{typeIAMMember, typeIAMBinding, typeIAMPolicy} {
		relations = append(relations, declared.Binding{
			From: grant, Attribute: "bucket", To: typeBucket})
	}
	return relations
}

// Environment reads a resource's declared environment with this provider's
// vocabulary, so a control resource is asked the same question as a subject.
func (m Mapper) Environment(change terraformplan.ResourceChange) model.Fact[string] {
	return declared.Environment(change, attrLabels, model.CloudGCP)
}
