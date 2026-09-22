// Package azure interprets Azure Blob Storage resources.
//
// Public access on Azure is a conjunction of two resources: the storage account
// has to allow anonymous blob access at all, and the container has to be set to
// blob or container level access. Either one alone settles nothing, and the
// account is frequently managed outside the plan that creates the container.
package azure

import (
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeAccount   = "azurerm_storage_account"
	typeContainer = "azurerm_storage_container"

	attrAllowPublic  = "allow_nested_items_to_be_public"
	attrAccessType   = "container_access_type"
	accessTypePublic = "blob"
	accessTypeList   = "container"
)

// Mapper normalizes Azure blob containers.
type Mapper struct{}

// Cloud identifies the cloud this mapper interprets.
func (Mapper) Cloud() model.Cloud { return model.CloudAzure }

// Interprets reports the resource types this mapper understands.
func (Mapper) Interprets(resourceType string) bool {
	return resourceType == typeAccount || resourceType == typeContainer
}

// IsSubject reports that a container is exposed, and so is an account whose
// containers this plan does not contain — otherwise an account opened up for
// anonymous access would be reported nowhere at all.
func (Mapper) IsSubject(resourceType string) bool {
	return resourceType == typeContainer || resourceType == typeAccount
}

// attrTags is where Azure carries user-supplied labels.
const attrTags = "tags"

// Map normalizes a container together with the account that gates it, or an
// account that has no container here to speak for it.
func (m Mapper) Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource {
	resource := model.NormalizedResource{
		Address:     subject.Address,
		Provider:    subject.ProviderName,
		Cloud:       model.CloudAzure,
		Family:      model.FamilyObjectStorage,
		Destructive: subject.IsDestructive(),
		Environment: declared.Environment(subject, attrTags, model.CloudAzure),
	}

	if subject.Type == typeAccount {
		resource.ObjectStorage = accountCapabilities(subject, related)
		return resource
	}

	account, ambiguous := findType(related, typeAccount)
	capabilities := model.ObjectStorageCapabilities{
		PublicAccess: publicAccess(subject, account),
	}
	switch {
	case ambiguous:
		// Both accounts are in the plan. Telling the reader to add one would
		// send them to do the thing they have already done twice.
		capabilities.Unresolved = []model.MissingControl{{
			CheckID: "AZURE_STORAGE_ACCOUNT_AMBIGUOUS",
			Reason:  "This container names more than one storage account, and which of them gates anonymous access is not stated.",
			Cloud:   model.CloudAzure,
		}}
	case account == nil:
		capabilities.Unresolved = []model.MissingControl{{
			CheckID: "AZURE_STORAGE_ACCOUNT_NOT_IN_PLAN",
			Reason:  "The storage account gating anonymous access is not part of this plan.",
			Cloud:   model.CloudAzure,
		}}
	}
	resource.ObjectStorage = &capabilities
	return resource
}

// accountCapabilities describes an account in its own right.
//
// With a container in the plan, the container carries the verdict and the
// account defers; reporting both would say the same thing twice. Without one,
// the account is the only thing there is to report, and an account permitting
// anonymous access is not a conclusion that nothing is exposed.
func accountCapabilities(account terraformplan.ResourceChange, related []terraformplan.ResourceChange) *model.ObjectStorageCapabilities {
	// Whether any container is here is an existence question. findType declines
	// to choose between two accounts, which is right, but applying that rule to
	// counting containers made an account with two of them claim that none was
	// in the plan.
	if hasType(related, typeContainer) {
		return nil
	}

	gate, sources := accountAllowsPublic(&account)
	if gate == answerNo {
		return &model.ObjectStorageCapabilities{PublicAccess: model.Known(false, sources...).Canonical()}
	}

	capabilities := &model.ObjectStorageCapabilities{
		Unresolved: []model.MissingControl{{
			CheckID: "AZURE_CONTAINER_NOT_IN_PLAN",
			Reason:  "This storage account permits anonymous access and no container of it is part of this plan.",
			Cloud:   model.CloudAzure,
		}},
	}
	if gate == answerRedacted {
		capabilities.PublicAccess = model.Redacted[bool](sources...).Canonical()
	} else {
		capabilities.PublicAccess = model.Unknown[bool](sources...).Canonical()
	}
	return capabilities
}

// answer keeps "no" apart from "cannot tell" and from "the source was
// sensitive".
type answer int

const (
	answerNo answer = iota
	answerYes
	answerUnknown
	answerRedacted
)

// publicAccess decides whether the change grants anonymous access to the
// container. Both the account gate and the container setting must say yes, and
// either saying no is enough to prove it does not.
func publicAccess(container terraformplan.ResourceChange, account *terraformplan.ResourceChange) model.Fact[bool] {
	gate, gateSources := accountAllowsPublic(account)
	setting, settingSources := containerIsPublic(container)

	sources := append(gateSources, settingSources...)

	// One definite no settles it, whatever the other says.
	if gate == answerNo {
		return model.Known(false, gateSources...).Canonical()
	}
	if setting == answerNo {
		return model.Known(false, settingSources...).Canonical()
	}
	if gate == answerYes && setting == answerYes {
		return model.Known(true, sources...).Canonical()
	}

	if gate == answerRedacted || setting == answerRedacted {
		return model.Redacted[bool](sources...).Canonical()
	}
	return model.Unknown[bool](sources...).Canonical()
}

// accountAllowsPublic reads the account-level gate. An account this plan does
// not contain is not an account that permits nothing; it is an account nobody
// here can see.
func accountAllowsPublic(account *terraformplan.ResourceChange) (answer, []model.Provenance) {
	if account == nil {
		return answerUnknown, nil
	}

	sources := []model.Provenance{provenance(account.Address, attrAllowPublic)}
	value := account.After.Field(attrAllowPublic)
	switch {
	case value.Kind() == terraformplan.KindBool:
		if value.Bool() {
			return answerYes, sources
		}
		return answerNo, sources
	case value.State() == terraformplan.StateRedacted:
		return answerRedacted, sources
	default:
		// Absent is not the provider default, and a readable value of the wrong
		// kind is not an answer either: Bool returns false for both, and false
		// here is what proves a container private.
		return answerUnknown, sources
	}
}

// containerIsPublic reads the container's access level. blob exposes the blobs;
// container additionally exposes the listing.
func containerIsPublic(container terraformplan.ResourceChange) (answer, []model.Provenance) {
	sources := []model.Provenance{provenance(container.Address, attrAccessType)}

	value := container.After.Field(attrAccessType)
	switch {
	case value.Kind() == terraformplan.KindString:
		if value.Text() == accessTypePublic || value.Text() == accessTypeList {
			return answerYes, sources
		}
		return answerNo, sources
	case value.State() == terraformplan.StateRedacted:
		return answerRedacted, sources
	default:
		return answerUnknown, sources
	}
}

// hasType reports whether any resource of a kind is attached.
func hasType(changes []terraformplan.ResourceChange, resourceType string) bool {
	for i := range changes {
		if changes[i].Type == resourceType {
			return true
		}
	}
	return false
}

// findType returns the single resource of a kind attached to a subject, and
// reports whether there was more than one. Two storage accounts gating one
// container is a contradiction, and choosing between them would state a
// determination the plan does not support. Both degrade to UNKNOWN, but they
// are different gaps and a reader can only act on the one they are told about.
func findType(changes []terraformplan.ResourceChange, resourceType string) (*terraformplan.ResourceChange, bool) {
	var found *terraformplan.ResourceChange
	for i := range changes {
		if changes[i].Type != resourceType {
			continue
		}
		if found != nil {
			return nil, true
		}
		found = &changes[i]
	}
	return found, false
}

func provenance(address, attribute string) model.Provenance {
	return model.Provenance{ResourceAddress: address, AttributePath: attribute, Cloud: model.CloudAzure}
}

// Bindings declares that a container is placed in an account, and how.
//
// The provider accepts either the account's resource id or its name, and a
// container carries one of them; both are the application, so both are
// declared. An account declares nothing: containers name it, not the reverse.
func (Mapper) Bindings() []declared.Binding {
	return []declared.Binding{
		{From: typeContainer, Attribute: "storage_account_id", To: typeAccount},
		{From: typeContainer, Attribute: "storage_account_name", To: typeAccount},
	}
}

// Environment reads a resource's declared environment with this provider's
// vocabulary, so a control resource is asked the same question as a subject.
func (m Mapper) Environment(change terraformplan.ResourceChange) model.Fact[string] {
	return declared.Environment(change, attrTags, model.CloudAzure)
}
