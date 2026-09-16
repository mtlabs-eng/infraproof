// Package azure interprets Azure Blob Storage resources.
//
// Public access on Azure is a conjunction of two resources: the storage account
// has to allow anonymous blob access at all, and the container has to be set to
// blob or container level access. Either one alone settles nothing, and the
// account is frequently managed outside the plan that creates the container.
package azure

import (
	"github.com/mtlabs-eng/infraproof/internal/model"
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

// IsSubject reports that the container is the thing exposed, not the account.
func (Mapper) IsSubject(resourceType string) bool { return resourceType == typeContainer }

// Map normalizes a container together with the account that gates it.
func (m Mapper) Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource {
	account := findType(related, typeAccount)

	capabilities := model.ObjectStorageCapabilities{
		PublicAccess: publicAccess(subject, account),
	}
	if account == nil {
		capabilities.Unresolved = []model.MissingControl{{
			CheckID: "AZURE_STORAGE_ACCOUNT_NOT_IN_PLAN",
			Reason:  "The storage account gating anonymous access is not part of this plan.",
			Cloud:   model.CloudAzure,
		}}
	}

	return model.NormalizedResource{
		Address:       subject.Address,
		Provider:      subject.ProviderName,
		Cloud:         model.CloudAzure,
		Family:        model.FamilyObjectStorage,
		Destructive:   subject.IsDestructive(),
		ObjectStorage: &capabilities,
	}
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
	switch value.State() {
	case terraformplan.StateKnown:
		if value.Bool() {
			return answerYes, sources
		}
		return answerNo, sources
	case terraformplan.StateRedacted:
		return answerRedacted, sources
	default:
		// Absent is not the provider default. The default happens to be safe,
		// but reading absence as a value is exactly the mistake this model
		// exists to prevent.
		return answerUnknown, sources
	}
}

// containerIsPublic reads the container's access level. blob exposes the blobs;
// container additionally exposes the listing.
func containerIsPublic(container terraformplan.ResourceChange) (answer, []model.Provenance) {
	sources := []model.Provenance{provenance(container.Address, attrAccessType)}

	value := container.After.Field(attrAccessType)
	switch value.State() {
	case terraformplan.StateKnown:
		if value.Text() == accessTypePublic || value.Text() == accessTypeList {
			return answerYes, sources
		}
		return answerNo, sources
	case terraformplan.StateRedacted:
		return answerRedacted, sources
	default:
		return answerUnknown, sources
	}
}

func findType(changes []terraformplan.ResourceChange, resourceType string) *terraformplan.ResourceChange {
	for i := range changes {
		if changes[i].Type == resourceType {
			return &changes[i]
		}
	}
	return nil
}

func provenance(address, attribute string) model.Provenance {
	return model.Provenance{ResourceAddress: address, AttributePath: attribute, Cloud: model.CloudAzure}
}
