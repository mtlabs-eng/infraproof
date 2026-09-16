package terraformplan

import "slices"

// Plan is one parsed Terraform or OpenTofu plan file.
type Plan struct {
	// FormatVersion is the plan format version, such as "1.2".
	FormatVersion string
	// TerraformVersion is the version string the tool recorded. OpenTofu writes
	// its own version into the same field.
	TerraformVersion string
	// Digest is "sha256:<hex>" over the exact input bytes. It allows a report to
	// correlate with a plan file without embedding the plan, and is the only
	// field a rejected plan carries.
	Digest string
	// ResourceChanges holds every change in the plan, in input order. Nothing is
	// filtered: a resource type no mapper recognizes is still here.
	ResourceChanges []ResourceChange
	// ProviderConfigs holds the declared provider instances, keyed by provider
	// config key such as "aws.west". Empty when the plan omits its
	// configuration block, which sanitized plans often do.
	ProviderConfigs map[string]ProviderConfig
}

// ProviderConfig is one declared provider instance.
type ProviderConfig struct {
	// Key is the provider config key. Terraform writes "aws.west" for a root
	// instance and "<module_address>:<name>.<alias>" for one declared inside a
	// module, as in "module.storage.module.inner:terraform".
	Key string
	// Name is the local provider name, such as "aws".
	Name string
	// Alias is the instance alias, empty for the default instance.
	Alias string
	// FullName is the provider source address.
	FullName string
	// ModuleAddress is the module the instance is declared in, empty for root.
	ModuleAddress string
}

// Mode distinguishes a managed resource from a data source.
type Mode string

const (
	// ModeManaged is a resource Terraform creates and destroys.
	ModeManaged Mode = "managed"
	// ModeData is a data source Terraform only reads.
	ModeData Mode = "data"
)

// Action is one planned operation. Terraform expresses a replace as an ordered
// pair of delete and create rather than a single action, so that any caller
// scanning for "delete" recognizes every case in which an object goes away.
type Action string

const (
	// ActionNoOp means nothing changes.
	ActionNoOp Action = "no-op"
	// ActionCreate means the object is created.
	ActionCreate Action = "create"
	// ActionRead means a data source is read.
	ActionRead Action = "read"
	// ActionUpdate means the object is updated in place.
	ActionUpdate Action = "update"
	// ActionDelete means the object is destroyed.
	ActionDelete Action = "delete"
)

// Valid reports whether a is an action this build recognizes. An unrecognized
// action is carried through rather than rejected, because Terraform documents
// that new action combinations may appear; a policy layer must refuse to
// conclude rather than treat an unfamiliar action as safe.
func (a Action) Valid() bool {
	switch a {
	case ActionNoOp, ActionCreate, ActionRead, ActionUpdate, ActionDelete:
		return true
	}
	return false
}

// ResourceChange is one planned change, as the plan described it.
type ResourceChange struct {
	// Address is the full resource address, including any index key.
	Address string
	// ModuleAddress is the containing module, empty at the root.
	ModuleAddress string
	// Mode distinguishes managed resources from data sources.
	Mode Mode
	// Type and Name are the resource type and local name.
	Type, Name string
	// Index is the count or for_each key, rendered as text. HasIndex
	// distinguishes an absent index from an empty string key.
	Index    string
	HasIndex bool
	// ProviderName is the provider source address. It does not identify which
	// aliased instance is in use; ProviderConfigKey does.
	ProviderName string
	// ProviderConfigKey identifies the provider instance, empty when the plan
	// carries no configuration block.
	ProviderConfigKey string
	// ProviderAlias is the resolved alias, empty for the default instance.
	ProviderAlias string
	// Deposed is the deposed object key, empty for the current object.
	Deposed string
	// ActionReason is Terraform's optional explanation, such as
	// "replace_because_cannot_update". The set is open and display-only.
	ActionReason string
	// Actions are the planned operations in the order Terraform emitted them.
	// The order is meaningful and is never collapsed into a single action.
	Actions []Action
	// Before and After are the object state on each side of the change.
	Before, After Value
	// ReplacePaths are the attribute paths that forced a replacement.
	ReplacePaths [][]string
	// ImportID is the import ID when this change imports an existing object.
	ImportID string
}

// IsReplace reports whether the object is destroyed and recreated.
func (c ResourceChange) IsReplace() bool {
	return slices.Contains(c.Actions, ActionDelete) && slices.Contains(c.Actions, ActionCreate)
}

// IsDestructive reports whether the planned change destroys the existing
// object, which covers a plain delete and both replace orderings.
func (c ResourceChange) IsDestructive() bool {
	return slices.Contains(c.Actions, ActionDelete)
}

// CreateBeforeDestroy reports the replacement ordering in which the new object
// is created first. It is a materially different risk from the default
// ordering, so the two must stay distinguishable.
func (c ResourceChange) CreateBeforeDestroy() bool {
	return len(c.Actions) == 2 && c.Actions[0] == ActionCreate && c.Actions[1] == ActionDelete
}
