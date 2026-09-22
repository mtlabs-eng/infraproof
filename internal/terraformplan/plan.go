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
	// ActionForget means the object is dropped from state and left alone,
	// which a "removed" block asks for. It is not destruction: the object
	// survives the change, and only Terraform's record of it does not.
	ActionForget Action = "forget"
)

// Valid reports whether a is an action this build recognizes. An unrecognized
// action is carried through rather than rejected, because Terraform documents
// that new action combinations may appear; a policy layer must refuse to
// conclude rather than treat an unfamiliar action as safe.
func (a Action) Valid() bool {
	switch a {
	case ActionNoOp, ActionCreate, ActionRead, ActionUpdate, ActionDelete, ActionForget:
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
	// DeclaredRepeated reports that the configuration declares this resource
	// with count or for_each, whether or not every instance reached the plan.
	//
	// It says something the surviving instances cannot: a plan holding one
	// instance of a repeated resource looks unambiguous by count and is not,
	// because a reference naming no instance may have meant one that is absent.
	DeclaredRepeated bool
	// References are the resources this resource's configuration refers to, in
	// deterministic order. They are the only dependable link between a resource
	// and the resources that control it: an attribute holding another
	// resource's id is unknown until apply, so matching on values would fail
	// exactly where correlation matters. Empty when the plan carries no
	// configuration block.
	References []ExpressionReference
	// ImportID is the import ID when this change imports an existing object.
	ImportID string
}

// ExpressionReference is one resource named by another resource's
// configuration.
type ExpressionReference struct {
	// Attribute is the configuration argument holding the reference, such as
	// "bucket". It is what makes a correlation explainable to a reader.
	Attribute string
	// Target is the referenced resource's address, module-qualified and without
	// count or for_each keys, matching the form the configuration block uses.
	Target string
	// TargetKeys are the count or for_each keys the reference named, or nil
	// when it named the resource as a whole.
	//
	// Terraform writes both forms: an argument holding another instance's id
	// produces the keyed reference and the bare one side by side, while a
	// meta-argument such as "for_each = aws_s3_bucket.b" produces only the
	// bare form. The difference is the only thing separating one instance's
	// controls from its sibling's, so it is kept rather than normalized away.
	TargetKeys []string
}

// ConfigAddress returns the address as the configuration block spells it:
// module-qualified, without count or for_each keys. It is the form an
// ExpressionReference targets, so correlating a resource with the resources
// that refer to it means comparing this against ExpressionReference.Target.
//
// Every instance of a counted resource shares one configuration address, which
// is what lets all of them correlate to the same referenced resource.
func (c ResourceChange) ConfigAddress() string {
	return stripIndexKeys(c.Address)
}

// ModuleKeys returns the repetition keys of the modules containing this
// resource.
//
// They are structural: everything inside module.m["eu"] shares that key, and a
// resource there can only refer to resources there. Pairing on a module key
// therefore asserts nothing. A resource's own key is different — each resource
// chooses its own for_each independently, so pairing on it is an assumption
// that needs evidence.
func (c ResourceChange) ModuleKeys() []string {
	return indexKeys(c.ModuleAddress)
}

// InstanceKeys returns the count and for_each keys along the address, outermost
// first, with quotes removed. A resource with no repetition anywhere returns
// nil.
//
// ConfigAddress deliberately discards these so that an address can be matched
// against the configuration block, which has none. Correlation then needs them
// back: every instance of a repeated resource shares one configuration address,
// so without the keys one instance's controls are indistinguishable from
// another's.
func (c ResourceChange) InstanceKeys() []string {
	return indexKeys(c.Address)
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

// HasUnrecognizedAction reports that the change names an operation this build
// does not know.
//
// It matters because IsDestructive asks whether "delete" is among the actions,
// so an unfamiliar verb reads as a change that destroys nothing — and a
// contract forbidding destruction passed one. What the verb means is
// Terraform's to say and not this program's to guess, so a caller must refuse
// to conclude rather than treat it as safe. The parser carries it rather than
// rejecting the plan, because a plan using a feature this build has not learned
// is still a plan, and the rest of it is still worth reading.
func (c ResourceChange) HasUnrecognizedAction() bool {
	for _, action := range c.Actions {
		if !action.Valid() {
			return true
		}
	}
	return false
}

// CreateBeforeDestroy reports the replacement ordering in which the new object
// is created first. It is a materially different risk from the default
// ordering, so the two must stay distinguishable.
func (c ResourceChange) CreateBeforeDestroy() bool {
	return len(c.Actions) == 2 && c.Actions[0] == ActionCreate && c.Actions[1] == ActionDelete
}
