package declared

import "github.com/mtlabs-eng/infraproof/internal/terraformplan"

// Unwritten reports that the configuration declares this resource and does not
// write the argument, so the provider's documented default is what the value
// will be.
//
// It exists because an Optional and Computed attribute is emitted as unknown in
// two opposite situations. The author left it out, and the provider's default
// applies -- the overwhelmingly common case, since that is what Optional means.
// Or the author set it from something the plan cannot resolve yet, and no default
// applies to a value somebody did write. The plan gives both the same shape.
//
// Treating every such unknown as unreadable answers UNKNOWN for the ordinary
// case, which is what made every `google_compute_firewall` that does not spell
// out `direction = "INGRESS"` undeterminable on a real plan. Treating every one
// as the default invents a value for the interpolated case, which this project
// forbids.
//
// False when the plan carries no configuration for the resource. A sanitized
// plan does not record what the author wrote, and silence nobody recorded is not
// evidence of an omission -- so the caller keeps whatever it does for a value it
// cannot read.
func Unwritten(change terraformplan.ResourceChange, attribute string) bool {
	return change.Configured && !change.States(attribute)
}

// Written reports that the configuration states the argument.
//
// The positive form of the question, and the only direction that is reliable for
// an attribute a provider models as a block. Terraform's configuration block does
// not represent a `dynamic` block in a resource's arguments, so an argument's
// absence from Stated does not prove nothing writes it -- but its presence does
// prove the author wrote it, because block syntax and attribute syntax cannot
// both name one attribute.
//
// That asymmetry is why closure is decided with this and the default-applying
// guard is decided with Unwritten. Reading an absence as "the author wrote no
// inline rules" would let a rule set written as a dynamic block be reported as a
// stated absence.
func Written(change terraformplan.ResourceChange, attribute string) bool {
	return change.Configured && change.States(attribute)
}
