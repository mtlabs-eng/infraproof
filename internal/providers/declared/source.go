package declared

import (
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// Source locates a value a mapper read, and records whether the located value
// was one it was permitted to read.
//
// The Evidence Bundle defines that flag as the located value being sensitive,
// and it is per reference rather than per fact: a fact is redacted if any one
// of its sources was, so deriving the flag from the fact marks values the
// mapper plainly read. The mirror of that mistake is deriving it from the
// state, which marks a value Terraform has not computed yet — not a secret, and
// a report claiming otherwise is describing a plan that does not exist.
//
// Sensitivity is asked of everything at the location rather than of the
// outermost node, because a list whose entries are marked individually is
// itself readable and the reference points at the list.
//
// Three mappers had a copy of this. They agreed, which is the only reason the
// defect was one defect rather than three.
func Source(cloud model.Cloud, address, attribute string, value terraformplan.Value) model.Provenance {
	return model.Provenance{
		ResourceAddress: address,
		AttributePath:   attribute,
		Cloud:           cloud,
		Withheld:        value.HoldsSensitive(),
	}
}
