package providers

import (
	"github.com/mtlabs-eng/infraproof/internal/providers/aws"
	"github.com/mtlabs-eng/infraproof/internal/providers/azure"
	"github.com/mtlabs-eng/infraproof/internal/providers/gcp"
)

// Default returns the mappers this build ships.
//
// This is the only place that names a cloud. Adding one is an entry here and a
// new subpackage; no rule, no correlation and no model type changes.
func Default() []Mapper {
	return []Mapper{aws.Mapper{}, azure.Mapper{}, gcp.Mapper{}}
}
