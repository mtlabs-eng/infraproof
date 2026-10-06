package intent

import "github.com/mtlabs-eng/infraproof/internal/model"

// SchemaVersion is the contract version this build understands. The major
// version is the compatibility boundary: a contract written against a later
// major version is rejected rather than read partially.
const SchemaVersion = "1.1"

// Contract is a Version 1 Intent Contract.
//
// Every field a rule reads is required. An omitted required field is an invalid
// contract rather than a defaulted one: a contract that did not say what it
// permits must not be read as permitting anything.
type Contract struct {
	// SchemaVersion is the contract version, such as "1.0".
	SchemaVersion string
	// ChangeID is a human-readable identifier for the change. It is not
	// authorization and carries no meaning beyond identification.
	ChangeID string
	// Environment is the target environment the change is written for.
	Environment string
	// AllowedClouds is the non-empty set of clouds the change may affect.
	AllowedClouds []string
	// DestructiveChanges is the policy for changes that destroy an object.
	DestructiveChanges DestructivePolicy
	// Resources are the declared capabilities the change is expected to have.
	Resources []ResourceIntent
	// Constraints are optional explicit restrictions. This build loads and
	// validates them but evaluates none; see Unevaluated.
	Constraints *Constraints
	// Digest is "sha256:<hex>" over the exact contract bytes, so a report can
	// identify the contract it compared against without copying it.
	Digest string
	// Source names where the contract was read from, for the bundle subject.
	Source string

	// present records which fields the file contained, so validation can tell
	// an omitted field from one written empty.
	present presence
}

// DestructivePolicy is what the contract permits for destructive changes.
type DestructivePolicy string

const (
	// DestructiveForbidden blocks any change that destroys an object.
	DestructiveForbidden DestructivePolicy = "forbidden"
	// DestructiveAllowedWithWarning permits destruction but requires a human
	// decision.
	DestructiveAllowedWithWarning DestructivePolicy = "allowed_with_warning"
)

// Valid reports whether the policy is one this build understands.
func (p DestructivePolicy) Valid() bool {
	switch p {
	case DestructiveForbidden, DestructiveAllowedWithWarning:
		return true
	default:
		return false
	}
}

// ResourceIntent is one declared resource capability.
//
// It carries no address. The contract describes what the change is for, not
// which resource implements it, and docs/INTENT-CONTRACT.md defers resource
// cardinality and scope. An entry therefore constrains every resource of its
// family: that is the only reading which does not require the cardinality the
// contract does not yet express, and it fails safe, since adding a resource to
// a plan cannot escape a declared intent.
type ResourceIntent struct {
	// Family is the resource family, such as "object_storage".
	Family string
	// Exposure is the declared exposure of the family. It belongs to
	// object_storage; the network family declares ports instead.
	Exposure Exposure
	// PublicPorts are the ports the network family may make reachable from any
	// address, parsed. It belongs to the network family and no other.
	//
	// A pointer, because presence is not length. An empty list is the most
	// restrictive thing this field can say -- no port may be public -- and an
	// omitted field is the absence of a statement, under which any public
	// ingress needs a human. Reading presence off the length collapses the two,
	// and the collapse favours the permissive reading.
	PublicPorts *[]model.PortRange
	// Purpose is an optional human note. No rule reads it.
	Purpose string
}

// Exposure is a declared exposure requirement.
type Exposure string

const (
	// ExposurePrivate requires that the change not grant public access.
	ExposurePrivate Exposure = "private"
	// ExposurePublic declares public access as intended.
	ExposurePublic Exposure = "public"
	// ExposureUnspecified is explicit uncertainty. It is not the same as an
	// omitted field, which is invalid: this one says "the author considered
	// exposure and declined to commit", and no exposure rule is applied.
	ExposureUnspecified Exposure = "unspecified"
)

// Valid reports whether the exposure is one this build understands.
func (e Exposure) Valid() bool {
	switch e {
	case ExposurePrivate, ExposurePublic, ExposureUnspecified:
		return true
	default:
		return false
	}
}

// Families this build understands. A contract naming any other family is
// invalid: silently accepting a family no rule evaluates would let a contract
// appear to constrain something nothing checks.
//
// Each declares what its own rule reads, and only that. Storage declares an
// exposure; network declares ports. An entry carrying both would be two fields
// that can contradict each other, and refusing that is cheaper than deciding
// which one wins.
const (
	FamilyObjectStorage = "object_storage"
	FamilyNetwork       = "network"
)

// Constraints are explicit restrictions the contract records.
//
// This build evaluates none of them. They are loaded and validated so that a
// malformed constraint is still rejected, and reported through Unevaluated so
// that a reader is never left believing a restriction was checked when it was
// not.
// Both fields are pointers, like every optional field in the document they are
// loaded from. Presence is not length: an empty allow-list is the most
// restrictive thing the field can say — no region is permitted — and reading
// presence off the length reported a stated restriction as absent, which is the
// one case this type exists to prevent. Carrying the distinction in the type
// rather than beside it is what keeps a contract from stating a constraint that
// Unevaluated does not report.
type Constraints struct {
	// AllowedRegions restricts the regions the change may affect.
	AllowedRegions *[]string
	// RequiredTags are tags every affected resource must carry.
	RequiredTags *map[string]string
}

// Unevaluated names the contract fields this build loaded but did not evaluate,
// in deterministic order. It is empty when the contract asks for nothing this
// build cannot check.
//
// A contract that states a restriction no rule enforces is the product-level
// form of reading absence as permission: the reader sees a constraint written
// down and a PASS beside it, and concludes it held.
func (c Contract) Unevaluated() []string {
	if c.Constraints == nil {
		return nil
	}

	var out []string
	if c.Constraints.AllowedRegions != nil {
		out = append(out, "constraints.allowed_regions")
	}
	if c.Constraints.RequiredTags != nil {
		out = append(out, "constraints.required_tags")
	}
	return out
}

// ExposureOf returns the declared exposure for a family, and whether the
// contract declared one at all.
func (c Contract) ExposureOf(family string) (Exposure, bool) {
	for _, resource := range c.Resources {
		if resource.Family == family {
			return resource.Exposure, true
		}
	}
	return "", false
}

// PublicPortsOf returns the ports a family may make reachable from any address,
// and whether the contract declared any at all.
//
// The two answers are separate because they mean different things to a rule. No
// declaration is silence, and silence is not permission: public ingress then
// needs a human. A declaration of none is a statement, and exceeding it is a
// violation.
func (c Contract) PublicPortsOf(family string) ([]model.PortRange, bool) {
	for _, resource := range c.Resources {
		if resource.Family != family || resource.PublicPorts == nil {
			continue
		}
		return *resource.PublicPorts, true
	}
	return nil, false
}

// AllowsCloud reports whether a cloud is in the allowed set.
func (c Contract) AllowsCloud(cloud string) bool {
	for _, allowed := range c.AllowedClouds {
		if allowed == cloud {
			return true
		}
	}
	return false
}

// derefSlice and derefMap read an optional collection. A nil pointer is a field
// the document omitted; an empty collection is one it stated as empty.
func derefSlice(values *[]string) []string {
	if values == nil {
		return nil
	}
	return *values
}

func derefMap(values *map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	return *values
}
