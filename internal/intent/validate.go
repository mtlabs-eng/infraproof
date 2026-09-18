package intent

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// presence records which fields the file actually contained, so validation can
// tell an omitted field from one written with an empty value. The distinction
// is not pedantry: the two have different causes and different fixes, and a
// reader told "environment is invalid" when they forgot the line entirely will
// look in the wrong place.
type presence struct {
	schemaVersion      bool
	changeID           bool
	environment        bool
	allowedClouds      bool
	destructiveChanges bool
	resources          bool
	resourceFields     []resourcePresence
}

type resourcePresence struct {
	family   bool
	exposure bool
}

// clouds this build understands. The set is closed: a contract naming a cloud
// no mapper covers would declare a restriction nothing can evaluate.
var knownClouds = []string{"aws", "azure", "gcp"}

// knownFamilies is closed for the same reason.
var knownFamilies = []string{FamilyObjectStorage}

func (c Contract) validate() error {
	var errs []error

	errs = append(errs, c.validateEnvelope()...)
	errs = append(errs, c.validateClouds()...)
	errs = append(errs, c.validateResources()...)
	errs = append(errs, c.validateConstraints()...)

	return errors.Join(errs...)
}

func (c Contract) validateEnvelope() []error {
	var errs []error

	switch {
	case !c.present.schemaVersion:
		errs = append(errs, fmt.Errorf("schema_version is required"))
	default:
		if err := validateSchemaVersion(c.SchemaVersion); err != nil {
			errs = append(errs, err)
		}
	}

	if !c.present.changeID {
		errs = append(errs, fmt.Errorf("change_id is required"))
	} else if c.ChangeID == "" {
		errs = append(errs, fmt.Errorf("change_id must not be blank"))
	}

	if !c.present.environment {
		errs = append(errs, fmt.Errorf("environment is required"))
	} else if c.Environment == "" {
		errs = append(errs, fmt.Errorf("environment must not be blank"))
	}

	switch {
	case !c.present.destructiveChanges:
		errs = append(errs, fmt.Errorf("destructive_changes is required"))
	case !c.DestructiveChanges.Valid():
		errs = append(errs, fmt.Errorf(
			"destructive_changes is %q, want %q or %q",
			c.DestructiveChanges, DestructiveForbidden, DestructiveAllowedWithWarning))
	}

	return errs
}

// validateSchemaVersion holds the compatibility boundary at the major version.
// A later minor version may add fields this build can safely ignore; a later
// major version may redefine one it believes it understands.
func validateSchemaVersion(version string) error {
	major, _, found := strings.Cut(version, ".")
	if !found {
		return fmt.Errorf("schema_version is %q, want a major.minor version such as %q",
			version, SchemaVersion)
	}

	number, err := strconv.Atoi(major)
	if err != nil {
		return fmt.Errorf("schema_version is %q, want a numeric major version", version)
	}

	supported, _, _ := strings.Cut(SchemaVersion, ".")
	want, _ := strconv.Atoi(supported)
	if number != want {
		return fmt.Errorf("schema_version is %q; this build understands major version %d", version, want)
	}
	return nil
}

func (c Contract) validateClouds() []error {
	if !c.present.allowedClouds {
		return []error{fmt.Errorf("allowed_clouds is required")}
	}
	if len(c.AllowedClouds) == 0 {
		return []error{fmt.Errorf("allowed_clouds must name at least one cloud")}
	}

	var errs []error
	seen := map[string]bool{}
	for i, cloud := range c.AllowedClouds {
		switch {
		case !contains(knownClouds, cloud):
			errs = append(errs, fmt.Errorf("allowed_clouds[%d] is %q, want one of %s",
				i, cloud, strings.Join(knownClouds, ", ")))
		case seen[cloud]:
			errs = append(errs, fmt.Errorf("allowed_clouds[%d] repeats %q", i, cloud))
		}
		seen[cloud] = true
	}
	return errs
}

func (c Contract) validateResources() []error {
	if !c.present.resources {
		return []error{fmt.Errorf("resources is required")}
	}
	if len(c.Resources) == 0 {
		return []error{fmt.Errorf("resources must declare at least one resource")}
	}

	var errs []error
	seen := map[string]bool{}
	for i, resource := range c.Resources {
		present := c.present.resourceFields[i]

		switch {
		case !present.family:
			errs = append(errs, fmt.Errorf("resources[%d].family is required", i))
		case !contains(knownFamilies, resource.Family):
			errs = append(errs, fmt.Errorf("resources[%d].family is %q, want one of %s",
				i, resource.Family, strings.Join(knownFamilies, ", ")))
		case seen[resource.Family]:
			// One entry constrains a whole family, so two entries for one
			// family either agree, and one is noise, or disagree, and neither
			// can be applied.
			errs = append(errs, fmt.Errorf("resources[%d] repeats family %q", i, resource.Family))
		}
		seen[resource.Family] = true

		switch {
		case !present.exposure:
			errs = append(errs, fmt.Errorf("resources[%d].exposure is required; write %q to record that it was considered and left open",
				i, ExposureUnspecified))
		case !resource.Exposure.Valid():
			errs = append(errs, fmt.Errorf("resources[%d].exposure is %q, want %q, %q or %q",
				i, resource.Exposure, ExposurePrivate, ExposurePublic, ExposureUnspecified))
		}
	}
	return errs
}

func (c Contract) validateConstraints() []error {
	if c.Constraints == nil {
		return nil
	}

	var errs []error
	for i, region := range c.Constraints.AllowedRegions {
		if strings.TrimSpace(region) == "" {
			errs = append(errs, fmt.Errorf("constraints.allowed_regions[%d] must not be blank", i))
		}
	}
	// Sorted, because Go iterates a map in a random order and a tool whose
	// selling point is determinism must not report one contract two ways.
	keys := make([]string, 0, len(c.Constraints.RequiredTags))
	for key := range c.Constraints.RequiredTags {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		if strings.TrimSpace(key) == "" {
			errs = append(errs, fmt.Errorf("constraints.required_tags has a blank key"))
		}
		if strings.TrimSpace(c.Constraints.RequiredTags[key]) == "" {
			errs = append(errs, fmt.Errorf("constraints.required_tags[%q] must not be blank", key))
		}
	}
	return errs
}

func contains(haystack []string, needle string) bool {
	for _, candidate := range haystack {
		if candidate == needle {
			return true
		}
	}
	return false
}
