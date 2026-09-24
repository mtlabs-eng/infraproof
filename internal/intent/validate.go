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
			quotable(string(c.DestructiveChanges)), DestructiveForbidden, DestructiveAllowedWithWarning))
	}

	return errs
}

// quotable bounds a value a message quotes back.
//
// The values are the reader's own contract, so quoting one is what makes a
// message actionable. Its length is theirs too, and a single entry may be a
// megabyte: a message is written to a terminal, and one that reprints the file
// is one nobody reads to the end. The truncation is stated rather than silent.
func quotable(value string) string {
	const limit = 80

	count := 0
	for at := range value {
		count++
		if count > limit {
			// Cut on a character boundary. Slicing at a byte offset split a
			// multi-byte character and put an invalid sequence in the message,
			// which is a different way of failing to say which value is wrong.
			return value[:at] + "… (truncated)"
		}
	}
	return value
}

// validateSchemaVersion holds the compatibility boundary at the major version.
// A later major version may redefine a field this build believes it
// understands, so it is refused.
//
// A later minor version is accepted here and then refused by the loader, which
// rejects unknown fields: this build reads the version it knows and will not
// guess at what a field it has never heard of was meant to constrain. Accepting
// the version while refusing the document is the honest pair, because the
// version says what the document claims to be and the fields say what it asks
// for.
func validateSchemaVersion(version string) error {
	major, minor, found := strings.Cut(version, ".")
	if !found {
		return fmt.Errorf("schema_version is %q, want a major.minor version such as %q",
			quotable(version), SchemaVersion)
	}

	// Both components, and both by the Evidence Bundle's own rule: strconv.Atoi
	// accepts "+1" and "001", and leaving the minor unchecked accepted "1.x.y"
	// as a version this build understands.
	if !isPlainNumber(major) || !isPlainNumber(minor) {
		return fmt.Errorf("schema_version is %q, want a major.minor version such as %q",
			quotable(version), SchemaVersion)
	}
	number, err := strconv.Atoi(major)
	if err != nil {
		return fmt.Errorf("schema_version is %q, want a numeric major version", quotable(version))
	}

	supported, _, _ := strings.Cut(SchemaVersion, ".")
	want, _ := strconv.Atoi(supported)
	if number != want {
		return fmt.Errorf("schema_version is %q; this build understands major version %d", quotable(version), want)
	}
	return nil
}

// isPlainNumber matches the Evidence Bundle's rule for a version component:
// digits, no sign, no leading zero beyond zero itself.
//
// It is stated here as well as in internal/evidence rather than shared, because
// this package knows nothing about the Evidence Bundle and should not start
// now. That is a duplicate rule, not a restated one: neither package is
// deferring to the other's definition, and a version component is the
// project's own idea of what a version looks like.
func isPlainNumber(s string) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
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
				i, quotable(cloud), strings.Join(knownClouds, ", ")))
		case seen[cloud]:
			errs = append(errs, fmt.Errorf("allowed_clouds[%d] repeats %q", i, quotable(cloud)))
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
				i, quotable(resource.Family), strings.Join(knownFamilies, ", ")))
		case seen[resource.Family]:
			// One entry constrains a whole family, so two entries for one
			// family either agree, and one is noise, or disagree, and neither
			// can be applied.
			errs = append(errs, fmt.Errorf("resources[%d] repeats family %q", i, quotable(resource.Family)))
		}
		seen[resource.Family] = true

		switch {
		case !present.exposure:
			errs = append(errs, fmt.Errorf("resources[%d].exposure is required; write %q to record that it was considered and left open",
				i, ExposureUnspecified))
		case !resource.Exposure.Valid():
			errs = append(errs, fmt.Errorf("resources[%d].exposure is %q, want %q, %q or %q",
				i, quotable(string(resource.Exposure)), ExposurePrivate, ExposurePublic, ExposureUnspecified))
		}
	}
	return errs
}

func (c Contract) validateConstraints() []error {
	if c.Constraints == nil {
		return nil
	}

	var errs []error
	for i, region := range derefSlice(c.Constraints.AllowedRegions) {
		if strings.TrimSpace(region) == "" {
			errs = append(errs, fmt.Errorf("constraints.allowed_regions[%d] must not be blank", i))
		}
	}
	// Sorted, because Go iterates a map in a random order and a tool whose
	// selling point is determinism must not report one contract two ways.
	tags := derefMap(c.Constraints.RequiredTags)
	keys := make([]string, 0, len(tags))
	for key := range tags {
		keys = append(keys, key)
	}
	slices.Sort(keys)

	for _, key := range keys {
		if strings.TrimSpace(key) == "" {
			errs = append(errs, fmt.Errorf("constraints.required_tags has a blank key"))
		}
		if strings.TrimSpace(tags[key]) == "" {
			errs = append(errs, fmt.Errorf("constraints.required_tags[%q] must not be blank", quotable(key)))
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
