package terraformplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// supportedMajorVersion is the plan format major version this build implements.
// Terraform increments the major version for breaking changes, so a different
// major version is a different format rather than a newer dialect of this one.
const supportedMajorVersion = "1"

// Parse reads plan JSON into a Plan.
//
// A rejected plan returns its Digest and nothing else. The digest identifies
// the bytes that were rejected, which stays useful; a half-built plan does not,
// and handing one back invites a caller to act on data the parser refused to
// vouch for.
//
// Structural problems are collected rather than reported one at a time; only a
// document that is not JSON at all stops the walk immediately.
func Parse(raw []byte) (Plan, error) {
	sum := sha256.Sum256(raw)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	plan, err := parseDocument(raw)
	if err != nil {
		return Plan{Digest: digest}, err
	}
	plan.Digest = digest
	return plan, nil
}

func parseDocument(raw []byte) (Plan, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	// Numbers stay exact: float64 would round a large integer identifier and
	// make the text of a zero depend on the decoder.
	decoder.UseNumber()

	var document map[string]any
	if err := decoder.Decode(&document); err != nil {
		return Plan{}, invalid("", "input is not valid JSON at byte offset %d", decoder.InputOffset())
	}
	// A file holding a second document would otherwise be read as the first one
	// alone, so the change a human reviews and the change this tool reads would
	// not be the same change.
	if decoder.More() {
		return Plan{}, invalid("", "unexpected content after the plan document at byte offset %d", decoder.InputOffset())
	}

	var plan Plan
	var errs []error

	version, err := formatVersion(document)
	if err != nil {
		// A plan whose format this build does not implement cannot be read
		// further without guessing at its meaning.
		return Plan{}, err
	}
	plan.FormatVersion = version
	plan.TerraformVersion = optionalString(document, "terraform_version", "terraform_version", &errs)

	plan.ResourceChanges = parseResourceChanges(document, &errs)

	configs, keysByAddress := parseConfiguration(document, &errs)
	plan.ProviderConfigs = configs
	resolveProviderInstances(&plan, keysByAddress)

	if len(errs) > 0 {
		return Plan{}, errors.Join(errs...)
	}
	return plan, nil
}

// formatVersion extracts and checks the plan format version.
func formatVersion(document map[string]any) (string, error) {
	raw, present := document["format_version"]
	if !present {
		return "", unsupported("format_version", "must be present")
	}
	version, ok := raw.(string)
	if !ok {
		return "", unsupported("format_version", "must be a string")
	}

	major, minor, split := strings.Cut(version, ".")
	if !split || strings.Contains(minor, ".") || !isDigits(major) || !isDigits(minor) {
		return version, unsupported("format_version", "must be written as major.minor, got %s", safeToken(version))
	}
	if major != supportedMajorVersion {
		return version, unsupported("format_version",
			"major version %s is not implemented by this build, which reads %s.x", safeToken(version), supportedMajorVersion)
	}
	return version, nil
}

// safeToken bounds a value before it reaches a diagnostic. A plan is untrusted
// input and its diagnostics land in CI logs, so a version string is echoed only
// when it is short and plainly a version; anything else is described rather
// than repeated. A real version is always reportable.
func safeToken(s string) string {
	const limit = 16

	if s == "" || len(s) > limit {
		return "an unreportable value"
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		case r == '.', r == '-', r == '_':
		default:
			return "an unreportable value"
		}
	}
	return strconv.Quote(s)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// parseResourceChanges walks resource_changes. An absent or null list is an
// empty plan; anything that is not a list is malformed.
func parseResourceChanges(document map[string]any, errs *[]error) []ResourceChange {
	raw, present := document["resource_changes"]
	if !present || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		*errs = append(*errs, invalid("resource_changes", "must be an array"))
		return nil
	}

	changes := make([]ResourceChange, 0, len(list))
	for i, item := range list {
		path := "resource_changes" + indexPath(i)
		object, ok := item.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(path, "must be an object"))
			continue
		}
		changes = append(changes, parseResourceChange(path, object, errs))
	}
	return changes
}

func parseResourceChange(path string, object map[string]any, errs *[]error) ResourceChange {
	change := ResourceChange{
		Address:       requiredString(object, "address", path+".address", errs),
		ModuleAddress: optionalString(object, "module_address", path+".module_address", errs),
		Type:          optionalString(object, "type", path+".type", errs),
		Name:          optionalString(object, "name", path+".name", errs),
		ProviderName:  optionalString(object, "provider_name", path+".provider_name", errs),
		Deposed:       optionalString(object, "deposed", path+".deposed", errs),
		ActionReason:  optionalString(object, "action_reason", path+".action_reason", errs),
		Mode:          Mode(optionalString(object, "mode", path+".mode", errs)),
	}
	change.Index, change.HasIndex = parseIndex(path+".index", object, errs)

	raw, present := object["change"]
	if !present {
		*errs = append(*errs, invalid(path+".change", "must be present"))
		return change
	}
	body, ok := raw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid(path+".change", "must be an object"))
		return change
	}
	parseChangeBody(path+".change", body, &change, errs)
	return change
}

func parseChangeBody(path string, body map[string]any, change *ResourceChange, errs *[]error) {
	change.Actions = parseActions(path+".actions", body, errs)
	change.ReplacePaths = parseReplacePaths(path+".replace_paths", body, errs)
	change.ImportID = parseImporting(path+".importing", body, errs)

	beforeSensitive := parseMaskField(path, body, "before_sensitive", errs)
	afterSensitive := parseMaskField(path, body, "after_sensitive", errs)
	afterUnknown := parseMaskField(path, body, "after_unknown", errs)

	before, beforePresent := body["before"]
	after, afterPresent := body["after"]

	// There is no before_unknown: everything in the prior state is already
	// known, by definition.
	change.Before = merge(before, beforePresent, mask{}, beforeSensitive)
	change.After = merge(after, afterPresent, afterUnknown, afterSensitive)
}

func parseMaskField(path string, body map[string]any, name string, errs *[]error) mask {
	raw, present := body[name]
	return parseMask(path+"."+name, raw, present, errs)
}

// parseActions requires at least one action: a change that does nothing at all
// is not something this package can represent honestly.
func parseActions(path string, body map[string]any, errs *[]error) []Action {
	raw, present := body["actions"]
	if !present {
		*errs = append(*errs, invalid(path, "must be present"))
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		*errs = append(*errs, invalid(path, "must be an array"))
		return nil
	}
	if len(list) == 0 {
		*errs = append(*errs, invalid(path, "must name at least one action"))
		return nil
	}

	actions := make([]Action, 0, len(list))
	for i, item := range list {
		text, ok := item.(string)
		if !ok {
			*errs = append(*errs, invalid(path+indexPath(i), "must be a string"))
			continue
		}
		actions = append(actions, Action(text))
	}
	return actions
}

// parseReplacePaths reads the attribute paths that forced a replacement. A step
// is a string for an object key or a number for a list index; both are rendered
// as text, which is all a path needs to locate a field.
func parseReplacePaths(path string, body map[string]any, errs *[]error) [][]string {
	raw, present := body["replace_paths"]
	if !present || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		*errs = append(*errs, invalid(path, "must be an array"))
		return nil
	}

	paths := make([][]string, 0, len(list))
	for i, item := range list {
		stepPath := path + indexPath(i)
		steps, ok := item.([]any)
		if !ok {
			*errs = append(*errs, invalid(stepPath, "must be an array of path steps"))
			continue
		}
		rendered := make([]string, 0, len(steps))
		for j, step := range steps {
			switch typed := step.(type) {
			case string:
				rendered = append(rendered, typed)
			case json.Number:
				rendered = append(rendered, typed.String())
			default:
				*errs = append(*errs, invalid(stepPath+indexPath(j), "must be a string or a number"))
			}
		}
		paths = append(paths, rendered)
	}
	return paths
}

func parseImporting(path string, body map[string]any, errs *[]error) string {
	raw, present := body["importing"]
	if !present || raw == nil {
		return ""
	}
	object, ok := raw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid(path, "must be an object"))
		return ""
	}
	return optionalString(object, "id", path+".id", errs)
}

// parseIndex reads a count or for_each key. HasIndex distinguishes a resource
// without an index from one keyed by the empty string.
func parseIndex(path string, object map[string]any, errs *[]error) (string, bool) {
	raw, present := object["index"]
	if !present || raw == nil {
		return "", false
	}
	switch typed := raw.(type) {
	case string:
		return typed, true
	case json.Number:
		return typed.String(), true
	default:
		*errs = append(*errs, invalid(path, "must be a string or a number"))
		return "", false
	}
}

func requiredString(object map[string]any, name, path string, errs *[]error) string {
	value := optionalString(object, name, path, errs)
	if value == "" {
		*errs = append(*errs, invalid(path, "must be present and not empty"))
	}
	return value
}

func optionalString(object map[string]any, name, path string, errs *[]error) string {
	raw, present := object[name]
	if !present || raw == nil {
		return ""
	}
	text, ok := raw.(string)
	if !ok {
		*errs = append(*errs, invalid(path, "must be a string"))
		return ""
	}
	return text
}

func indexPath(i int) string { return "[" + strconv.Itoa(i) + "]" }
