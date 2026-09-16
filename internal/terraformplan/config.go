package terraformplan

import (
	"cmp"
	"slices"
	"strings"
)

// parseConfiguration reads the plan's configuration block, which is the only
// place a plan records which provider instance a resource uses.
//
// resource_changes carries provider_name, but that is the provider's source
// address and is identical for every aliased instance, so "aws" and "aws.west"
// are indistinguishable without this walk. Sanitized plans routinely omit the
// block entirely; that loses alias information and is not an error.
//
// It returns the declared provider instances and, for every configured
// resource, its provider config key and the references its arguments make.
func parseConfiguration(document map[string]any, errs *[]error) (map[string]ProviderConfig, map[string]configResource) {
	raw, present := document["configuration"]
	if !present || raw == nil {
		return nil, nil
	}
	configuration, ok := raw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid("configuration", "must be an object"))
		return nil, nil
	}

	configs := parseProviderConfigs(configuration, errs)

	byAddress := map[string]configResource{}
	if rootRaw, present := configuration["root_module"]; present && rootRaw != nil {
		root, ok := rootRaw.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid("configuration.root_module", "must be an object"))
		} else {
			walkModule("configuration.root_module", "", root, byAddress, errs)
		}
	}
	// A reference is only an address if the configuration declares a resource
	// at it. Terraform emits the attribute form alongside the bare resource
	// form of every reference, and also names variables, count.index and
	// each.key, none of which is a resource.
	for address, resource := range byAddress {
		resource.references = resolveReferences(resource.references, byAddress)
		byAddress[address] = resource
	}
	return configs, byAddress
}

// configResource is what the configuration block says about one resource.
type configResource struct {
	providerConfigKey string
	references        []ExpressionReference
}

func resolveReferences(refs []ExpressionReference, byAddress map[string]configResource) []ExpressionReference {
	if len(refs) == 0 {
		return nil
	}

	out := make([]ExpressionReference, 0, len(refs))
	for _, ref := range refs {
		if _, declared := byAddress[ref.Target]; declared {
			out = append(out, ref)
		}
	}
	if len(out) == 0 {
		return nil
	}

	slices.SortFunc(out, func(a, b ExpressionReference) int {
		if c := cmp.Compare(a.Attribute, b.Attribute); c != 0 {
			return c
		}
		return cmp.Compare(a.Target, b.Target)
	})
	return slices.Compact(out)
}

func parseProviderConfigs(configuration map[string]any, errs *[]error) map[string]ProviderConfig {
	const path = "configuration.provider_config"

	raw, present := configuration["provider_config"]
	if !present || raw == nil {
		return nil
	}
	object, ok := raw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid(path, "must be an object"))
		return nil
	}

	configs := make(map[string]ProviderConfig, len(object))
	for key, entry := range object {
		entryPath := path + "." + key
		fields, ok := entry.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(entryPath, "must be an object"))
			continue
		}
		configs[key] = ProviderConfig{
			Key:           key,
			Name:          optionalString(fields, "name", entryPath+".name", errs),
			Alias:         optionalString(fields, "alias", entryPath+".alias", errs),
			FullName:      optionalString(fields, "full_name", entryPath+".full_name", errs),
			ModuleAddress: optionalString(fields, "module_address", entryPath+".module_address", errs),
		}
	}
	return configs
}

// walkModule records the provider config key of every resource in a module and
// descends into its module calls. Configuration addresses are module-relative,
// so the qualified address is rebuilt on the way down.
func walkModule(path, addressPrefix string, module map[string]any, byAddress map[string]configResource, errs *[]error) {
	if resourcesRaw, present := module["resources"]; present && resourcesRaw != nil {
		resources, ok := resourcesRaw.([]any)
		if !ok {
			*errs = append(*errs, invalid(path+".resources", "must be an array"))
		} else {
			for i, entry := range resources {
				entryPath := path + ".resources" + indexPath(i)
				fields, ok := entry.(map[string]any)
				if !ok {
					*errs = append(*errs, invalid(entryPath, "must be an object"))
					continue
				}
				address := optionalString(fields, "address", entryPath+".address", errs)
				if address == "" {
					continue
				}
				byAddress[joinAddress(addressPrefix, address)] = configResource{
					providerConfigKey: optionalString(fields, "provider_config_key", entryPath+".provider_config_key", errs),
					references:        parseExpressions(entryPath+".expressions", fields, addressPrefix, errs),
				}
			}
		}
	}

	callsRaw, present := module["module_calls"]
	if !present || callsRaw == nil {
		return
	}
	calls, ok := callsRaw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid(path+".module_calls", "must be an object"))
		return
	}
	for name, callRaw := range calls {
		callPath := path + ".module_calls." + name
		call, ok := callRaw.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(callPath, "must be an object"))
			continue
		}
		innerRaw, present := call["module"]
		if !present || innerRaw == nil {
			continue
		}
		inner, ok := innerRaw.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(callPath+".module", "must be an object"))
			continue
		}
		walkModule(callPath+".module", joinAddress(addressPrefix, "module."+name), inner, byAddress, errs)
	}
}

// parseExpressions reads the references a resource's arguments make. Targets
// are qualified with the module the resource sits in, because configuration
// addresses are module-relative.
func parseExpressions(path string, fields map[string]any, addressPrefix string, errs *[]error) []ExpressionReference {
	raw, present := fields["expressions"]
	if !present || raw == nil {
		return nil
	}
	expressions, ok := raw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid(path, "must be an object"))
		return nil
	}

	var refs []ExpressionReference
	for attribute, entry := range expressions {
		attributePath := path + "." + attribute
		body, ok := entry.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(attributePath, "must be an object"))
			continue
		}
		listRaw, present := body["references"]
		if !present || listRaw == nil {
			continue
		}
		list, ok := listRaw.([]any)
		if !ok {
			*errs = append(*errs, invalid(attributePath+".references", "must be an array"))
			continue
		}
		for i, item := range list {
			target, ok := item.(string)
			if !ok {
				*errs = append(*errs, invalid(attributePath+".references"+indexPath(i), "must be a string"))
				continue
			}
			refs = append(refs, ExpressionReference{
				Attribute: attribute,
				Target:    joinAddress(addressPrefix, target),
			})
		}
	}
	return refs
}

// resolveProviderInstances attaches the provider instance to each change.
//
// A resource_changes address carries count and for_each keys that the
// configuration block does not, so the key is stripped before matching. A
// resource whose address is not in the configuration keeps an empty key rather
// than being guessed at.
func resolveProviderInstances(plan *Plan, byAddress map[string]configResource) {
	if len(byAddress) == 0 {
		return
	}
	for i := range plan.ResourceChanges {
		change := &plan.ResourceChanges[i]
		configured, found := byAddress[stripIndexKeys(change.Address)]
		if !found {
			continue
		}
		change.ProviderConfigKey = configured.providerConfigKey
		change.ProviderAlias = plan.ProviderConfigs[configured.providerConfigKey].Alias
		change.References = configured.references
	}
}

func joinAddress(prefix, address string) string {
	if prefix == "" {
		return address
	}
	return prefix + "." + address
}

// stripIndexKeys removes every bracketed count or for_each key from an address,
// so that module.storage["eu"].aws_s3_bucket.assets[0] matches the
// configuration address module.storage.aws_s3_bucket.assets. Quoted keys may
// themselves contain brackets, so quoting is tracked.
func stripIndexKeys(address string) string {
	var out strings.Builder
	out.Grow(len(address))

	depth, inQuotes, escaped := 0, false, false
	for i := 0; i < len(address); i++ {
		c := address[i]
		if depth == 0 {
			if c == '[' {
				depth = 1
				continue
			}
			out.WriteByte(c)
			continue
		}
		switch {
		case escaped:
			escaped = false
		case c == '\\':
			escaped = true
		case c == '"':
			inQuotes = !inQuotes
		case inQuotes:
		case c == '[':
			depth++
		case c == ']':
			depth--
		}
	}
	return out.String()
}
