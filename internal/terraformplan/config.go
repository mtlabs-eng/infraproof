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
// It returns the declared provider instances, the module calls, and for every
// configured resource its provider config key and the references its arguments
// make.
func parseConfiguration(document map[string]any, errs *[]error) (map[string]ProviderConfig,
	map[string]configResource, map[string]ModuleCall) {

	raw, present := document["configuration"]
	if !present || raw == nil {
		return nil, nil, nil
	}
	configuration, ok := raw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid("configuration", "must be an object"))
		return nil, nil, nil
	}

	configs := parseProviderConfigs(configuration, errs)

	byAddress := map[string]configResource{}
	calls := map[string]ModuleCall{}
	if rootRaw, present := configuration["root_module"]; present && rootRaw != nil {
		root, ok := rootRaw.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid("configuration.root_module", "must be an object"))
		} else {
			walkModule("configuration.root_module", "", root, byAddress, calls, errs)
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
	return configs, byAddress, calls
}

// configResource is what the configuration block says about one resource.
type configResource struct {
	providerConfigKey string
	repeated          bool
	references        []ExpressionReference
	stated            []string
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
		if c := cmp.Compare(a.Target, b.Target); c != 0 {
			return c
		}
		return slices.Compare(a.TargetKeys, b.TargetKeys)
	})
	return slices.CompactFunc(out, func(a, b ExpressionReference) bool {
		return a.Attribute == b.Attribute && a.Target == b.Target &&
			slices.Equal(a.TargetKeys, b.TargetKeys)
	})
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
func walkModule(path, addressPrefix string, module map[string]any, byAddress map[string]configResource,
	calls map[string]ModuleCall, errs *[]error) {

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
				qualified := joinAddress(addressPrefix, address)
				if _, declared := byAddress[qualified]; declared {
					// The same rule resource_changes applies, for the same
					// reason: an address identifies one resource. Keeping the
					// last entry discarded the first one's references, and a
					// reference is the only dependable link between a resource
					// and the controls over it — so a second entry with no
					// arguments erased a stated correlation and left a grant
					// looking undetermined, with nothing said about it.
					//
					// safeToken, like every plan-derived string in a
					// diagnostic: an address is a plan value.
					*errs = append(*errs, invalid(entryPath+".address",
						"is %s, which another resource in this module already declares; "+
							"an address identifies one resource", safeToken(address)))
					continue
				}
				_, byForEach := fields["for_each_expression"]
				_, byCount := fields["count_expression"]
				byAddress[qualified] = configResource{
					providerConfigKey: optionalString(fields, "provider_config_key", entryPath+".provider_config_key", errs),
					repeated:          byForEach || byCount,
					references:        parseExpressions(entryPath, fields, addressPrefix, errs),
					stated:            statedArguments(fields),
				}
			}
		}
	}

	callsRaw, present := module["module_calls"]
	if !present || callsRaw == nil {
		return
	}
	moduleCalls, ok := callsRaw.(map[string]any)
	if !ok {
		*errs = append(*errs, invalid(path+".module_calls", "must be an object"))
		return
	}
	for name, callRaw := range moduleCalls {
		callPath := path + ".module_calls." + name
		call, ok := callRaw.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(callPath, "must be an object"))
			continue
		}
		address := joinAddress(addressPrefix, "module."+name)
		// A call with no source is not a call with an empty source: the empty
		// string joined onto a parent directory resolves to the parent, which
		// would hand this module the declarations of the module that calls it.
		// Absent stays absent.
		if source := optionalString(call, "source", callPath+".source", errs); source != "" {
			calls[address] = ModuleCall{Address: address, Parent: addressPrefix, Source: source}
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
		walkModule(callPath+".module", address, inner, byAddress, calls, errs)
	}
}

// statedArguments names every argument a resource's configuration writes.
//
// The keys of the expressions object are exactly the arguments the author wrote,
// whether they hold a constant, a reference, or a nested block. Meta-arguments
// live outside it and are not arguments of the resource.
//
// Sorted, for a binary search and so that two plans differing only in key order
// -- which JSON object order is -- produce the same answer.
func statedArguments(fields map[string]any) []string {
	raw, present := fields["expressions"]
	if !present || raw == nil {
		return nil
	}
	body, ok := raw.(map[string]any)
	if !ok {
		// parseExpressions reports the malformed shape; naming the arguments of
		// something that is not an object is not this function's to invent.
		return nil
	}
	if len(body) == 0 {
		return nil
	}
	names := make([]string, 0, len(body))
	for name := range body {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// parseExpressions reads every reference a resource's configuration makes:
// its arguments, the blocks nested inside them, and the meta-arguments.
//
// Targets are qualified with the module the resource sits in, because
// configuration addresses are module-relative.
func parseExpressions(path string, fields map[string]any, addressPrefix string, errs *[]error) []ExpressionReference {
	var refs []ExpressionReference

	if raw, present := fields["expressions"]; present && raw != nil {
		expressionsPath := path + ".expressions"
		body, ok := raw.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(expressionsPath, "must be an object"))
		} else {
			refs = append(refs, expressionBlock(expressionsPath, "", body, addressPrefix, errs)...)
		}
	}

	// A control resource often names the resource it controls only through a
	// meta-argument: "for_each = aws_s3_bucket.b" leaves its own arguments
	// referring to each.value, which names nothing. Missing these loses the
	// only link there is.
	for name, attribute := range map[string]string{
		"for_each_expression": "for_each",
		"count_expression":    "count",
	} {
		raw, present := fields[name]
		if !present || raw == nil {
			continue
		}
		body, ok := raw.(map[string]any)
		if !ok {
			*errs = append(*errs, invalid(path+"."+name, "must be an object"))
			continue
		}
		refs = append(refs, expressionReferences(path+"."+name, attribute, body, addressPrefix, errs)...)
	}

	refs = append(refs, dependsOnReferences(path, fields, addressPrefix, errs)...)
	return preferKeyed(refs)
}

// expressionBlock walks one level of a configuration body. An attribute is an
// object; a nested block is an array of objects, one per block written, and may
// nest further.
func expressionBlock(path, prefix string, body map[string]any, addressPrefix string, errs *[]error) []ExpressionReference {
	var refs []ExpressionReference

	for name, entry := range body {
		attribute := name
		if prefix != "" {
			attribute = prefix + "." + name
		}
		entryPath := path + "." + name

		switch typed := entry.(type) {
		case map[string]any:
			refs = append(refs, expressionReferences(entryPath, attribute, typed, addressPrefix, errs)...)
		case []any:
			for i, element := range typed {
				nested, ok := element.(map[string]any)
				if !ok {
					// A block whose elements are not objects is a shape this
					// build does not read. It is not an unreadable plan.
					continue
				}
				refs = append(refs, expressionBlock(entryPath+indexPath(i), attribute, nested, addressPrefix, errs)...)
			}
		default:
			// An entry is an attribute expression or a nested block, and
			// nothing else. A scalar here is a malformed configuration rather
			// than a shape this build has yet to learn.
			*errs = append(*errs, invalid(entryPath, "must be an object or an array of blocks"))
		}
	}
	return refs
}

// expressionReferences reads the references of one attribute expression.
func expressionReferences(path, attribute string, body map[string]any, addressPrefix string, errs *[]error) []ExpressionReference {
	listRaw, present := body["references"]
	if !present || listRaw == nil {
		return nil
	}
	list, ok := listRaw.([]any)
	if !ok {
		*errs = append(*errs, invalid(path+".references", "must be an array"))
		return nil
	}

	targets := make([]string, 0, len(list))
	for i, item := range list {
		target, ok := item.(string)
		if !ok {
			*errs = append(*errs, invalid(path+".references"+indexPath(i), "must be a string"))
			continue
		}
		targets = append(targets, target)
	}

	refs := make([]ExpressionReference, 0, len(targets))
	for _, target := range targets {
		refs = append(refs, reference(attribute, target, addressPrefix))
	}
	return refs
}

// reference builds one reference, keeping the instance the target names.
func reference(attribute, target, addressPrefix string) ExpressionReference {
	return ExpressionReference{
		Attribute:  attribute,
		Target:     joinAddress(addressPrefix, stripIndexKeys(target)),
		TargetKeys: indexKeys(target),
	}
}

// preferKeyed drops the bare form of a reference to a resource this one also
// names by instance.
//
// Terraform emits both: "aws_s3_bucket.b[\"a\"]" names the instance an argument
// uses, and "aws_s3_bucket.b" records a dependency on the resource as a whole.
// The comparison is per target and not per argument, because the bare form
// arrives under depends_on as readily as under the argument itself — and one
// routine "depends_on = [aws_s3_bucket.b]" would otherwise widen every keyed
// reference the resource makes back to every instance.
func preferKeyed(refs []ExpressionReference) []ExpressionReference {
	keyed := map[string]bool{}
	for _, ref := range refs {
		if len(ref.TargetKeys) > 0 {
			keyed[ref.Target] = true
		}
	}
	if len(keyed) == 0 {
		return refs
	}

	out := refs[:0]
	for _, ref := range refs {
		if len(ref.TargetKeys) == 0 && keyed[ref.Target] {
			continue
		}
		out = append(out, ref)
	}
	return out
}

// dependsOnReferences reads an explicit dependency list, which is a plain array
// of addresses rather than an expression.
func dependsOnReferences(path string, fields map[string]any, addressPrefix string, errs *[]error) []ExpressionReference {
	raw, present := fields["depends_on"]
	if !present || raw == nil {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		*errs = append(*errs, invalid(path+".depends_on", "must be an array"))
		return nil
	}

	refs := make([]ExpressionReference, 0, len(list))
	for i, item := range list {
		target, ok := item.(string)
		if !ok {
			*errs = append(*errs, invalid(path+".depends_on"+indexPath(i), "must be a string"))
			continue
		}
		refs = append(refs, reference("depends_on", target, addressPrefix))
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
		change.DeclaredRepeated = configured.repeated
		change.References = configured.references
		change.Configured = true
		change.Stated = configured.stated
	}
}

func joinAddress(prefix, address string) string {
	if prefix == "" {
		return address
	}
	return prefix + "." + address
}

// indexKeys returns the contents of every bracketed key in an address,
// outermost first, with surrounding quotes removed. It is the complement of
// stripIndexKeys: one gives the configuration address, the other says which
// instance of it this is.
func indexKeys(address string) []string {
	var (
		keys    []string
		current []byte
	)

	depth, inQuotes, escaped := 0, false, false
	for i := 0; i < len(address); i++ {
		c := address[i]
		if depth == 0 {
			if c == '[' {
				depth, current = 1, nil
			}
			continue
		}
		switch {
		case escaped:
			escaped = false
			current = append(current, c)
		case c == '\\':
			escaped = true
		case c == '"':
			inQuotes = !inQuotes
		case inQuotes:
			current = append(current, c)
		case c == '[':
			depth++
			current = append(current, c)
		case c == ']':
			depth--
			if depth == 0 {
				keys = append(keys, string(current))
				continue
			}
			current = append(current, c)
		default:
			current = append(current, c)
		}
	}
	return keys
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
