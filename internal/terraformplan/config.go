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
		resource.references, resource.opaque = resolveReferences(resource.references, byAddress)
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
	opaque            []string
	// recorded reports that the entry carries an expressions object, which is
	// what makes stated an answer rather than a silence.
	recorded bool
}

func resolveReferences(refs []ExpressionReference,
	byAddress map[string]configResource) ([]ExpressionReference, []string) {

	if len(refs) == 0 {
		return nil, nil
	}

	out := make([]ExpressionReference, 0, len(refs))
	opaque := map[string]bool{}
	for _, ref := range refs {
		if _, declared := byAddress[ref.Target]; declared {
			out = append(out, ref)
			continue
		}
		// Dropped. Most drops are ordinary: Terraform emits the attribute form
		// of every reference beside the bare one, and `aws_security_group.a.id`
		// names no resource while `aws_security_group.a` does. Those say nothing
		// new.
		//
		// A drop that names nothing declared at any depth is the signal: the
		// argument's value draws on a variable, a local, a module output or a
		// literal, which this plan does not describe. The filter is right and
		// the loss of that fact was not -- a list with one placeable reference
		// and one variable read as a complete list.
		if ref.Attribute != "" && !namesSomethingDeclared(ref.Target, byAddress) {
			opaque[ref.Attribute] = true
		}
	}

	drew := make([]string, 0, len(opaque))
	for attribute := range opaque {
		drew = append(drew, attribute)
	}
	slices.Sort(drew)
	if len(drew) == 0 {
		drew = nil
	}
	if len(out) == 0 {
		return nil, drew
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
	}), drew
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
					recorded:          recordsArguments(fields),
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

// recordsArguments reports that the entry carries an expressions object.
//
// Without one, the configuration says that the resource exists and nothing about
// what was written in it, and the two must not be confused. Terraform emits such
// an entry for a resource whose body is only a dynamic block, and a sanitizer
// that strips expressions -- the one place literal values live -- leaves every
// entry in that shape.
//
// Reading it as an author who wrote nothing hands every Optional and Computed
// attribute its provider default. An independent review turned that into PASS,
// exit 0, with no findings, on a firewall opening SSH to 0.0.0.0/0: the deny's
// unknown direction was defaulted to INGRESS and cancelled the grant.
//
// An empty expressions object is a different thing and is recorded: the author
// wrote a resource with no arguments, which is an answer.
func recordsArguments(fields map[string]any) bool {
	raw, present := fields["expressions"]
	if !present || raw == nil {
		return false
	}
	_, ok := raw.(map[string]any)
	return ok
}

// namesSomethingDeclared reports that a reference target, or any prefix of it,
// is a resource the configuration declares.
//
// Terraform writes the attribute form of a reference beside the bare one, so a
// target like `aws_security_group.a.id` is dropped as a matter of course while
// `aws_security_group.a` is kept. Treating the first as evidence that an
// argument drew on something outside the configuration would mark every argument
// that references anything at all.
func namesSomethingDeclared(target string, byAddress map[string]configResource) bool {
	for {
		if _, declared := byAddress[target]; declared {
			return true
		}
		cut := strings.LastIndex(target, ".")
		if cut <= 0 {
			return false
		}
		target = target[:cut]
	}
}

// statedArguments names every argument a resource's configuration writes.
//
// The keys of the expressions object are the arguments the author wrote as
// arguments, whether they hold a constant, a reference, or a nested block
// written in block syntax. Meta-arguments live outside it and are not arguments
// of the resource.
//
// A `dynamic` block is not represented here at all, which is why the absence of
// an expressions object has to mean "not recorded" rather than "nothing written":
// a body that is only a dynamic block produces no object, and a body that mixes
// one with static arguments produces an object that does not mention the dynamic
// attribute. A caller must therefore never read the absence of a name as proof
// that nothing writes it -- only as the absence of a stated argument.
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
	names := map[string]bool{}
	collectArguments("", body, names)
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// collectArguments records an argument's name and descends into nested blocks,
// naming each by the path the configuration nests it at.
//
// An attribute inside a nested block has the same two meanings for an unknown
// value as a top-level one: the author omitted it and a provider default
// applies, or the author wrote it from something unresolvable and nothing does.
// Cloud SQL puts the switch deciding whether a database has a public IP three
// levels down, and recording only the top level made an instance that writes it
// and one that does not identical -- which is the shape milestone 08's worst
// defect had.
//
// The index is deliberately not part of the path. The configuration nests blocks
// as arrays, and an argument written in the second `ingress` block is the same
// argument as one written in the first; a caller asking whether the author wrote
// it should not have to know how many blocks there were. The consequence is that
// an argument written in *any* instance of a repeated block counts as written,
// which is the conservative reading: it withholds a default rather than applying
// one on the strength of a silence that was not total.
func collectArguments(prefix string, body map[string]any, into map[string]bool) {
	for name, entry := range body {
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		into[path] = true

		elements, nested := entry.([]any)
		if !nested {
			continue
		}
		for _, element := range elements {
			block, ok := element.(map[string]any)
			if !ok {
				// parseExpressions reports the malformed shape; naming the
				// arguments of something that is not a block is not this
				// function's to invent.
				continue
			}
			collectArguments(path, block, into)
		}
	}
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
		change.Configured = configured.recorded
		change.Stated = configured.stated
		change.Opaque = configured.opaque
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
