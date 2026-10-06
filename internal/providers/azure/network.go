package azure

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeSecurityGroup = "azurerm_network_security_group"
	typeSecurityRule  = "azurerm_network_security_rule"

	attrSecurityRule = "security_rule"
	// serviceTagInternet is every public address. Only the singular prefix
	// field may carry a tag; the plural one takes addresses alone, which is the
	// provider's own rule and not a simplification made here.
	serviceTagInternet = "Internet"
	anyAddressWildcard = "*"
)

// Check identifiers for the gaps this mapper reports.
const (
	checkRuleSetIncomplete  = "AZURE_NSG_RULES_INCOMPLETE"
	checkAssociationUnknown = "AZURE_NSG_ASSOCIATION_UNKNOWN"
	checkDenyNarrower       = "AZURE_NSG_DENY_NARROWER_THAN_ALLOW"
	checkDenyNarrowerByDest = "AZURE_NSG_DENY_NARROWER_BY_DESTINATION"
)

// securityGroup normalizes a network security group and its rules.
func (m Mapper) securityGroup(subject terraformplan.ResourceChange,
	related []terraformplan.ResourceChange) model.NormalizedResource {

	capabilities := m.ingressOf(subject, related)
	return model.NormalizedResource{
		Address:     subject.Address,
		Provider:    subject.ProviderName,
		Cloud:       model.CloudAzure,
		Family:      model.FamilyNetwork,
		Destructive: subject.IsDestructive(),
		Environment: m.Environment(subject),
		Network:     &capabilities,
	}
}

// ingressOf decides whether the change permits ingress from any address.
//
// This is the half AWS does not have. The rules are an ordered set: the lowest
// priority number wins, and a deny below an allow means the allow permits
// nothing. The verdict is about the set and not about any rule in it.
//
// An unreadable rule therefore outranks a proven grant here, where in AWS it does
// not. An AWS set has no denies, so a rule nobody could read can only add
// openness and a proven grant stays proven. An Azure rule nobody could read might
// be a deny below the allow, which would take the grant away -- so the honest
// answer is that the set is unsettled. The two mappers differ because the clouds
// do, which is the whole reason the ordering lives here and not in the rule.
func (m Mapper) ingressOf(subject terraformplan.ResourceChange,
	related []terraformplan.ResourceChange) model.NetworkCapabilities {

	inline := subject.After.Field(attrSecurityRule)
	cited := []model.Provenance{
		declared.Source(model.CloudAzure, subject.Address, attrSecurityRule, inline),
	}

	// `security_rule` is Optional and Computed, so a group writing no inline
	// rules has the attribute emitted as unknown rather than empty -- which is
	// what a real plan does and what no hand-written fixture here did. An unknown
	// nobody wrote is the absence of an inline set, not an unreadable one, and
	// reading it as unreadable discarded grants provable from a separate rule
	// resource. One NSG plus separate azurerm_network_security_rule resources is
	// the most common Azure shape there is.
	noInlineRules := declared.Unwritten(subject, attrSecurityRule)

	var rules []inbound
	unread := !noInlineRules &&
		inline.State() != terraformplan.StateKnown && inline.State() != terraformplan.StateAbsent
	for i := range inline.Len() {
		path := fmt.Sprintf("%s[%d]", attrSecurityRule, i)
		rules = append(rules, readRule(subject.Address, path, inline.At(i)))
	}

	separate := securityRules(related)
	for _, rule := range separate {
		rules = append(rules, readRule(rule.Address, "", rule.After))
	}

	for _, rule := range rules {
		if rule.unread {
			unread = true
		}
		cited = append(cited, rule.cited...)
	}

	opened, approximated, narrowedByDestination := resolve(rules)

	capabilities := model.NetworkCapabilities{
		OpenToAnyAddress: opened,
		Unresolved:       m.ingressGaps(subject),
	}
	if approximated {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkDenyNarrower,
			Reason: "A deny rule below an allow rule covers only some of the protocols the allow " +
				"permits, and a range carries one protocol, so the ports reported as reachable are " +
				"wider than what the set permits.",
			Cloud: model.CloudAzure,
		})
	}
	if narrowedByDestination {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkDenyNarrowerByDest,
			Reason: "A deny rule below an allow rule is limited to a destination narrower than the " +
				"addresses the allow reaches, so it cannot be shown to prevent what the allow " +
				"permits and the grant stands.",
			Cloud: model.CloudAzure,
		})
	}

	// Closure is provable only from an inline set, and only as far as this plan
	// goes.
	//
	// This used to say the provider refuses to mix the two forms. It does not:
	// the documentation advises against it and the plan accepts it, so an
	// inline set is the whole set as this plan writes it and a rule resource
	// elsewhere could still add to it. That bound is reported rather than
	// assumed away.
	// An inline set the author wrote as explicitly empty is stated in full and is
	// empty. Only the positive question is asked, because a `dynamic` block is
	// absent from the configuration's arguments and an absence proves nothing.
	stated := (inline.Len() > 0 || declared.Written(subject, attrSecurityRule)) && len(separate) == 0

	switch {
	case unread:
		capabilities.PublicIngress = model.Unknown[bool](cited...)
	case len(opened) > 0:
		capabilities.PublicIngress = model.Known(true, cited...)
		if !stated {
			// A grant is provable from part of a rule set, and this is that
			// part. What is not here is a deny at a lower priority, which would
			// mean the set permits less than this grant says -- the risk GCP
			// attaches to every firewall and this branch said nothing about.
			capabilities.Unresolved = append(capabilities.Unresolved, incompleteSet())
		}
	case stated:
		// Every rule in the set was read and none of them opens anything. The
		// platform's own default denies inbound traffic no rule allows, so a set
		// with no allow from any address permits none.
		capabilities.PublicIngress = model.Known(false, cited...)
	default:
		capabilities.PublicIngress = model.Unknown[bool](cited...)
		capabilities.Unresolved = append(capabilities.Unresolved, incompleteSet())
	}
	return capabilities
}

// incompleteSet is the control a plan holding only part of a rule set leaves
// unresolved. Both branches that reach it say the same thing, and saying it in
// one place is what keeps the grant branch from falling silent again.
func incompleteSet() model.MissingControl {
	return model.MissingControl{
		CheckID: checkRuleSetIncomplete,
		Reason: "The plan does not state this network security group's rules in full: a rule " +
			"declared elsewhere could permit more, and a deny at a lower priority could permit " +
			"less. They may be separate rule resources, or written in the group in a form the " +
			"plan could not resolve.",
		Cloud: model.CloudAzure,
	}
}

// ingressGaps names what the plan does not say about where this set applies.
func (m Mapper) ingressGaps(subject terraformplan.ResourceChange) []model.MissingControl {
	return []model.MissingControl{{
		CheckID: checkAssociationUnknown,
		Reason: "A network security group applies to the subnets and interfaces associated with it, and " +
			"an association is not part of the group, so the plan does not state what this rule set " +
			"governs.",
		Sources: []model.Provenance{{
			ResourceAddress: subject.Address,
			AttributePath:   attrSecurityRule,
			Cloud:           model.CloudAzure,
		}},
		Cloud: model.CloudAzure,
	}}
}

// securityRules returns the separate rule resources joined to a group.
func securityRules(related []terraformplan.ResourceChange) []terraformplan.ResourceChange {
	var out []terraformplan.ResourceChange
	for _, change := range related {
		// Not a delete, or a delete that is half of a replacement: a rule being
		// rewritten is a rule that will exist, and skipping it would read the
		// state before the change rather than the one it produces.
		if change.Type == typeSecurityRule &&
			(!slices.Contains(change.Actions, terraformplan.ActionDelete) || change.IsReplace()) {
			out = append(out, change)
		}
	}
	return out
}

// inbound is one rule as this mapper reads it. A rule that could not be read
// carries unread, and then nothing else about it is trusted.
type inbound struct {
	priority int
	allow    bool
	inbound  bool
	protocol model.Protocol
	ports    []model.PortRange
	// anySource records that the rule's source covers every address.
	anySource bool
	// anyDestination records that the rule's destination covers every address.
	//
	// It is read for the same reason the source is and used only for a deny. A
	// narrow destination on an allow narrows what is reachable rather than
	// whether ingress is permitted; on a deny it decides whether the deny can be
	// shown to cover the allow at all, and ignoring it made a deny scoped to one
	// host look like a deny covering the subnet.
	anyDestination bool
	unread         bool
	cited          []model.Provenance
}

// resolve reads the ordered set and returns what it leaves open.
//
// Lowest priority number first, and a deny covering an allow below it removes
// exactly what it covers -- by port, which is arithmetic, and by protocol, which
// is not always expressible. A deny narrower by protocol than the allow it meets
// cannot be subtracted from it: a range carries one protocol, and "every protocol
// except TCP" is not one. Rather than drop the grant, which would hide that UDP
// and ICMP are still open, the wider range is reported and the approximation is
// returned so the caller can say so.
func resolve(rules []inbound) (opened []model.OpenRange, approximated, narrowedByDestination bool) {
	ordered := slices.Clone(rules)
	slices.SortStableFunc(ordered, func(a, b inbound) int { return a.priority - b.priority })

	for _, allow := range ordered {
		if !allow.allow || !allow.inbound || !allow.anySource || allow.unread {
			continue
		}

		remaining := slices.Clone(allow.ports)
		blocked := false
		for _, deny := range ordered {
			switch {
			case deny.allow || !deny.inbound || !deny.anySource || deny.unread:
				continue
			case !deny.anyDestination:
				// The deny reaches some of what the allow reaches, and "some"
				// cannot prove prevention. The grant stands, which is the safe
				// direction, and the narrowing is reported.
				narrowedByDestination = true
				continue
			case deny.priority >= allow.priority:
				// Azure requires a priority to be unique within a set, so this
				// is the deny that comes after: it never reaches traffic the
				// allow has already permitted.
				continue
			case !covers(deny.protocol, allow.protocol):
				// Approximated only if the deny would have removed something.
				// A deny whose ports do not meet the allow's removes nothing,
				// so the range is exact and warning that it may be wider than
				// reality is a warning about nothing -- which is how a reader
				// learns to ignore the one that matters.
				if allow.protocol == model.ProtocolEvery && meets(allow.ports, deny.ports) {
					approximated = true
				}
				continue
			}

			if !allow.protocol.HasPorts() {
				// Nothing to subtract, so the deny either reaches all of this
				// protocol or cannot be shown to reach any of it. Reading the
				// first as unconditional let a deny limited to port 80 cancel an
				// ICMP grant whole.
				if reachesEveryPort(deny.ports) {
					blocked = true
					break
				}
				continue
			}
			remaining = model.Without(remaining, deny.ports)
		}
		if blocked {
			continue
		}

		if !allow.protocol.HasPorts() {
			// One range, carrying no ports, because the protocol has none. The
			// loop below would emit nothing here: a rule that opens ICMP to the
			// world has no port range to iterate, and reporting nothing would
			// turn a grant into silence.
			opened = append(opened, model.OpenRange{Protocol: allow.protocol, Sources: allow.cited})
			continue
		}

		for _, ports := range remaining {
			opened = append(opened, model.OpenRange{
				Protocol: allow.protocol,
				Ports:    ports,
				Sources:  allow.cited,
			})
		}
	}
	return opened, approximated, narrowedByDestination
}

// meets reports whether any port in either set is in the other, so an
// approximation is only claimed when something was actually approximated.
//
// A protocol with no ports meets anything: a deny that reaches it reaches all of
// it, and there are no ports to compare.
func meets(allow, deny []model.PortRange) bool {
	if len(allow) == 0 || len(deny) == 0 {
		return true
	}
	for _, a := range allow {
		for _, d := range deny {
			if a.Overlaps(d) {
				return true
			}
		}
	}
	return false
}

// privateServiceTag names the documented service tags for these fields that are
// not reachable from the internet.
//
// The provider documents three: Internet is every public address, VirtualNetwork
// is the address space of the virtual network, and AzureLoadBalancer is the
// platform's health probe. The set is closed deliberately -- Azure adds tags, and
// one nobody here has heard of could be every address, so anything outside this
// list stays unreadable rather than being assumed narrow.
//
// AzureCloud is not here on purpose: it is Azure's own public IP space, which is
// public, and it correctly lands in the unreadable case rather than being read as
// every address or as none.
func privateServiceTag(text string) bool {
	switch text {
	case "VirtualNetwork", "AzureLoadBalancer":
		return true
	default:
		return false
	}
}

// destinationReach reads the destination the same way the source is read. The
// plural field may not carry a tag, and the singular one may -- and of the three
// documented tags only Internet is every public address, which for a destination
// is still narrower than every address.
func destinationReach(rule terraformplan.Value) (any, unread bool) {
	singular := rule.Field("destination_address_prefix")
	switch singular.State() {
	case terraformplan.StateKnown:
		switch {
		case singular.Text() == anyAddressWildcard:
			return true, false
		case singular.Text() == "":
			// The plural field is in use.
		default:
			switch declared.AddressReach(singular.Text()) {
			case declared.ReachAnyAddress:
				return true, false
			case declared.ReachUnreadable:
				return false, true
			default:
				return false, false
			}
		}
	case terraformplan.StateAbsent:
	default:
		return false, true
	}

	switch declared.ListReach(rule.Field("destination_address_prefixes")) {
	case declared.ReachAnyAddress:
		return true, false
	case declared.ReachUnreadable:
		return false, true
	default:
		return false, false
	}
}

// covers reports whether a deny's protocol reaches everything an allow's does.
//
// Equal protocols, or a deny on every protocol. The asymmetry is deliberate: a
// deny on TCP does not cover an allow on every protocol, and treating it as
// though it did would report a set as closed while UDP was open.
func covers(deny, allow model.Protocol) bool {
	return deny == model.ProtocolEvery || deny == allow
}

// readRule reads one rule, in either of the two forms it can be written in. The
// field names are the same in both; only where they sit differs.
func readRule(address, path string, rule terraformplan.Value) inbound {
	at := func(field string) string {
		if path == "" {
			return field
		}
		return path + "." + field
	}
	cite := func(field string) model.Provenance {
		return declared.Source(model.CloudAzure, address, at(field), rule.Field(field))
	}

	read := inbound{cited: []model.Provenance{cite("priority"), cite("access")}}

	priority := rule.Field("priority")
	if priority.Kind() != terraformplan.KindNumber {
		// Without the number there is no ordering, and without the ordering a
		// deny and an allow cannot be told apart in effect.
		read.unread = true
		return read
	}
	value, err := priority.Number().Int64()
	if err != nil {
		read.unread = true
		return read
	}
	read.priority = int(value)

	direction := rule.Field("direction")
	access := rule.Field("access")
	if direction.Kind() != terraformplan.KindString || access.Kind() != terraformplan.KindString {
		read.unread = true
		return read
	}
	// A value this build cannot name is undetermined, not the opposite of the one
	// it can. Reading `read.inbound` as "the text is not Inbound" made any other
	// spelling an outbound rule, which says nothing about who can reach in, and
	// any access that is not Allow a deny, which opens nothing. Both fall to the
	// quiet answer and hide a grant.
	switch {
	case strings.EqualFold(direction.Text(), "Inbound"):
		read.inbound = true
	case strings.EqualFold(direction.Text(), "Outbound"):
		read.inbound = false
	default:
		read.unread = true
		read.cited = append(read.cited, cite("direction"))
		return read
	}
	switch {
	case strings.EqualFold(access.Text(), "Allow"):
		read.allow = true
	case strings.EqualFold(access.Text(), "Deny"):
		read.allow = false
	default:
		read.unread = true
		read.cited = append(read.cited, cite("access"))
		return read
	}
	if !read.inbound {
		// An outbound rule says nothing about who can reach in, and reading no
		// further is not the same as failing to read it.
		return read
	}

	source, unread := sourceReach(rule)
	if unread {
		read.unread = true
		read.cited = append(read.cited, cite("source_address_prefix"), cite("source_address_prefixes"))
		return read
	}
	read.anySource = source

	// An unreadable destination is not read as unread: it narrows nothing about
	// an allow, and a deny that cannot be shown to cover is simply not applied.
	// Making the whole set unknown on it would turn every rule with a
	// destination this build cannot name into an undetermined one.
	destination, _ := destinationReach(rule)
	read.anyDestination = destination
	if source {
		read.cited = append(read.cited, cite("source_address_prefix"), cite("source_address_prefixes"))
	}

	protocol, ok := protocolOf(rule.Field("protocol"))
	if !ok {
		read.unread = true
		read.cited = append(read.cited, cite("protocol"))
		return read
	}
	read.protocol = protocol
	read.cited = append(read.cited, cite("protocol"))

	if !protocol.HasPorts() {
		return read
	}
	ports, ok := destinationPorts(rule)
	if !ok {
		read.unread = true
		read.cited = append(read.cited, cite("destination_port_range"))
		return read
	}
	read.ports = ports
	return read
}

// sourceReach reports whether a rule's source covers every address.
//
// Three spellings mean it: the wildcard, the Internet service tag, and a prefix
// that constrains no bits. The tag is accepted only in the singular field,
// because the provider documents that the plural one takes addresses and not
// tags -- and accepting it in both would be this build inventing a spelling the
// provider refuses.
func sourceReach(rule terraformplan.Value) (any, unread bool) {
	singular := rule.Field("source_address_prefix")
	switch singular.State() {
	case terraformplan.StateKnown:
		switch {
		case singular.Text() == anyAddressWildcard, singular.Text() == serviceTagInternet:
			return true, false
		case singular.Text() == "":
			// The plural field is in use. Not a value, and not unreadable.
		case privateServiceTag(singular.Text()):
			// Documented, and not the internet. Reading these as tags this
			// build does not know turned Azure's most common benign rule --
			// "allow inbound from the virtual network" -- into an undetermined
			// set.
			return false, false
		default:
			switch declared.AddressReach(singular.Text()) {
			case declared.ReachAnyAddress:
				return true, false
			case declared.ReachUnreadable:
				// A service tag this build does not know, or a spelling it
				// cannot read. Either could be every address.
				return false, true
			}
		}
	case terraformplan.StateAbsent:
		// Not stated. The plural field may be.
	default:
		return false, true
	}

	// The plural field may not carry a service tag, so every entry is an
	// address, and what it admits is the union of them.
	switch declared.ListReach(rule.Field("source_address_prefixes")) {
	case declared.ReachAnyAddress:
		return true, false
	case declared.ReachUnreadable:
		return false, true
	default:
		return false, false
	}
}

// protocolOf normalizes this provider's protocol spellings.
//
// Esp and Ah are real protocols with no ports, and this build does not interpret
// them: reporting them as unrecognized is what makes the rule say the contract
// cannot describe them, which is true, rather than folding them into ICMP.
func protocolOf(value terraformplan.Value) (model.Protocol, bool) {
	if value.Kind() != terraformplan.KindString {
		return model.ProtocolUnrecognized, false
	}
	switch strings.ToLower(value.Text()) {
	case anyAddressWildcard:
		return model.ProtocolEvery, true
	case "tcp":
		return model.ProtocolTCP, true
	case "udp":
		return model.ProtocolUDP, true
	case "icmp":
		return model.ProtocolICMP, true
	case "esp", "ah":
		// Real protocols with no ports that this build cannot interpret. They
		// used to be reported as a grant on an unnameable protocol, which made
		// Esp and Ah compare equal and let a deny on one cancel an allow on the
		// other -- and rendered an empty string as the observed fact.
		return model.ProtocolUnrecognized, false
	default:
		return model.ProtocolUnrecognized, false
	}
}

// destinationPorts reads the ports a rule applies to, from whichever of the two
// fields states them.
func destinationPorts(rule terraformplan.Value) ([]model.PortRange, bool) {
	singular := rule.Field("destination_port_range")
	if singular.Kind() == terraformplan.KindString && singular.Text() != "" {
		parsed, ok := portRange(singular.Text())
		if !ok {
			return nil, false
		}
		return []model.PortRange{parsed}, true
	}
	if singular.State() != terraformplan.StateKnown && singular.State() != terraformplan.StateAbsent {
		return nil, false
	}

	plural := rule.Field("destination_port_ranges")
	if plural.State() != terraformplan.StateKnown && plural.State() != terraformplan.StateAbsent {
		return nil, false
	}
	var ranges []model.PortRange
	for i := range plural.Len() {
		element := plural.At(i)
		if element.Kind() != terraformplan.KindString {
			return nil, false
		}
		parsed, ok := portRange(element.Text())
		if !ok {
			return nil, false
		}
		ranges = append(ranges, parsed)
	}
	if len(ranges) == 0 {
		// A rule stating no destination port at all. The provider requires one,
		// so this is a plan this build cannot read rather than a rule that
		// opens nothing.
		return nil, false
	}
	return ranges, true
}

// portRange reads this provider's port spelling: a wildcard, a port, or a range.
func portRange(text string) (model.PortRange, bool) {
	text = strings.TrimSpace(text)
	if text == anyAddressWildcard {
		return model.EveryPort(), true
	}

	low, high, ranged := strings.Cut(text, "-")
	from, ok := port(low)
	if !ok {
		return model.PortRange{}, false
	}
	if !ranged {
		return model.PortRange{From: from, To: from}, true
	}
	to, ok := port(high)
	if !ok || from > to {
		return model.PortRange{}, false
	}
	return model.PortRange{From: from, To: to}, true
}

func port(text string) (int, bool) {
	value, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || value < 0 || value > 65535 {
		return 0, false
	}
	return value, true
}

// reachesEveryPort reports that a deny is not limited to a subset of ports.
//
// A protocol with no ports has nothing to subtract, so a deny reaching it was
// applied all-or-nothing -- without its own ports being read. A deny written on
// every protocol but limited to port 80 therefore cancelled an ICMP grant whole,
// and the set came out as a proven closure. Both clouds document a port range as
// applying only to the protocols that have ports, so a port-limited rule cannot
// reach one that does not.
//
// No ports at all means the rule is not about ports, which is the shape a deny on
// a port-less protocol has.
func reachesEveryPort(ports []model.PortRange) bool {
	return len(ports) == 0 || model.Covers(ports, model.EveryPort())
}
