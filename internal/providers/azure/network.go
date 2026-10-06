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

	var rules []inbound
	unread := inline.State() != terraformplan.StateKnown && inline.State() != terraformplan.StateAbsent
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

	opened, approximated := resolve(rules)

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

	// The whole set is in the plan only when the group writes it inline. The
	// provider refuses to mix the two forms, so inline rules mean there are no
	// separate ones -- and no separate ones in this plan does not mean none
	// anywhere.
	stated := inline.Len() > 0 && len(separate) == 0

	switch {
	case unread:
		capabilities.PublicIngress = model.Unknown[bool](cited...)
	case len(opened) > 0:
		capabilities.PublicIngress = model.Known(true, cited...)
	case stated:
		// Every rule in the set was read and none of them opens anything. The
		// platform's own default denies inbound traffic no rule allows, so a set
		// with no allow from any address permits none.
		capabilities.PublicIngress = model.Known(false, cited...)
	default:
		capabilities.PublicIngress = model.Unknown[bool](cited...)
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkRuleSetIncomplete,
			Reason: "This network security group's rules are not written in the group itself, so the " +
				"plan does not state the whole set and nothing here can show that no rule permits " +
				"ingress from any address.",
			Cloud: model.CloudAzure,
		})
	}
	return capabilities
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
		if change.Type == typeSecurityRule && !slices.Contains(change.Actions, terraformplan.ActionDelete) {
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
	unread    bool
	cited     []model.Provenance
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
func resolve(rules []inbound) (opened []model.OpenRange, approximated bool) {
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
			case deny.priority >= allow.priority:
				// Azure requires a priority to be unique within a set, so this
				// is the deny that comes after: it never reaches traffic the
				// allow has already permitted.
				continue
			case !covers(deny.protocol, allow.protocol):
				if allow.protocol == model.ProtocolEvery {
					approximated = true
				}
				continue
			}

			if !allow.protocol.HasPorts() {
				// Nothing to subtract: the protocol carries no ports, so a deny
				// that reaches it reaches all of it.
				blocked = true
				break
			}
			remaining = without(remaining, deny.ports)
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
	return opened, approximated
}

// covers reports whether a deny's protocol reaches everything an allow's does.
//
// Equal protocols, or a deny on every protocol. The asymmetry is deliberate: a
// deny on TCP does not cover an allow on every protocol, and treating it as
// though it did would report a set as closed while UDP was open.
func covers(deny, allow model.Protocol) bool {
	return deny == model.ProtocolEvery || deny == allow
}

// without removes every port a deny covers from what an allow permits.
//
// Exact, rather than all-or-nothing. A deny on 22 against an allow on 20-30
// leaves 20-21 and 23-30, and reporting the whole range as open would claim that
// 22 is reachable when the set says it is not -- a true-sounding statement about
// a port nobody can reach, which is the same failure as a wrong line in a file.
func without(ranges, cuts []model.PortRange) []model.PortRange {
	for _, cut := range cuts {
		var next []model.PortRange
		for _, span := range ranges {
			if cut.To < span.From || span.To < cut.From {
				next = append(next, span)
				continue
			}
			if span.From < cut.From {
				next = append(next, model.PortRange{From: span.From, To: cut.From - 1})
			}
			if cut.To < span.To {
				next = append(next, model.PortRange{From: cut.To + 1, To: span.To})
			}
		}
		ranges = next
	}
	return ranges
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
	read.inbound = strings.EqualFold(direction.Text(), "Inbound")
	read.allow = strings.EqualFold(access.Text(), "Allow")
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

	plural := rule.Field("source_address_prefixes")
	if plural.State() != terraformplan.StateKnown && plural.State() != terraformplan.StateAbsent {
		return false, true
	}
	for i := range plural.Len() {
		element := plural.At(i)
		if element.State() != terraformplan.StateKnown {
			return false, true
		}
		switch declared.AddressReach(element.Text()) {
		case declared.ReachAnyAddress:
			return true, false
		case declared.ReachUnreadable:
			return false, true
		}
	}
	return false, false
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
