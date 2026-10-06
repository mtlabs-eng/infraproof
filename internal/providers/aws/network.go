package aws

import (
	"fmt"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeSecurityGroup = "aws_security_group"
	typeIngressRule   = "aws_vpc_security_group_ingress_rule"
)

// Check identifiers for the gaps this mapper reports, stable because consumers
// branch on them.
const (
	checkRuleSetIncomplete = "AWS_SECURITY_GROUP_RULES_INCOMPLETE"
	checkAttachmentUnknown = "AWS_SECURITY_GROUP_ATTACHMENT_UNKNOWN"
)

// securityGroup normalizes a security group and the ingress rules the plan joins
// to it.
func (m Mapper) securityGroup(subject terraformplan.ResourceChange,
	related []terraformplan.ResourceChange) model.NormalizedResource {

	capabilities := m.ingressOf(subject, related)
	return model.NormalizedResource{
		Address:     subject.Address,
		Provider:    subject.ProviderName,
		Cloud:       model.CloudAWS,
		Family:      model.FamilyNetwork,
		Destructive: subject.IsDestructive(),
		Environment: m.Environment(subject),
		Network:     &capabilities,
	}
}

// ingressOf decides whether the change permits ingress from any address.
//
// AWS rules are an allow-only union: there is no priority and there is no deny,
// so nothing in the set can override anything else and a rule that opens a port
// opens it. That is what makes this the simplest of the three clouds, and it is
// why the ordering machinery the other two need is absent here rather than
// written and unused.
//
// The asymmetry is the whole of it. A grant is provable from part of the set --
// one rule in the plan opening a port to any address settles it, whatever else
// exists elsewhere. Closure is not: a group whose rules are separate resources
// may have more of them in a module this plan does not include, so the only way
// to prove that nothing is open is for the set to be written inline, where the
// group states all of it.
func (m Mapper) ingressOf(subject terraformplan.ResourceChange,
	related []terraformplan.ResourceChange) model.NetworkCapabilities {

	inline := subject.After.Field("ingress")
	// Cited whichever way the answer goes. A fact that concluded "nothing is
	// open" has to say what it read to conclude it, or a reader is asked to take
	// the absence of a finding on trust -- and every other fact in this build
	// names its source.
	found := openness{cited: []model.Provenance{
		declared.Source(model.CloudAWS, subject.Address, "ingress", inline),
	}}
	for i := range inline.Len() {
		found = found.and(inlineRule(subject.Address, inline.At(i), i))
	}
	if inline.State() != terraformplan.StateKnown && inline.State() != terraformplan.StateAbsent {
		// The set itself could not be read. A port, protocol or address the
		// parser could not read is unknown rather than absent, and so is a whole
		// rule list.
		found.unread = true
	}

	separate := ingressRules(related)
	for _, rule := range separate {
		found = found.and(standaloneRule(rule))
		found.cited = append(found.cited,
			declared.Source(model.CloudAWS, rule.Address, "ip_protocol", rule.After.Field("ip_protocol")))
	}

	capabilities := model.NetworkCapabilities{
		OpenToAnyAddress: found.ranges,
		Unresolved:       m.ingressGaps(subject),
	}

	// The whole set is in the plan only when the group writes it inline. The
	// provider refuses to mix the two forms, so inline rules mean there are no
	// separate ones -- and no separate ones in this plan does not mean none
	// anywhere.
	stated := inline.Len() > 0 && len(separate) == 0

	switch {
	case len(found.ranges) > 0:
		capabilities.PublicIngress = model.Known(true, found.cited...)
	case found.unread:
		capabilities.PublicIngress = model.Unknown[bool](found.cited...)
	case stated:
		capabilities.PublicIngress = model.Known(false, found.cited...)
	default:
		capabilities.PublicIngress = model.Unknown[bool](found.cited...)
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkRuleSetIncomplete,
			Reason: "This security group's ingress rules are not written in the group itself, so the " +
				"plan does not state the whole set and nothing here can show that no rule permits " +
				"ingress from any address.",
			Cloud: model.CloudAWS,
		})
	}
	return capabilities
}

// ingressGaps names what the plan does not say about where this rule set applies.
//
// The attachment is never in the group: an instance or an interface names the
// group, not the other way round, and the group may be attached by something
// this plan does not contain. It bounds what a finding means without preventing
// it, which is what a non-required unknown is for.
func (m Mapper) ingressGaps(subject terraformplan.ResourceChange) []model.MissingControl {
	return []model.MissingControl{{
		CheckID: checkAttachmentUnknown,
		Reason: "A security group applies to whatever attaches it, and an attachment is not part of the " +
			"group, so the plan does not state what this rule set governs.",
		Sources: []model.Provenance{{
			ResourceAddress: subject.Address,
			AttributePath:   "ingress",
			Cloud:           model.CloudAWS,
		}},
		Cloud: model.CloudAWS,
	}}
}

// ingressRules returns the separate ingress-rule resources joined to a group.
func ingressRules(related []terraformplan.ResourceChange) []terraformplan.ResourceChange {
	var out []terraformplan.ResourceChange
	for _, change := range related {
		if change.Type == typeIngressRule && !beingRemoved(change) {
			out = append(out, change)
		}
	}
	return out
}

// openness is what one rule contributes to the answer.
type openness struct {
	// unread records that something the answer depends on could not be read, so
	// this rule can neither open anything nor prove that it does not.
	unread bool
	ranges []model.OpenRange
	// cited is what was read to decide, whichever way it went. A fact that
	// concluded nothing still has to say what it looked at.
	cited []model.Provenance
}

// and combines two rules' contributions. A union, because that is what AWS does
// with them.
func (o openness) and(other openness) openness {
	return openness{
		unread: o.unread || other.unread,
		ranges: append(o.ranges, other.ranges...),
		cited:  append(o.cited, other.cited...),
	}
}

// inlineRule reads one ingress block written in the group.
func inlineRule(address string, block terraformplan.Value, index int) openness {
	path := fmt.Sprintf("ingress[%d]", index)
	addresses := []reachable{
		{value: block.Field("cidr_blocks"), path: path + ".cidr_blocks", list: true},
		{value: block.Field("ipv6_cidr_blocks"), path: path + ".ipv6_cidr_blocks", list: true},
	}
	return rule(address, path, addresses,
		block.Field("protocol"), path+".protocol",
		block.Field("from_port"), block.Field("to_port"), path)
}

// standaloneRule reads one separate ingress-rule resource.
//
// The field names differ from the inline block's, and so does the shape: one
// address rather than a list, and "ip_protocol" rather than "protocol". Reading
// the inline names here would find nothing and report a rule that opens nothing,
// which is the permissive direction.
func standaloneRule(change terraformplan.ResourceChange) openness {
	addresses := []reachable{
		{value: change.After.Field("cidr_ipv4"), path: "cidr_ipv4"},
		{value: change.After.Field("cidr_ipv6"), path: "cidr_ipv6"},
	}
	return rule(change.Address, "", addresses,
		change.After.Field("ip_protocol"), "ip_protocol",
		change.After.Field("from_port"), change.After.Field("to_port"), "")
}

// reachable is one address expression a rule states, with where it was read.
type reachable struct {
	value terraformplan.Value
	path  string
	// list records that the field holds several expressions rather than one.
	list bool
}

// rule decides what one ingress rule contributes, whichever form it was written
// in.
//
// Both forms reduce to the same three questions -- which addresses, which
// protocol, which ports -- and answering them once is what keeps the two forms
// from disagreeing. The field names are the caller's to supply, because those
// are the only part that differs.
func rule(address, path string, addresses []reachable,
	protocol terraformplan.Value, protocolPath string,
	from, to terraformplan.Value, portPath string) openness {

	var found openness
	open := false
	for _, source := range addresses {
		reach, unread := reachOf(source)
		if unread {
			found.unread = true
			found.cited = append(found.cited,
				declared.Source(model.CloudAWS, address, source.path, source.value))
			continue
		}
		if reach {
			open = true
			found.cited = append(found.cited,
				declared.Source(model.CloudAWS, address, source.path, source.value))
		}
	}
	if !open {
		return found
	}

	named, readable := protocolOf(protocol)
	if !readable {
		found.unread = true
		found.cited = append(found.cited,
			declared.Source(model.CloudAWS, address, protocolPath, protocol))
		return found
	}

	ports, readable := portsOf(named, from, to)
	if !readable {
		found.unread = true
		found.cited = append(found.cited,
			declared.Source(model.CloudAWS, address, portPath+".from_port", from),
			declared.Source(model.CloudAWS, address, portPath+".to_port", to))
		return found
	}

	found.ranges = append(found.ranges, model.OpenRange{
		Protocol: named,
		Ports:    ports,
		Sources: []model.Provenance{{
			ResourceAddress: address,
			AttributePath:   protocolPath,
			Cloud:           model.CloudAWS,
		}},
	})
	return found
}

// reachOf reports whether an address expression reaches every address, and
// whether it could be read at all.
//
// A field the plan has not determined is unreadable, and so is a spelling this
// build cannot interpret: either could be "0.0.0.0/0", and treating it as
// narrower would be reading an unknown as a reassurance.
//
// A rule stating no address at all opens nothing -- AWS blocks traffic a rule
// does not describe a source for -- so an absent field is narrow rather than
// unreadable.
func reachOf(source reachable) (any, unread bool) {
	if source.value.State() == terraformplan.StateAbsent {
		return false, false
	}
	if source.value.State() != terraformplan.StateKnown {
		return false, true
	}
	if !source.list {
		return declared.AddressReach(source.value.Text()) == declared.ReachAnyAddress,
			declared.AddressReach(source.value.Text()) == declared.ReachUnreadable
	}

	for i := range source.value.Len() {
		element := source.value.At(i)
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

// protocolOf normalizes the protocol spellings this provider uses.
//
// "-1" and "all" are every protocol. icmpv6 is ICMP: it carries no ports either,
// and the question this family asks does not distinguish them. A spelling this
// build does not know is not readable, because guessing between "every protocol"
// and "one protocol" is guessing between a grant and nothing.
func protocolOf(value terraformplan.Value) (model.Protocol, bool) {
	if value.State() != terraformplan.StateKnown {
		return model.ProtocolUnrecognized, false
	}
	switch value.Text() {
	case "-1", "all":
		return model.ProtocolEvery, true
	case "tcp":
		return model.ProtocolTCP, true
	case "udp":
		return model.ProtocolUDP, true
	case "icmp", "icmpv6":
		return model.ProtocolICMP, true
	default:
		// `protocol` on an inline block is normalized by the provider, but
		// `ip_protocol` on a standalone rule is not: a real plan carries "6"
		// through verbatim, and refusing it loses the verdict on an ordinary
		// rule.
		if protocol, ok := declared.ProtocolNumber(value.Text()); ok {
			return protocol, true
		}
		return model.ProtocolUnrecognized, false
	}
}

// portsOf reads the range a rule opens.
//
// Every protocol is every port, whatever the port fields say: an inline block
// with protocol "-1" writes from_port and to_port as zero, and reading that as
// "port 0" would report a rule that opens everything as one that opens nothing
// much. A protocol with no ports has none to read.
func portsOf(protocol model.Protocol, from, to terraformplan.Value) (model.PortRange, bool) {
	switch protocol {
	case model.ProtocolEvery:
		return model.EveryPort(), true
	case model.ProtocolICMP, model.ProtocolUnrecognized:
		return model.PortRange{}, true
	}

	low, readable := portOf(from)
	if !readable {
		return model.PortRange{}, false
	}
	high, readable := portOf(to)
	if !readable {
		return model.PortRange{}, false
	}
	if low > high {
		// A range the provider would refuse. This build does not know which end
		// was meant, and a guess here is a guess about how much is open.
		return model.PortRange{}, false
	}
	return model.PortRange{From: low, To: high}, true
}

// portOf reads one port number.
func portOf(value terraformplan.Value) (int, bool) {
	if value.Kind() != terraformplan.KindNumber {
		return 0, false
	}
	port, err := value.Number().Int64()
	if err != nil || port < 0 || port > 65535 {
		return 0, false
	}
	return int(port), true
}
