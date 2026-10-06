package gcp

import (
	"slices"
	"strconv"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeFirewall = "google_compute_firewall"
	typeNetwork  = "google_compute_network"

	// defaultPriority is what the provider documents for an unstated priority.
	defaultPriority = 1000
	// protocolEvery is this provider's spelling of every protocol.
	protocolEvery = "all"
)

// Check identifiers for the gaps this mapper reports.
const (
	checkDenyElsewhere  = "GCP_FIREWALL_DENY_MAY_EXIST_ELSEWHERE"
	checkDenyByTarget   = "GCP_FIREWALL_DENY_NARROWER_BY_TARGET"
	checkDenyByProtocol = "GCP_FIREWALL_DENY_NARROWER_BY_PROTOCOL"
	checkNetworkUnread  = "GCP_FIREWALL_NETWORK_UNDETERMINED"
)

// firewall normalizes one firewall, which on this cloud is a rule and a subject
// at once.
//
// There is no container to hang the set on: a security group and a network
// security group each hold their rules, and here each rule is its own resource.
// So the set this firewall belongs to is every firewall on the same network, and
// what can override it is another resource -- which is why this mapper reads the
// whole plan rather than only what refers to it.
func (m Mapper) firewall(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) model.NormalizedResource {

	capabilities := m.ingressOf(subject, scope)
	return model.NormalizedResource{
		Address:     subject.Address,
		Provider:    subject.ProviderName,
		Cloud:       model.CloudGCP,
		Family:      model.FamilyNetwork,
		Destructive: subject.IsDestructive(),
		Environment: m.Environment(subject),
		Network:     &capabilities,
	}
}

// ingressOf decides whether this firewall permits ingress from any address, once
// the denies that can reach it have been applied.
//
// A deny takes precedence at a lower priority number and also at an equal one,
// which is this cloud's own rule and the one a mapper written from the other two
// would get wrong: Azure forbids the tie, AWS has no denies at all.
func (m Mapper) ingressOf(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) model.NetworkCapabilities {

	rule := readFirewall(subject)
	capabilities := model.NetworkCapabilities{Unresolved: m.ingressGaps(subject)}

	if rule.unread {
		capabilities.PublicIngress = model.Unknown[bool](rule.cited...)
		return capabilities
	}

	cited := rule.cited
	var byTarget, byProtocol, networkUnread bool
	remaining := slices.Clone(rule.allows)

	if rule.anySource && !rule.disabled && rule.inbound {
		for _, candidate := range scope {
			if candidate.Type != typeFirewall || candidate.Address == subject.Address {
				continue
			}
			if slices.Contains(candidate.Actions, terraformplan.ActionDelete) {
				continue
			}
			deny := readFirewall(candidate)
			switch {
			case deny.unread || deny.disabled || !deny.inbound || len(deny.denies) == 0:
				continue
			case !deny.anySource:
				// A deny reaches only the addresses it names. One scoped to a
				// private range, or to a tag, says nothing about traffic from
				// the internet -- and using it to cancel a grant open to the
				// world reported PASS, with no finding and no unknown, for a
				// port open to everyone. Azure's resolve has always required
				// this; nothing proved either of them did.
				continue
			case deny.priority > rule.priority:
				// Above this rule in the ordering, so it never reaches traffic
				// this rule has already permitted. Equal is not above: a deny
				// takes precedence over an allow of the same priority.
				continue
			}

			together, unread := sameNetwork(subject, candidate)
			if unread {
				networkUnread = true
				continue
			}
			if !together {
				continue
			}
			if !coversTargets(deny, rule) {
				// The deny reaches some of the instances this rule reaches, and
				// "some" cannot prove prevention. The grant stands, which is
				// the safe direction, and the narrowing is reported.
				byTarget = true
				continue
			}

			cited = append(cited, deny.cited...)
			remaining, byProtocol = subtract(remaining, deny.denies, byProtocol)
		}
	}

	opened := openRanges(remaining, rule)
	capabilities.OpenToAnyAddress = opened

	switch {
	case len(opened) > 0:
		capabilities.PublicIngress = model.Known(true, cited...)
	default:
		// Every rule of this firewall was read. The platform denies inbound
		// traffic no rule allows, so a firewall that opens nothing to any
		// address permits nothing from any address -- whatever another firewall
		// allows is that firewall's own grant, reported there.
		capabilities.PublicIngress = model.Known(false, cited...)
	}

	// Two different approximations, each with its own reason. They share a
	// direction -- the answer is wider than the truth -- and nothing else, and a
	// reader told about protocols when the cause was a target tag has been sent
	// to look at the wrong field.
	if byTarget {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkDenyByTarget,
			Reason: "A deny rule that takes precedence over this one applies to some instances rather " +
				"than all of them, by target tag or service account, so it cannot be shown to cover " +
				"what this rule permits and what is reported is wider than what the network permits.",
			Cloud: model.CloudGCP,
		})
	}
	if byProtocol {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkDenyByProtocol,
			Reason: "A deny rule that takes precedence over this one covers some of the protocols it " +
				"permits rather than all of them, and a reported range carries one protocol, so what " +
				"is reported is wider than what the network permits.",
			Cloud: model.CloudGCP,
		})
	}
	if networkUnread {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkNetworkUnread,
			Reason: "Another firewall in this plan could take precedence over this one, and the plan " +
				"does not state clearly enough which network either of them applies to.",
			Cloud: model.CloudGCP,
		})
	}
	return capabilities
}

// ingressGaps names what the plan cannot say about this set.
//
// A deny could exist in a firewall this plan does not contain, and nothing here
// can see it. It bounds the finding rather than preventing it, which is what the
// milestone's decision about reachability means in practice.
func (m Mapper) ingressGaps(subject terraformplan.ResourceChange) []model.MissingControl {
	return []model.MissingControl{{
		CheckID: checkDenyElsewhere,
		Reason: "A firewall on the same network at a lower priority can deny what this one permits, " +
			"and one declared outside this plan is not visible here.",
		Sources: []model.Provenance{{
			ResourceAddress: subject.Address,
			AttributePath:   "priority",
			Cloud:           model.CloudGCP,
		}},
		Cloud: model.CloudGCP,
	}}
}

// firewallRule is one firewall as this mapper reads it.
type firewallRule struct {
	priority  int
	inbound   bool
	disabled  bool
	anySource bool
	// allows and denies are the protocol and port tuples the firewall states.
	// Exactly one of them is non-empty: the provider requires one and refuses
	// both.
	allows, denies []protocolPorts
	targets        []string
	// targetsUnread records that which instances this rule reaches could not be
	// read, which bounds comparison with a deny without unsettling the rule.
	targetsUnread bool
	unread        bool
	cited         []model.Provenance
}

// protocolPorts is one allow or deny block.
type protocolPorts struct {
	protocol model.Protocol
	ports    []model.PortRange
}

// readFirewall reads one firewall resource.
func readFirewall(change terraformplan.ResourceChange) firewallRule {
	cite := func(field string) model.Provenance {
		return declared.Source(model.CloudGCP, change.Address, field, change.After.Field(field))
	}
	read := firewallRule{priority: defaultPriority, inbound: true,
		cited: []model.Provenance{cite("priority"), cite("source_ranges")}}

	priority := change.After.Field("priority")
	switch priority.State() {
	case terraformplan.StateAbsent:
		// The provider documents 1000 for an unstated priority, so an absent
		// field is a value rather than a gap.
	case terraformplan.StateKnown:
		value, err := priority.Number().Int64()
		if priority.Kind() != terraformplan.KindNumber || err != nil {
			read.unread = true
			return read
		}
		read.priority = int(value)
	default:
		if !declared.Unwritten(change, "priority") {
			read.unread = true
			read.cited = append(read.cited, cite("priority"))
			return read
		}
		// Unknown because nobody wrote it, which is the default.
	}

	direction := change.After.Field("direction")
	switch direction.State() {
	case terraformplan.StateAbsent:
		// INGRESS by the provider's own default.
	case terraformplan.StateKnown:
		read.inbound = strings.EqualFold(direction.Text(), "INGRESS")
	default:
		// The field is Optional and Computed, so a real create plan emits it as
		// unknown for every firewall that does not spell it out -- which is
		// nearly all of them. Reading that as unreadable made the common case
		// undeterminable; the configuration is what says whether the unknown is
		// the provider's default or a value somebody interpolated.
		//
		// In or out is the difference between a rule about who can reach in and
		// one about nothing of the sort, so an interpolated direction is still
		// a gap.
		if !declared.Unwritten(change, "direction") {
			read.unread = true
			read.cited = append(read.cited, cite("direction"))
			return read
		}
	}

	disabled := change.After.Field("disabled")
	switch disabled.State() {
	case terraformplan.StateAbsent:
	case terraformplan.StateKnown:
		read.disabled = disabled.Kind() == terraformplan.KindBool && disabled.Bool()
	default:
		if !declared.Unwritten(change, "disabled") {
			read.unread = true
			read.cited = append(read.cited, cite("disabled"))
			return read
		}
		// Unwritten, so enforced: the provider's default is false.
	}

	source, unread := sourceReach(change)
	if unread {
		read.unread = true
		return read
	}
	read.anySource = source

	tags, tagsUnread := targetsOf(change, "target_tags")
	accounts, accountsUnread := targetsOf(change, "target_service_accounts")
	// Separate from unread, because a target says which instances a rule reaches
	// and not whether it permits ingress. A grant can still be settled with an
	// undetermined target; what cannot be settled is whether a deny covers it.
	read.targetsUnread = tagsUnread || accountsUnread
	read.targets = append(tags, accounts...)
	if read.targetsUnread {
		read.cited = append(read.cited, cite("target_tags"))
	}

	allows, ok := blocksOf(change, "allow")
	if !ok {
		read.unread = true
		read.cited = append(read.cited, cite("allow"))
		return read
	}
	denies, ok := blocksOf(change, "deny")
	if !ok {
		read.unread = true
		read.cited = append(read.cited, cite("deny"))
		return read
	}
	read.allows, read.denies = allows, denies
	if len(allows) > 0 {
		read.cited = append(read.cited, cite("allow"))
	}
	if len(denies) > 0 {
		read.cited = append(read.cited, cite("deny"))
	}
	return read
}

// sourceReach reports whether a firewall's source covers every address.
//
// Since provider version 4 an ingress firewall must state one of source_ranges,
// source_tags or source_service_accounts, so an absent source_ranges is a
// firewall scoped by something else rather than the old default of every
// address. Reading the old default here would invent a grant on every
// tag-scoped rule in every plan.
func sourceReach(change terraformplan.ResourceChange) (any, unread bool) {
	ranges := change.After.Field("source_ranges")
	switch ranges.State() {
	case terraformplan.StateAbsent:
		return false, false
	case terraformplan.StateKnown:
	default:
		return false, true
	}

	for i := range ranges.Len() {
		element := ranges.At(i)
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

// targetsOf reads one of the two fields that narrow a firewall to some instances.
func targetsOf(change terraformplan.ResourceChange, field string) (targets []string, unread bool) {
	value := change.After.Field(field)
	switch value.State() {
	case terraformplan.StateAbsent:
		return nil, false
	case terraformplan.StateKnown:
	default:
		return nil, true
	}

	for i := range value.Len() {
		element := value.At(i)
		if element.Kind() != terraformplan.KindString {
			// Dropping it made a deny targeting {"web"} appear to cover an allow
			// targeting {"web", <unknown>}: the instances carrying the tag
			// nobody can read are reached by the allow and not by the deny.
			return nil, true
		}
		targets = append(targets, field+":"+element.Text())
	}
	return targets, false
}

// blocksOf reads the allow or deny blocks of a firewall.
func blocksOf(change terraformplan.ResourceChange, field string) ([]protocolPorts, bool) {
	value := change.After.Field(field)
	switch value.State() {
	case terraformplan.StateAbsent:
		return nil, true
	case terraformplan.StateKnown:
	default:
		return nil, false
	}

	var out []protocolPorts
	for i := range value.Len() {
		block := value.At(i)
		protocol, ok := protocolOf(block.Field("protocol"))
		if !ok {
			return nil, false
		}
		ports, ok := portsOf(block.Field("ports"), protocol)
		if !ok {
			return nil, false
		}
		out = append(out, protocolPorts{protocol: protocol, ports: ports})
	}
	return out, true
}

// protocolOf normalizes this provider's protocol spellings.
//
// A protocol number is accepted and not interpreted: "6" is TCP to the platform
// and this build does not translate it, so it is reported as a protocol a port
// declaration cannot describe rather than guessed at.
func protocolOf(value terraformplan.Value) (model.Protocol, bool) {
	if value.Kind() != terraformplan.KindString {
		return model.ProtocolUnrecognized, false
	}
	switch strings.ToLower(value.Text()) {
	case protocolEvery:
		return model.ProtocolEvery, true
	case "tcp":
		return model.ProtocolTCP, true
	case "udp":
		return model.ProtocolUDP, true
	case "icmp":
		return model.ProtocolICMP, true
	default:
		// The provider documents the IANA number as an accepted spelling and
		// passes it through verbatim, so a real `protocol = "6"` reaches here.
		if protocol, ok := declared.ProtocolNumber(value.Text()); ok {
			return protocol, true
		}
		// Not readable rather than "some protocol". Every spelling this build
		// cannot name used to collapse onto one value, and coverage is then
		// decided by equality -- so a deny on protocol 47 cancelled an allow on
		// protocol 6. AWS already refuses one, and the three clouds have to
		// agree about equivalent situations.
		return model.ProtocolUnrecognized, false
	}
}

// portsOf reads the ports a block states. An empty list is every port of that
// protocol, which is the provider's own meaning for omitting it.
func portsOf(value terraformplan.Value, protocol model.Protocol) ([]model.PortRange, bool) {
	if !protocol.HasPorts() {
		return nil, true
	}
	switch value.State() {
	case terraformplan.StateAbsent:
		return []model.PortRange{model.EveryPort()}, true
	case terraformplan.StateKnown:
	default:
		return nil, false
	}
	if value.Len() == 0 {
		return []model.PortRange{model.EveryPort()}, true
	}

	var out []model.PortRange
	for i := range value.Len() {
		element := value.At(i)
		if element.Kind() != terraformplan.KindString {
			return nil, false
		}
		parsed, ok := portRange(element.Text())
		if !ok {
			return nil, false
		}
		out = append(out, parsed)
	}
	return out, true
}

// portRange reads one port or range.
func portRange(text string) (model.PortRange, bool) {
	text = strings.TrimSpace(text)
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

// sameNetwork reports whether two firewalls apply to one network.
//
// The reference decides when both state one, because a network's name is unknown
// until apply and two firewalls naming the same resource are on the same network
// whatever that name turns out to be. Literal names are compared only when
// neither states a reference. Anything else is undetermined, and an undetermined
// deny is not applied -- a deny that cannot be shown to reach this firewall must
// not be used to show it is closed.
func sameNetwork(subject, candidate terraformplan.ResourceChange) (together, unread bool) {
	mine, hasMine := networkReference(subject)
	theirs, hasTheirs := networkReference(candidate)
	if hasMine && hasTheirs {
		return mine == theirs, false
	}

	myName := subject.After.Field("network")
	theirName := candidate.After.Field("network")
	if myName.Kind() != terraformplan.KindString || theirName.Kind() != terraformplan.KindString {
		return false, true
	}
	return myName.Text() == theirName.Text(), false
}

// networkReference returns the network resource a firewall's configuration names.
func networkReference(change terraformplan.ResourceChange) (string, bool) {
	for _, reference := range change.References {
		if reference.Attribute == "network" && strings.HasPrefix(reference.Target, typeNetwork+".") {
			return reference.Target, true
		}
	}
	return "", false
}

// coversTargets reports whether a deny reaches every instance an allow reaches.
//
// A deny with no targets applies to every instance in the network, so it covers
// anything. A deny with targets covers an allow only when the allow is narrowed
// to a subset of them -- and an allow with no targets applies to every instance,
// which a targeted deny cannot cover.
func coversTargets(deny, allow firewallRule) bool {
	if deny.targetsUnread || allow.targetsUnread {
		// One side's instances are not stated, so no subset relation can be
		// established either way. A deny that cannot be shown to cover must not
		// be used to show this rule is closed.
		return false
	}
	if len(deny.targets) == 0 {
		return true
	}
	if len(allow.targets) == 0 {
		return false
	}
	for _, target := range allow.targets {
		if !slices.Contains(deny.targets, target) {
			return false
		}
	}
	return true
}

// subtract removes what a deny covers from what an allow permits.
//
// By protocol first, which is all or nothing, and then by port, which is
// arithmetic. A deny narrower by protocol than an allow on every protocol cannot
// be subtracted: a range carries one protocol and "every protocol except TCP" is
// not one. The wider answer is kept and the approximation is reported, because
// dropping the grant would hide that the other protocols are still open.
func subtract(allows, denies []protocolPorts, approximated bool) ([]protocolPorts, bool) {
	var out []protocolPorts
	for _, allow := range allows {
		remaining := slices.Clone(allow.ports)
		blocked := false
		for _, deny := range denies {
			if deny.protocol != model.ProtocolEvery && deny.protocol != allow.protocol {
				if allow.protocol == model.ProtocolEvery {
					approximated = true
				}
				continue
			}
			if !allow.protocol.HasPorts() {
				blocked = true
				break
			}
			remaining = without(remaining, deny.ports)
		}
		if blocked {
			continue
		}
		if !allow.protocol.HasPorts() {
			out = append(out, allow)
			continue
		}
		if len(remaining) > 0 {
			out = append(out, protocolPorts{protocol: allow.protocol, ports: remaining})
		}
	}
	return out, approximated
}

// without removes every port a deny covers from what an allow permits, exactly.
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

// openRanges turns what survives into what the rules read.
func openRanges(allows []protocolPorts, rule firewallRule) []model.OpenRange {
	if !rule.anySource || rule.disabled || !rule.inbound {
		return nil
	}

	var out []model.OpenRange
	for _, allow := range allows {
		if !allow.protocol.HasPorts() {
			out = append(out, model.OpenRange{Protocol: allow.protocol, Sources: rule.cited})
			continue
		}
		for _, ports := range allow.ports {
			out = append(out, model.OpenRange{
				Protocol: allow.protocol,
				Ports:    ports,
				Sources:  rule.cited,
			})
		}
	}
	return out
}
