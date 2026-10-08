package azure

import (
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
	"slices"
)

const (
	typeSQLServer       = "azurerm_mssql_server"
	typeSQLFirewallRule = "azurerm_mssql_firewall_rule"
	typePostgresServer  = "azurerm_postgresql_flexible_server"
	typePostgresRule    = "azurerm_postgresql_flexible_server_firewall_rule"
	attrPublicNetwork   = "public_network_access_enabled"
	attrStartIP         = "start_ip_address"
	attrEndIP           = "end_ip_address"
	attrServerID        = "server_id"
	// azureServices is the address Azure's own convention uses to mean "traffic
	// from inside Azure", written as a range from it to itself.
	azureServices        = "0.0.0.0"
	portSQLServer        = 1433
	portPostgres         = 5432
	checkRulesIncomplete = "AZURE_DATABASE_FIREWALL_RULES_INCOMPLETE"
	checkEndpointUnknown = "AZURE_DATABASE_PUBLIC_ACCESS_UNDETERMINED"
	checkRuleRangeUnread = "AZURE_DATABASE_FIREWALL_RANGE_UNREADABLE"
	checkAllowsAzure     = "AZURE_DATABASE_ALLOWS_AZURE_SERVICES"
)

// database normalizes a managed database server.
//
// This cloud answers both halves of the conjunction itself. The endpoint switch
// is an attribute of the server, and the allow list is the server's own firewall
// rules -- control resources the normalizer joins to it through a declared
// binding -- so nothing is deferred to another subject and GatedBy stays empty.
//
// A rule is a start and an end address rather than a prefix, which is the only
// grammar this field has, so the arithmetic goes through declared.RangeReach.
func (m Mapper) database(subject terraformplan.ResourceChange,
	related, scope []terraformplan.ResourceChange) model.NormalizedResource {

	capabilities := model.DatabaseCapabilities{
		PublicEndpoint: m.publicEndpoint(subject),
		Port:           listeningPort(subject),
	}
	capabilities.AdmitsAnyAddress, capabilities.Unresolved = m.allowList(subject, related, scope)
	if !capabilities.PublicEndpoint.IsKnown() {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkEndpointUnknown,
			Reason: "The plan does not state whether this server accepts connections from outside " +
				"its virtual network, and this build does not know what the provider defaults that " +
				"to, so it does not assume one.",
			Sources: []model.Provenance{declared.Source(model.CloudAzure, subject.Address,
				attrPublicNetwork, subject.After.Field(attrPublicNetwork))},
			Cloud: model.CloudAzure,
		})
	}

	return model.NormalizedResource{
		Address:     subject.Address,
		Provider:    subject.ProviderName,
		Cloud:       model.CloudAzure,
		Family:      model.FamilyDatabase,
		Destructive: subject.IsDestructive(),
		Removed:     declared.Removed(subject),
		Environment: declared.Environment(subject, attrTags, model.CloudAzure),
		Database:    &capabilities,
	}
}

// publicEndpoint reads whether the server accepts connections from outside its
// virtual network.
//
// No default is applied, and that is deliberate rather than an omission. The
// attribute is Optional and not Computed on both types in scope, so a real plan
// would state it -- but this provider cannot be planned offline, so what it
// states when nobody writes it has not been measured here. Guessing it in the
// direction that reads as private would hide a reachable database, and guessing
// it the other way would invent a finding. Undetermined is the answer that is
// true either way.
func (Mapper) publicEndpoint(subject terraformplan.ResourceChange) model.Fact[bool] {
	value := subject.After.Field(attrPublicNetwork)
	cited := declared.Source(model.CloudAzure, subject.Address, attrPublicNetwork, value)

	if value.State() != terraformplan.StateKnown || value.Kind() != terraformplan.KindBool {
		return model.Unknown[bool](cited)
	}
	return model.Known(value.Bool(), cited)
}

// allowList reads the server's firewall rules and answers whether any of them
// admits every address.
//
// The asymmetry this family shares with the network one: a grant is provable from
// part of a rule set and closure is not. The rules are separate resources, so a
// plan holding none of them holds none of the set, and one that admits everything
// settles the question whatever else is missing.
func (m Mapper) allowList(subject terraformplan.ResourceChange,
	related, scope []terraformplan.ResourceChange) (model.Fact[bool], []model.MissingControl) {

	var cited []model.Provenance
	var unread []model.MissingControl
	var ranges []declared.AddressRange
	var rules int

	for _, candidate := range related {
		// A rule being destroyed is not a rule this build cannot read. Its
		// addresses are absent from `after` because it is going away, and
		// reading that as unreadable made a plan whose whole purpose is to close
		// the hole report the question as reopened. The network mapper filters
		// removals for the same reason.
		if slices.Contains(candidate.Actions, terraformplan.ActionDelete) && !candidate.IsReplace() {
			continue
		}
		if candidate.Type != ruleTypeFor(subject.Type) {
			// A guard the correlator makes unreachable rather than a decision
			// this makes: the only binding pointing at a server is from its own
			// rule type, so nothing else reaches the related set -- which a test
			// pins, because it is the correlator's discipline and not this
			// mapper's. Kept because a binding added later would otherwise walk
			// straight through here.
			continue
		}
		rules++
		start := candidate.After.Field(attrStartIP)
		end := candidate.After.Field(attrEndIP)
		cited = append(cited,
			declared.Source(model.CloudAzure, candidate.Address, attrStartIP, start),
			declared.Source(model.CloudAzure, candidate.Address, attrEndIP, end))

		if start.Kind() != terraformplan.KindString || end.Kind() != terraformplan.KindString {
			unread = append(unread, rangeUnreadable(candidate))
			continue
		}
		span := declared.AddressRange{Start: start.Text(), End: end.Text()}
		if declared.RangeReach([]declared.AddressRange{span}) == declared.ReachUnreadable {
			unread = append(unread, rangeUnreadable(candidate))
			continue
		}
		// The rule Azure writes to mean "services inside Azure". One address by
		// the arithmetic, which is right -- it is not 0.0.0.0/0 -- and in Azure
		// it admits every Azure-hosted address, which is anyone who can rent a
		// virtual machine. The arithmetic stays and the reader is told, for the
		// reason the inferred port is disclosed: a verdict resting on a
		// provider's convention has to say so.
		//
		// Disclosed and *kept*. It used to be disclosed and skipped, which made
		// the union smaller than the set it describes: a sentinel beside
		// 0.0.0.1-255.255.255.255 admits every IPv4 address between them, and the
		// cover sweep never saw the first one. Measured, that was exit 0 on a
		// server open to the whole internet. A disclosure is not a subtraction.
		if span.Start == azureServices && span.End == azureServices {
			unread = append(unread, model.MissingControl{
				CheckID: checkAllowsAzure,
				Reason: "A firewall rule in front of this server spans 0.0.0.0 to 0.0.0.0, which is " +
					"how Azure admits traffic from inside Azure. It is one address by arithmetic, " +
					"and in practice it admits every Azure-hosted address.",
				Sources: []model.Provenance{
					declared.Source(model.CloudAzure, candidate.Address, attrStartIP, start),
					declared.Source(model.CloudAzure, candidate.Address, attrEndIP, end),
				},
				Cloud: model.CloudAzure,
			})
		}
		ranges = append(ranges, span)
	}

	// The grant is tested before the gaps, and that order is the asymmetry this
	// family shares with the network one: a grant is provable from part of a
	// set, so a rule admitting every address settles the question whatever else
	// is missing -- an unreadable rule beside it could only admit more.
	//
	// The union, not any single rule: two halves of the space are each narrow
	// and together are the internet.
	if len(ranges) > 0 && declared.RangeReach(ranges) == declared.ReachAnyAddress {
		return model.Known(true, cited...), unread
	}
	// Closure is not provable on this cloud at all, and that is not a limitation
	// of this build. A database firewall rule is always a separate resource --
	// there is no inline form -- so a plan never holds the whole set, whether it
	// holds none of it or all but one.
	//
	// Two fixtures used to contradict each other here: zero rules gave a
	// required UNKNOWN saying the set could not be complete, and one benign rule
	// gave PASS while the same build still reported that a rule declared
	// elsewhere could admit more. PRODUCT.md states the rule for the product --
	// a set whose rules live in separate resources is UNKNOWN rather than closed
	// -- and the AWS network mapper refuses closure the moment one rule is a
	// separate resource, which is this cloud's permanent condition.
	//
	// The grant half of the asymmetry is above and unchanged: one rule admitting
	// every address settles it.
	reason := "This server's firewall rules are separate resources, so a rule declared outside " +
		"this plan could admit every address and nothing here can show that none does."
	if rules == 0 {
		// Two causes, and they are different things to go and fix. A rule
		// declared in another module is somewhere else. A rule this plan holds
		// that nobody could attach -- a server under count or for_each, named by
		// an expression that resolves to no instance -- is right here, and what
		// settles it is naming the instance outright.
		//
		// Saying the first about the second stated the opposite of the fact, on
		// a plan whose uncorrelated rule admitted every address. CLAUDE.md
		// requires a finding to carry observed facts.
		reason = "This server's firewall rules are separate resources and none of them is in " +
			"this plan, so nothing here can show that no rule admits every address."
		if uncorrelated(subject, scope) {
			reason = "This plan holds a firewall rule of this server's type that could not be " +
				"attached to any server in it, so nothing here can show that no rule admits " +
				"every address. Naming the server instance outright, rather than through an " +
				"expression, is what would settle it."
		}
	}
	return model.Unknown[bool](cited...), append(unread, model.MissingControl{
		CheckID: checkRulesIncomplete,
		Reason:  reason,
		Sources: []model.Provenance{declared.Source(model.CloudAzure, subject.Address,
			attrPublicNetwork, subject.After.Field(attrPublicNetwork))},
		Cloud: model.CloudAzure,
	})
}

// rangeUnreadable reports a rule whose span this build could not read.
func rangeUnreadable(rule terraformplan.ResourceChange) model.MissingControl {
	return model.MissingControl{
		CheckID: checkRuleRangeUnread,
		Reason: "A firewall rule in front of this server names a range of addresses this build " +
			"could not read, and it could be the one that admits every address.",
		Sources: []model.Provenance{
			declared.Source(model.CloudAzure, rule.Address, attrStartIP, rule.After.Field(attrStartIP)),
			declared.Source(model.CloudAzure, rule.Address, attrEndIP, rule.After.Field(attrEndIP)),
		},
		Cloud: model.CloudAzure,
	}
}

// ruleTypeFor names the firewall-rule type that belongs to a server type.
//
// The pairing is the provider's and not a guess: each server type has its own
// rule resource, and a rule of the wrong type names a different server entirely.
func ruleTypeFor(serverType string) string {
	switch serverType {
	case typeSQLServer:
		return typeSQLFirewallRule
	case typePostgresServer:
		return typePostgresRule
	default:
		return ""
	}
}

// portOf names the port a server type listens on.
//
// This cloud has no engine attribute: the engine is the resource type, which is
// readable with certainty rather than inferred from a value. AWS and GCP both
// write an engine and need a table; here the type is the table.
// A type this build does not name answers zero, which the caller reports as an
// undetermined port. The default used to be the MSSQL port, so a third server
// type added to Interprets without touching this function would have inherited
// 1433 in silence -- and a wrong port makes a reachable database read as closed,
// which is the direction that hides a grant. ruleTypeFor next door already
// refuses the same way.
func portOf(serverType string) int {
	switch serverType {
	case typePostgresServer:
		return portPostgres
	case typeSQLServer:
		return portSQLServer
	default:
		return 0
	}
}

// portCitation names what the port was read from, which is the resource type
// rather than any attribute -- so the citation points at the resource itself.
func portCitation(subject terraformplan.ResourceChange) model.Provenance {
	return model.Provenance{
		ResourceAddress: subject.Address,
		AttributePath:   "type",
		Cloud:           model.CloudAzure,
	}
}

// uncorrelated reports that the plan holds a firewall rule of the subject's own
// type that reached no server's related set.
//
// It separates a rule declared somewhere else from one declared right here that
// the correlator could not place, which is what a reader needs in order to know
// where to go. The count is deliberately crude: any rule of the type, anywhere in
// the plan, while this server was handed none. A rule correlated to a *different*
// server would also match, which over-states the problem rather than under-stating
// it -- and a reader sent to look at a rule that turns out to belong elsewhere has
// lost a minute, where a reader told the plan is empty has been told something
// untrue.
func uncorrelated(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) bool {

	for _, candidate := range scope {
		if candidate.Type != ruleTypeFor(subject.Type) {
			continue
		}
		if slices.Contains(candidate.Actions, terraformplan.ActionDelete) && !candidate.IsReplace() {
			continue
		}
		return true
	}
	return false
}

// listeningPort reads the port from the resource type, because on this cloud the
// engine *is* the type: there is no engine attribute and no `port` attribute
// either, so the port is certain rather than inferred from a table of defaults.
// That is why PortInferred stays false here.
//
// A type portOf does not name leaves the port undetermined rather than taking
// another type's, which the rule then reports as an approximation.
func listeningPort(subject terraformplan.ResourceChange) model.Fact[int] {
	port := portOf(subject.Type)
	if port == 0 {
		return model.Unknown[int](portCitation(subject))
	}
	return model.Known(port, portCitation(subject))
}
