package gcp

import (
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeSQLInstance = "google_sql_database_instance"

	attrSettings       = "settings"
	attrIPConfig       = "ip_configuration"
	attrIPv4Enabled    = "ipv4_enabled"
	attrAuthorizedNets = "authorized_networks"
	attrNetworkValue   = "value"
	attrDatabaseVer    = "database_version"

	// pathIPv4Enabled is where the endpoint switch sits in the configuration's
	// own nesting, which is what Unwritten is asked about.
	pathIPv4Enabled = attrSettings + "." + attrIPConfig + "." + attrIPv4Enabled
	// pathIPConfig is the block the switch and the allow list share.
	pathIPConfig = attrSettings + "." + attrIPConfig

	checkIPConfigUnread = "GCP_SQL_IP_CONFIGURATION_UNREADABLE"
	checkAuthNetsUnread = "GCP_SQL_AUTHORIZED_NETWORK_UNREADABLE"
	checkVersionUnread  = "GCP_SQL_DATABASE_VERSION_UNREADABLE"
)

// database normalizes a Cloud SQL instance.
//
// Both halves of the conjunction are inside the resource: the endpoint switch and
// the authorized networks live in the same nested block, so nothing is deferred
// and GatedBy stays empty.
//
// This is the first mapper to read two levels of nested block, and the shape it
// has to get right is the one milestone 08 got wrong one level up. An instance
// writing no `ip_configuration` emits the whole block as unknown, and Google's
// documented default for `ipv4_enabled` is a public IP -- so reading that unknown
// as unreadable makes the idiomatic instance undeterminable, and reading it as
// the default when somebody wrote an unresolvable value invents a fact. The
// configuration separates them, at the path the block nests the switch at.
func (m Mapper) database(subject terraformplan.ResourceChange) model.NormalizedResource {
	config := ipConfiguration(subject)

	capabilities := model.DatabaseCapabilities{
		PublicEndpoint: publicEndpoint(subject, config),
		Port:           listeningPort(subject),
	}
	capabilities.AdmitsAnyAddress, capabilities.Unresolved = authorizedNetworks(subject, config)
	if !capabilities.Port.IsKnown() {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkVersionUnread,
			Reason: "This build does not know which port this database's version listens on, so an " +
				"authorized network is reported as reaching it whatever port it would reach.",
			Sources: []model.Provenance{declared.Source(model.CloudGCP, subject.Address,
				attrDatabaseVer, subject.After.Field(attrDatabaseVer))},
			Cloud: model.CloudGCP,
		})
	}

	return model.NormalizedResource{
		Address:     subject.Address,
		Provider:    subject.ProviderName,
		Cloud:       model.CloudGCP,
		Family:      model.FamilyDatabase,
		Destructive: subject.IsDestructive(),
		Removed:     subject.IsDestructive() && !subject.IsReplace(),
		Environment: declared.Environment(subject, attrLabels, model.CloudGCP),
		Database:    &capabilities,
	}
}

// ipConfiguration reaches the block holding both halves of the question.
//
// `settings` is a block with one element and `ip_configuration` is a block inside
// it with one element, so the walk is two indexes deep. An absent or unreadable
// block is returned as the zero value, and the callers tell that apart from a
// block that is there.
func ipConfiguration(subject terraformplan.ResourceChange) terraformplan.Value {
	settings := subject.After.Field(attrSettings)
	if settings.Len() == 0 {
		return terraformplan.Value{}
	}
	config := settings.At(0).Field(attrIPConfig)
	if config.Len() == 0 {
		return terraformplan.Value{}
	}
	return config.At(0)
}

// publicEndpoint reads whether this instance has an IPv4 address reachable from
// outside its network.
//
// Three shapes, and only the configuration separates the first two. The block
// unwritten: unknown, and Google's documented default is a public IP. The switch
// written from something unresolvable: unknown, and no default applies. The
// switch written plainly: read it.
func publicEndpoint(subject terraformplan.ResourceChange, config terraformplan.Value) model.Fact[bool] {
	cited := declared.Source(model.CloudGCP, subject.Address, pathIPv4Enabled,
		config.Field(attrIPv4Enabled))
	value := config.Field(attrIPv4Enabled)

	if value.State() == terraformplan.StateKnown && value.Kind() == terraformplan.KindBool {
		return model.Known(value.Bool(), cited)
	}
	if wroteSettings(subject) && declared.Unwritten(subject, pathIPv4Enabled) {
		// Nobody wrote it inside a block the author did write, so the provider's
		// documented default applies: Cloud SQL gives an instance a public IP
		// unless asked not to.
		return model.Known(true, cited)
	}
	return model.Unknown[bool](cited)
}

// authorizedNetworks reads the allow list and answers whether it admits every
// address.
//
// The same asymmetry the other two clouds have, for the same reason: the grant is
// tested before the gaps, because one entry covering every address settles the
// question whatever else could not be read.
//
// An absent list is a statement here rather than an incomplete set, which is what
// makes this cloud different from the other two: the authorized networks are
// inside the instance, so a readable instance with none of them authorizes
// nobody. Only an unreadable block or an unreadable entry leaves it open.
func authorizedNetworks(subject terraformplan.ResourceChange,
	config terraformplan.Value) (model.Fact[bool], []model.MissingControl) {

	cited := declared.Source(model.CloudGCP, subject.Address,
		attrSettings+"."+attrIPConfig+"."+attrAuthorizedNets, config.Field(attrAuthorizedNets))

	if config.State() != terraformplan.StateKnown {
		// The block could not be read. If nobody wrote it, nobody wrote the
		// authorized networks either, and the provider's default for those is
		// none -- so the list is empty and it authorizes nobody. That is the
		// ordinary Cloud SQL instance: a public IP that nothing can reach until
		// a network is added.
		//
		// The same reasoning as the switch two functions up, and it has to be
		// the same: applying a default to one half of a block and not the other
		// would read a single silence two ways.
		if wroteSettings(subject) && declared.Unwritten(subject, pathIPConfig) {
			return model.Known(false, cited), nil
		}
		// The block is unreadable and the silence is not the author's. The
		// reason says which cause it is, because they are different things to
		// go and fix -- and because a `dynamic` block, measured, resolves to a
		// readable list and records nothing in the configuration, so "written
		// from something unresolvable" was a sentence about a shape no plan
		// emits.
		reason := "This instance takes its settings from somewhere this plan does not describe, so " +
			"nothing here can show which addresses are authorized to reach it."
		if !subject.Configured {
			reason = "This plan does not record what was written for this instance, so nothing " +
				"here can show which addresses are authorized to reach it."
		}
		return model.Unknown[bool](cited), []model.MissingControl{{
			CheckID: checkIPConfigUnread,
			Reason:  reason,
			Sources: []model.Provenance{cited},
			Cloud:   model.CloudGCP,
		}}
	}

	networks := config.Field(attrAuthorizedNets)
	if networks.State() != terraformplan.StateKnown && networks.State() != terraformplan.StateAbsent {
		return model.Unknown[bool](cited), []model.MissingControl{{
			CheckID: checkAuthNetsUnread,
			Reason: "The plan does not state which networks are authorized to reach this instance, " +
				"and one of them could be every address.",
			Sources: []model.Provenance{cited},
			Cloud:   model.CloudGCP,
		}}
	}

	var prefixes []string
	var unread []model.MissingControl
	for i := range networks.Len() {
		value := networks.At(i).Field(attrNetworkValue)
		if value.Kind() != terraformplan.KindString {
			unread = append(unread, model.MissingControl{
				CheckID: checkAuthNetsUnread,
				Reason: "An authorized network in front of this instance names an address this " +
					"build could not read, and it could be every address.",
				Sources: []model.Provenance{cited},
				Cloud:   model.CloudGCP,
			})
			continue
		}
		prefixes = append(prefixes, value.Text())
	}

	// The grant before the gaps: one entry covering everything settles it.
	switch declared.SetReach(prefixes) {
	case declared.ReachAnyAddress:
		return model.Known(true, cited), unread
	case declared.ReachUnreadable:
		return model.Unknown[bool](cited), append(unread, model.MissingControl{
			CheckID: checkAuthNetsUnread,
			Reason: "An authorized network in front of this instance names an address this build " +
				"could not read, and it could be every address.",
			Sources: []model.Provenance{cited},
			Cloud:   model.CloudGCP,
		})
	}
	if len(unread) > 0 {
		return model.Unknown[bool](cited), unread
	}
	// Every entry was read and none covers every address. The list is inside the
	// instance, so this is the whole list and an empty one authorizes nobody.
	return model.Known(false, cited), nil
}

// wroteSettings reports that the author wrote the block the switch and the allow
// list live inside.
//
// It is what makes a silence about `ip_configuration` the author's silence. Cloud
// SQL requires one of `clone` or `settings`, so an instance created from a clone
// writes no `settings` at all -- and reading that as "the author left
// ip_configuration out, so the provider's defaults apply" turned a clone into a
// proof of privacy. A clone inherits the source instance's IP configuration,
// authorized networks included, and the source is not in the plan.
//
// The positive form, which ARCHITECTURE.md requires for any decision that a rule
// set is complete: an argument's presence proves the author wrote it, and its
// absence proves nothing.
func wroteSettings(subject terraformplan.ResourceChange) bool {
	return declared.Written(subject, attrSettings)
}

// listeningPort reads the port this instance answers on, from its version.
//
// Cloud SQL writes a version rather than an engine name -- POSTGRES_15 -- and the
// family is the part before the first underscore. declared.DatabasePort reads
// both grammars and refuses anything outside the closed set either names.
func listeningPort(subject terraformplan.ResourceChange) model.Fact[int] {
	version := subject.After.Field(attrDatabaseVer)
	cited := declared.Source(model.CloudGCP, subject.Address, attrDatabaseVer, version)

	if version.Kind() != terraformplan.KindString {
		return model.Unknown[int](cited)
	}
	port, named := declared.DatabasePort(version.Text())
	if !named {
		return model.Unknown[int](cited)
	}
	return model.Known(port, cited)
}
