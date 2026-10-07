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
			Reason: "This build does not know which port this database's version listens on, so " +
				"the port is reported as undetermined. The verdict does not rest on it: an " +
				"authorized network admits addresses and names no port, so nothing here " +
				"compares one.",
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
		Removed:     declared.Removed(subject),
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
// ipConfiguration returns the nested block both halves of the question live in,
// or a zero Value when this plan does not describe it.
//
// The zero Value does not say *why* the block is not there: an instance that
// writes no settings and one whose settings are unknown arrive the same way, and
// Len is 0 for an absent list and for an unknown one alike. That is deliberate,
// because the attribute is the wrong place to ask. Both callers ask the
// configuration instead -- the authority on whether the author wrote something --
// and that is what separates a provider default from a gap. Teaching this
// function the difference would put the answer in two places, which is where
// milestone 08's defects came from.
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
		// The block could not be read, and this build does not answer the allow
		// list from its absence.
		//
		// It used to: if nobody wrote `ip_configuration`, nobody wrote the
		// authorized networks inside it, and the provider's default for those is
		// none -- so the list was taken as empty and authorizing nobody. That is
		// proving a set complete from the *negative* form of the question, which
		// ARCHITECTURE.md forbids by name, and the defence was that a `dynamic`
		// block resolves to a readable list so the shape does not arise. That
		// was measured with a resolvable `for_each`. With an unresolvable one the
		// block comes back wholly unknown and the plan records nothing about it
		// -- not the block, not its content, not even its `for_each` reference --
		// so it is identical in `after`, `after_unknown` and `configuration` to
		// an instance that writes no `ip_configuration` at all. Measured on real
		// plans of both.
		//
		// Indistinguishable, and one of them is a world-open database, so the
		// answer is the one that does not hide the grant.
		//
		// The endpoint switch two functions up still takes the provider's
		// documented default, and that is not the same choice read two ways:
		// there the default is the *unsafe* direction, so applying it hides
		// nothing. Here it is the safe-looking one, which is what made it wrong.
		reason := "This instance takes its settings from somewhere this plan does not describe, so " +
			"nothing here can show which addresses are authorized to reach it."
		switch {
		case !subject.Configured:
			reason = "This plan does not record what was written for this instance, so nothing " +
				"here can show which addresses are authorized to reach it."
		case wroteSettings(subject) && declared.Unwritten(subject, pathIPConfig):
			reason = "This instance writes no ip_configuration block that this plan records, which " +
				"is both what an instance using the provider's defaults looks like and what a " +
				"dynamic block nobody can resolve looks like. The two are identical here, so " +
				"which addresses may reach it is undetermined."
		}
		return model.Unknown[bool](cited), []model.MissingControl{{
			CheckID: checkIPConfigUnread,
			Reason:  reason,
			Sources: []model.Provenance{cited},
			Cloud:   model.CloudGCP,
		}}
	}

	networks := config.Field(attrAuthorizedNets)
	if networks.State() == terraformplan.StateKnown && networks.Kind() != terraformplan.KindArray {
		// A scalar where the list belongs. Len is 0 for it, which reads as an
		// empty allow list and so as a proven closure -- narrower than reality,
		// in the direction that hides a grant. `declared.ListReach` guards the
		// same boundary for the same reason; a plan is input, and this is the one
		// place the defect class is already named.
		return model.Unknown[bool](cited), []model.MissingControl{{
			CheckID: checkAuthNetsUnread,
			Reason: "The authorized networks of this instance are not a list in this plan, so " +
				"nothing here can show which addresses may reach it.",
			Sources: []model.Provenance{cited},
			Cloud:   model.CloudGCP,
		}}
	}
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
