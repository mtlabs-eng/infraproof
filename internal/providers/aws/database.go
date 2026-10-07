package aws

import (
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeDBInstance      = "aws_db_instance"
	typeRDSCluster      = "aws_rds_cluster"
	typeClusterInstance = "aws_rds_cluster_instance"

	attrPubliclyAccessible = "publicly_accessible"
	attrSecurityGroupIDs   = "vpc_security_group_ids"
	attrClusterIdentifier  = "cluster_identifier"
	attrEngine             = "engine"
	attrPort               = "port"
	// lastPort is the highest port there is, so a number outside the range is
	// not read as one -- the same refusal the contract's own port parser makes.
	lastPort = 65535

	checkDatabaseGroupsUnknown = "AWS_DATABASE_SECURITY_GROUPS_UNKNOWN"
	checkDatabaseEngineUnknown = "AWS_DATABASE_ENGINE_UNREADABLE"
	checkClusterNotInPlan      = "AWS_DATABASE_CLUSTER_NOT_IN_PLAN"
	checkClusterNotCorrelated  = "AWS_DATABASE_CLUSTER_NOT_CORRELATED"
	checkAllowListMayBePartial = "AWS_DATABASE_ALLOW_LIST_MAY_BE_PARTIAL"
)

// database normalizes a database instance.
//
// The mapper answers one half of the conjunction -- whether the change gives this
// database an endpoint outside the private network -- and names where the other
// half is. On this cloud the allow list is a security group, which is a subject
// the network family already judges in its own right, so naming it is all that is
// needed and nothing here re-reads a rule set.
//
// scope rather than related, because of a split the schema makes and the design
// did not have: an Aurora instance carries the endpoint switch and no
// `vpc_security_group_ids`, while its cluster carries the groups and no switch.
// Reaching one from the other is two hops and a subject's related carries one.
func (m Mapper) database(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) model.NormalizedResource {

	port, inferred := m.listeningPort(subject, scope)
	capabilities := model.DatabaseCapabilities{
		PublicEndpoint: m.publicEndpoint(subject),
		Port:           port,
		PortInferred:   inferred,
	}
	capabilities.GatedBy, capabilities.Unresolved = m.allowList(subject, scope)
	if capabilities.PublicEndpoint.IsKnown() && !capabilities.PublicEndpoint.Get() {
		// The plan proves this database has no endpoint outside the private
		// network, which is the rule's own second arm: what the allow list says
		// cannot make it reachable. Bounds on the allow list are the whole story
		// for a database with a public endpoint behind groups that read as
		// closed, and noise on one that can never be reached -- and a disclosure
		// firing on every database in a plan tells a reader nothing about the
		// one where it matters.
		capabilities.Unresolved = nil
	}
	if !capabilities.Port.IsKnown() {
		capabilities.Unresolved = append(capabilities.Unresolved, model.MissingControl{
			CheckID: checkDatabaseEngineUnknown,
			Reason: "This build does not know which port this database's engine listens on, so a " +
				"rule admitting any address is reported as reaching it whatever port it admits.",
			Sources: []model.Provenance{declared.Source(model.CloudAWS, subject.Address, attrEngine,
				subject.After.Field(attrEngine))},
			Cloud: model.CloudAWS,
		})
	}

	return model.NormalizedResource{
		Address:     subject.Address,
		Provider:    subject.ProviderName,
		Cloud:       model.CloudAWS,
		Family:      model.FamilyDatabase,
		Destructive: subject.IsDestructive(),
		Removed:     declared.Removed(subject),
		Environment: declared.Environment(subject, attrTags, model.CloudAWS),
		Database:    &capabilities,
	}
}

// publicEndpoint reads whether the change gives this database an endpoint outside
// the private network.
//
// Two shapes, because the two resources differ and only a real plan said so.
// `publicly_accessible` on `aws_db_instance` is Optional and not Computed, so an
// unwritten one is emitted as a determined false -- the provider's default and
// the safe answer. On `aws_rds_cluster_instance` it is Optional **and Computed**
// and comes back unknown when unwritten, which is milestone 08's trap again: read
// as unreadable it makes every idiomatic Aurora instance undeterminable, and the
// configuration is what says whether the unknown is the default or a value
// somebody could not resolve.
func (Mapper) publicEndpoint(subject terraformplan.ResourceChange) model.Fact[bool] {
	cited := declared.Source(model.CloudAWS, subject.Address, attrPubliclyAccessible,
		subject.After.Field(attrPubliclyAccessible))
	value := subject.After.Field(attrPubliclyAccessible)

	if declared.Unstated(subject) {
		// Nothing in this change states anything, so the absence below is not the
		// author declining to write an attribute -- it is a change with no
		// after-object. A destroy is one; so is a `removed` block with
		// `lifecycle { destroy = false }`, which leaves the database up and
		// publicly accessible while Terraform stops managing it.
		return model.Unknown[bool](cited)
	}

	switch value.State() {
	case terraformplan.StateAbsent:
		// Not stated anywhere, in a change that states other things. The
		// provider's default is a private endpoint.
		return model.Known(false, cited)
	case terraformplan.StateKnown:
		if value.Kind() != terraformplan.KindBool {
			return model.Unknown[bool](cited)
		}
		return model.Known(value.Bool(), cited)
	default:
		if declared.Unwritten(subject, attrPubliclyAccessible) {
			// Computed and nobody wrote it, so the provider's documented default
			// applies: a database is not publicly accessible unless asked for.
			return model.Known(false, cited)
		}
		return model.Unknown[bool](cited)
	}
}

// allowList names the security groups that decide who may reach this database.
//
// Addresses, not a verdict. Each one is a subject the network family judges, and
// the rule resolves the names against the graph -- so this mapper never reads a
// rule set and the network mapper never learns that databases exist.
//
// Correlated by reference and by instance, through declared.Targets: the
// attribute holds group ids, which are unknown until apply, and the plural form
// is what a list needs. Reading it through the singular Target reported every
// database with more than one group as undecidable, and comparing addresses with
// their keys stripped is the defect milestone 08 found in the GCP network
// correlation.
//
// For an Aurora instance the groups are on its cluster, so the walk is two hops.
// A cluster the plan does not contain is reported rather than treated as an
// absence: the groups exist and this plan cannot see them.
func (m Mapper) allowList(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) ([]string, []model.MissingControl) {

	holder := subject
	if subject.Type == typeClusterInstance {
		cluster, found := m.clusterOf(subject, scope)
		if !found {
			// Two causes, and a reader needs to know which. A cluster declared
			// in another module is somewhere else and this plan cannot see its
			// groups. A cluster this plan holds that nobody could attach --
			// `aws_rds_cluster.each[each.key].id`, where the reference carries no
			// key and so names no instance -- is right here, and naming the
			// instance outright is what settles it.
			//
			// Saying the first about the second stated the opposite of the fact.
			// CLAUDE.md requires a finding to carry observed facts, and this is
			// PRODUCT.md's documented repeated-resource limitation rather than an
			// absent cluster, so it gets its own identifier instead of borrowing
			// one that means something else.
			control := model.MissingControl{
				CheckID: checkClusterNotInPlan,
				Reason: "This database instance belongs to a cluster that is not part of this plan, " +
					"and the cluster is what names the security groups that decide who may reach it.",
				Sources: []model.Provenance{declared.Source(model.CloudAWS, subject.Address,
					attrClusterIdentifier, subject.After.Field(attrClusterIdentifier))},
				Cloud: model.CloudAWS,
			}
			if clusterUncorrelated(subject, scope) {
				control.CheckID = checkClusterNotCorrelated
				control.Reason = "This database instance names its cluster through an expression " +
					"that resolves to no instance, and this plan holds clusters it could belong " +
					"to. The cluster is what names the security groups that decide who may reach " +
					"this database, so naming the cluster instance outright is what would settle it."
			}
			return nil, []model.MissingControl{control}
		}
		holder = cluster
	}

	named, state := declared.Targets(holder, attrSecurityGroupIDs, typeSecurityGroup, scope)
	cited := []model.Provenance{declared.Source(model.CloudAWS, holder.Address,
		attrSecurityGroupIDs, holder.After.Field(attrSecurityGroupIDs))}

	// The list draws on something this plan does not describe -- a variable, a
	// local, a module output. The references it does carry are a part of the
	// list and not the list, and a gate nobody can name could be the one that
	// admits everything.
	if holder.DrawsOnOpaque(attrSecurityGroupIDs) {
		return nil, []model.MissingControl{{
			CheckID: checkDatabaseGroupsUnknown,
			Reason: "The security groups that decide who may reach this database are named partly " +
				"from something this plan does not describe, so the groups it does name are part " +
				"of the list rather than the list.",
			Sources: cited,
			Cloud:   model.CloudAWS,
		}}
	}

	switch state {
	case declared.CorrelationNamed:
	case declared.CorrelationAbsent:
		// The author named no group, so AWS applies the default security group
		// of the database's VPC -- which is not in the plan. Different from a
		// group the plan does not contain, and a different thing to go and fix.
		// No reference to a security group. Either the author named none, and
		// AWS applies the default group of the VPC, or they named them as
		// literal ids -- which the plan records as a value and not as a
		// correlation. The sentence does not choose between them, because this
		// build cannot.
		return nil, []model.MissingControl{{
			CheckID: checkDatabaseGroupsUnknown,
			Reason: "This database's security groups are not named in a way this plan can correlate, " +
				"so nothing here can show who may reach it. Either none was named, and AWS applies " +
				"the default security group of the VPC, or they were named by identifier rather " +
				"than by reference.",
			Sources: cited,
			Cloud:   model.CloudAWS,
		}}
	default:
		return nil, []model.MissingControl{{
			CheckID: checkDatabaseGroupsUnknown,
			Reason: "The security groups that decide who may reach this database are named in a way " +
				"this plan does not pin down to particular ones, so nothing here can show who may " +
				"reach it.",
			Sources: cited,
			Cloud:   model.CloudAWS,
		}}
	}

	// Named instances resolved to the addresses the plan spells them with. A
	// reference names a resource the way the configuration does -- module
	// instance keys absent, every key quoted -- and the graph holds it the way
	// the plan does. Handing the first to the rule lost the gate of every
	// database written as a module per database, and cited an address appearing
	// nowhere in the plan.
	//
	// One the plan does not contain keeps its identity: the rule reports a gate
	// it cannot find as a gate it cannot read, which is the honest answer and
	// not an absence.
	//
	// And the list is bounded even so. A security group named by its identifier
	// -- `["sg-0aaa"]` -- leaves no reference at all, so a list holding one
	// reference and one literal is indistinguishable from a list holding one
	// reference. Closure here is never fully provable, and the network family
	// attaches the same kind of bound to its own.
	groups := make([]string, 0, len(named))
	for _, identity := range named {
		if address, found := declared.Resolve(holder, identity, scope); found {
			groups = append(groups, address)
			continue
		}
		groups = append(groups, identity)
	}

	return groups, []model.MissingControl{{
		CheckID: checkAllowListMayBePartial,
		Reason: "A security group named by identifier rather than by reference leaves nothing in " +
			"the plan to correlate, so a group admitting more than the ones named here could be " +
			"attached to this database.",
		Sources: cited,
		Cloud:   model.CloudAWS,
	}}
}

// clusterOf finds the cluster an Aurora instance belongs to.
//
// By reference rather than by value: `cluster_identifier` holds the cluster's
// id, which is unknown until apply, so the configuration is the only link that
// survives planning. Singular, because an instance belongs to one cluster and
// two references on that attribute would be a conditional the plan left open.
func (Mapper) clusterOf(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) (terraformplan.ResourceChange, bool) {

	identity, state := declared.Target(subject, attrClusterIdentifier, typeRDSCluster, scope)
	if state != declared.CorrelationNamed {
		return terraformplan.ResourceChange{}, false
	}
	// Resolved against the plan's own addresses rather than compared with
	// ConfigAddress, which discards keys: an Aurora instance written with
	// for_each named `aws_rds_cluster.each["eu"]` could never match a
	// key-stripped address, so its cluster was reported as not part of a plan
	// that contained it.
	address, found := declared.Resolve(subject, identity, scope)
	if !found {
		return terraformplan.ResourceChange{}, false
	}
	for _, candidate := range scope {
		if candidate.Address == address {
			return candidate, true
		}
	}
	return terraformplan.ResourceChange{}, false
}

// listeningPort reads the port this database answers on, from its engine.
//
// The port attribute itself is never in the plan -- Optional and Computed on an
// instance and on a cluster, and Computed only on a cluster instance -- so the
// engine is the only readable source. An Aurora instance takes its engine from
// its cluster, which is the same two hops the allow list takes.
func (m Mapper) listeningPort(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) (model.Fact[int], bool) {

	// The plan's own port first, because it is the plan. `port` is Optional and
	// Computed, so it is unknown when nobody writes it -- the common case, and
	// the reason the engine table exists at all -- and authoritative when
	// somebody does. Reading the table over a stated port is the one direction
	// DatabasePort's own comment calls dangerous: a wrong port makes a
	// reachable database report as closed, and a Postgres instance moved to 1433
	// was ruled out against 5432.
	if stated := subject.After.Field(attrPort); stated.State() == terraformplan.StateKnown &&
		stated.Kind() == terraformplan.KindNumber {
		if value, err := stated.Number().Int64(); err == nil && value > 0 && value <= lastPort {
			return model.Known(int(value),
				declared.Source(model.CloudAWS, subject.Address, attrPort, stated)), false
		}
	}

	holder := subject
	engine := subject.After.Field(attrEngine)
	if engine.Kind() != terraformplan.KindString && subject.Type == typeClusterInstance {
		if cluster, found := m.clusterOf(subject, scope); found {
			holder = cluster
			engine = cluster.After.Field(attrEngine)
		}
	}
	cited := declared.Source(model.CloudAWS, holder.Address, attrEngine, engine)

	if engine.Kind() != terraformplan.KindString {
		return model.Unknown[int](cited), true
	}
	port, named := declared.DatabasePort(engine.Text())
	if !named {
		return model.Unknown[int](cited), true
	}
	return model.Known(port, cited), true
}

// clusterUncorrelated reports that the plan holds an Aurora cluster the subject
// could belong to, while the subject's own reference named none of them.
//
// It separates a cluster declared somewhere else from one declared right here
// that the correlator could not place. The count is deliberately crude: any
// cluster anywhere in the plan, while this instance reached none. A cluster
// belonging to a different instance would also match, which over-states the
// problem rather than under-stating it -- and a reader sent to look at a cluster
// that turns out to be another one has lost a minute, where a reader told the
// plan is empty has been told something untrue.
func clusterUncorrelated(subject terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) bool {

	if !subject.After.Field(attrClusterIdentifier).Sensitive() &&
		subject.After.Field(attrClusterIdentifier).Kind() == terraformplan.KindString {
		// The identifier is a readable literal, so nothing was interpolated and
		// a cluster this plan held would have been found by name. Whatever it
		// names is genuinely not here.
		return false
	}
	for _, candidate := range scope {
		if candidate.Type == typeRDSCluster {
			return true
		}
	}
	return false
}
