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

	checkDatabaseGroupsUnknown = "AWS_DATABASE_SECURITY_GROUPS_UNKNOWN"
	checkDatabaseEngineUnknown = "AWS_DATABASE_ENGINE_UNREADABLE"
	checkClusterNotInPlan      = "AWS_DATABASE_CLUSTER_NOT_IN_PLAN"
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

	capabilities := model.DatabaseCapabilities{
		PublicEndpoint: m.publicEndpoint(subject),
		Port:           m.listeningPort(subject, scope),
	}
	capabilities.GatedBy, capabilities.Unresolved = m.allowList(subject, scope)
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

	switch value.State() {
	case terraformplan.StateAbsent:
		// Not stated anywhere. The provider's default is a private endpoint.
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
			return nil, []model.MissingControl{{
				CheckID: checkClusterNotInPlan,
				Reason: "This database instance belongs to a cluster that is not part of this plan, " +
					"and the cluster is what names the security groups that decide who may reach it.",
				Sources: []model.Provenance{declared.Source(model.CloudAWS, subject.Address,
					attrClusterIdentifier, subject.After.Field(attrClusterIdentifier))},
				Cloud: model.CloudAWS,
			}}
		}
		holder = cluster
	}

	named, state := declared.Targets(holder, attrSecurityGroupIDs, typeSecurityGroup, scope)
	cited := []model.Provenance{declared.Source(model.CloudAWS, holder.Address,
		attrSecurityGroupIDs, holder.After.Field(attrSecurityGroupIDs))}

	switch state {
	case declared.CorrelationNamed:
	case declared.CorrelationAbsent:
		// The author named no group, so AWS applies the default security group
		// of the database's VPC -- which is not in the plan. Different from a
		// group the plan does not contain, and a different thing to go and fix.
		return nil, []model.MissingControl{{
			CheckID: checkDatabaseGroupsUnknown,
			Reason: "This database names no security group, so AWS applies the default security " +
				"group of its VPC and nothing here can show who may reach it.",
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

	// Named instances resolved to the changes in the plan. One the plan does not
	// contain stays named: the rule reports a gate it cannot find as a gate it
	// cannot read, which is the honest answer and not an absence.
	var groups []string
	for _, identity := range named {
		groups = append(groups, identity)
	}
	return groups, nil
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
	for _, candidate := range scope {
		if candidate.Type == typeRDSCluster && candidate.ConfigAddress() == identity {
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
	scope []terraformplan.ResourceChange) model.Fact[int] {

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
		return model.Unknown[int](cited)
	}
	port, named := declared.DatabasePort(engine.Text())
	if !named {
		return model.Unknown[int](cited)
	}
	return model.Known(port, cited)
}
