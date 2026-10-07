// Package aws interprets Amazon S3 resources.
//
// No single S3 resource answers whether a bucket is public. A bucket is public
// when something grants access — a policy or an ACL — and nothing blocks it.
// The blocks live on a separate resource, and the one that decides the real
// answer, the account-wide public access block, is usually not in the plan at
// all. That gap is reported rather than guessed at.
package aws

import (
	"encoding/json"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

const (
	typeBucket            = "aws_s3_bucket"
	typePublicAccessBlock = "aws_s3_bucket_public_access_block"
	typeBucketPolicy      = "aws_s3_bucket_policy"
	typeBucketACL         = "aws_s3_bucket_acl"
	typeOwnershipControls = "aws_s3_bucket_ownership_controls"
	typeAccountBlock      = "aws_s3_account_public_access_block"
)

// Mapper normalizes S3 object storage.
type Mapper struct{}

// Cloud identifies the cloud this mapper interprets.
func (Mapper) Cloud() model.Cloud { return model.CloudAWS }

// Interprets reports the resource types this mapper understands, including the
// controls it folds into a bucket and the rules it folds into a security group.
func (Mapper) Interprets(resourceType string) bool {
	switch resourceType {
	case typeBucket, typePublicAccessBlock, typeBucketPolicy,
		typeBucketACL, typeOwnershipControls, typeAccountBlock,
		typeSecurityGroup, typeIngressRule,
		typeDBInstance, typeRDSCluster, typeClusterInstance:
		return true
	}
	return false
}

// IsSubject reports the resources normalized in their own right: a bucket, and a
// security group. Everything else this mapper interprets is a control over one of
// them.
func (Mapper) IsSubject(resourceType string) bool {
	switch resourceType {
	case typeBucket, typeSecurityGroup, typeDBInstance, typeClusterInstance:
		return true
	}
	// A cluster is interpreted and is not a subject: it carries no endpoint
	// switch at all, so it cannot be reachable in its own right, and its meaning
	// belongs to the instances that can.
	return false
}

// FamilyOf names the family a resource type belongs to.
//
// The normalizer asks rather than assumes, because a control resource carries no
// capabilities of its own and so cannot be placed by what it returned. Labelling
// an ingress rule as object storage would report it as a different kind of thing
// entirely -- and the default that produced that was invisible, because every
// type this build interpreted was storage until now.
func (Mapper) FamilyOf(resourceType string) model.Family {
	switch resourceType {
	case typeSecurityGroup, typeIngressRule:
		return model.FamilyNetwork
	case typeDBInstance, typeRDSCluster, typeClusterInstance:
		return model.FamilyDatabase
	case typeBucket, typePublicAccessBlock, typeBucketPolicy,
		typeBucketACL, typeOwnershipControls, typeAccountBlock:
		return model.FamilyObjectStorage
	default:
		return model.FamilyUnknown
	}
}

// The questions this mapper answers about a bucket, one per thing that can be
// asked rather than one per thing that can answer.
//
// The two block levels were one question and are two. They shut the same routes
// and they are not rivals: a bucket-level block set by this change proves
// prevention whatever an account-wide one says, so a read of the account
// baseline beside a hardened bucket contested a proof it could not have
// touched, and the most ordinary hardening idiom in S3 came back undetermined.
const (
	roleBucketName  = "bucket"
	roleACLRoute    = "acl"
	roleOwnership   = "object_ownership"
	rolePolicyRoute = "policy"
	roleBucketBlock = "public_access_block"
	roleAccountWide = "account_public_access_block"
)

// RoleOf names the question a resource would answer about a bucket.
//
// The account-wide block is the case the resource type cannot express: it
// governs the buckets in its own account and says nothing whatever about any
// other, which is the filter publicAccess already applies before letting one
// decide anything. Stating it here is what keeps a block read in one account
// from unsettling a verdict about a bucket in another.
func (Mapper) RoleOf(subject, candidate terraformplan.ResourceChange) string {
	if subject.Type != typeBucket {
		return ""
	}
	switch candidate.Type {
	case typeBucket:
		// The subject answers for its own name, which every verdict cites.
		return roleBucketName
	case typeBucketACL:
		return roleACLRoute
	case typeOwnershipControls:
		return roleOwnership
	case typeBucketPolicy:
		return rolePolicyRoute
	case typePublicAccessBlock:
		return roleBucketBlock
	case typeAccountBlock:
		if !sameProviderInstance(subject, candidate) {
			return ""
		}
		return roleAccountWide
	}
	return ""
}

// attrTags is where AWS carries user-supplied labels. It is the only part of
// reading a declared environment that differs between clouds.
const attrTags = "tags"

// Map normalizes a subject together with the resources that refer to it: a
// bucket with its access controls, a security group with its ingress rules.
func (m Mapper) Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource {
	if subject.Type == typeSecurityGroup {
		return m.securityGroup(subject, related)
	}
	if subject.Type == typeDBInstance || subject.Type == typeClusterInstance {
		return m.database(subject, scope)
	}

	capabilities := model.ObjectStorageCapabilities{
		PublicAccess: m.publicAccess(subject, related, scope),
		Unresolved:   unresolvedControls(subject, scope),
	}
	return model.NormalizedResource{
		Address:       subject.Address,
		Provider:      subject.ProviderName,
		Cloud:         model.CloudAWS,
		Family:        model.FamilyObjectStorage,
		Destructive:   subject.IsDestructive(),
		Environment:   declared.Environment(subject, attrTags, model.CloudAWS),
		ObjectStorage: &capabilities,
	}
}

// answer is what the plan says about one question, keeping "no" apart from
// "cannot tell" and from "the source was sensitive".
type answer int

const (
	answerNo answer = iota
	answerYes
	answerUnknown
	answerRedacted
)

// channel is one route by which access can be granted, together with whatever
// blocks that route.
type channel struct {
	grant   answer
	blocked answer
	sources []model.Provenance
}

// publicAccess decides whether the change grants public access.
//
// Known(true) means a grant is present and nothing in the plan blocks it.
// Known(false) means the plan proves prevention. Anything else means a control
// the answer depends on could not be read.
func (m Mapper) publicAccess(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.Fact[bool] {
	block := findType(related, typePublicAccessBlock)
	// The account-wide block overrides every bucket-level setting, so a route
	// it shuts is shut for this bucket too — but only if it is this bucket's
	// account.
	account, accountUnresolved := accountBlockFor(subject, scope)

	acl := aclChannel(related, block, account)
	policy := policyChannel(related, block, account)
	if accountUnresolved {
		// Two blocks for one account contradict each other. That is not the
		// same as there being none: one of them may well shut this route, so
		// neither route can be called open.
		acl.blocked = strongest(acl.blocked, answerUnknown)
		policy.blocked = strongest(policy.blocked, answerUnknown)
	}

	sources := append(acl.sources, policy.sources...)
	sources = append(sources, declared.Source(model.CloudAWS, subject.Address, "bucket", subject.After.Field("bucket")))

	// A grant nothing blocks settles it.
	for _, c := range []channel{acl, policy} {
		if c.grant == answerYes && c.blocked == answerNo {
			return model.Known(true, c.sources...).Canonical()
		}
	}

	// A route that might grant and might not be blocked leaves the question
	// open. Sensitivity is reported separately from ignorance, because a reader
	// can act on one and not the other.
	unreadable := answerNo
	for _, c := range []channel{acl, policy} {
		if c.blocked == answerYes {
			continue
		}
		switch {
		case c.grant == answerRedacted, c.blocked == answerRedacted:
			unreadable = answerRedacted
		case (c.grant == answerUnknown || c.blocked == answerUnknown) && unreadable != answerRedacted:
			unreadable = answerUnknown
		}
	}
	switch unreadable {
	case answerRedacted:
		return model.Redacted[bool](sources...).Canonical()
	case answerUnknown:
		return model.Unknown[bool](sources...).Canonical()
	}

	// No route grants access. That only proves the bucket is not public if the
	// plan also blocks the routes it cannot see — a policy or ACL applied
	// outside this change.
	if blocksEveryRoute(block) || blocksEveryRoute(account) {
		proven := block
		if !blocksEveryRoute(proven) {
			proven = account
		}
		return model.Known(false, blockProvenance(proven)...).Canonical()
	}
	return model.Unknown[bool](sources...).Canonical()
}

// aclChannel reads the bucket ACL and everything that can stop it taking
// effect: the bucket block, the account block, and ownership controls, which
// can disable ACLs for the bucket outright.
func aclChannel(related []terraformplan.ResourceChange, block, account *terraformplan.ResourceChange) channel {
	ownership := findType(related, typeOwnershipControls)
	c := channel{blocked: strongest(
		blockedBy(block, "block_public_acls", "ignore_public_acls"),
		blockedBy(account, "block_public_acls", "ignore_public_acls"),
		aclsDisabled(ownership),
	)}
	if block != nil {
		c.sources = blockProvenance(block)
	}
	if ownership != nil {
		// Consulted, so cited. BucketOwnerEnforced decides this route outright,
		// and a verdict resting on a resource no reference names is one a
		// reader cannot check.
		c.sources = append(c.sources, declared.Source(model.CloudAWS, ownership.Address,
			"rule.object_ownership", ownership.After.Field("rule")))
	}

	acl := findType(related, typeBucketACL)
	if acl == nil {
		return c
	}
	value := acl.After.Field("acl")
	c.sources = append(c.sources, declared.Source(model.CloudAWS, acl.Address, "acl", value))

	switch value.State() {
	case terraformplan.StateKnown:
		if value.Text() == "public-read" || value.Text() == "public-read-write" {
			c.grant = answerYes
		}
	case terraformplan.StateRedacted:
		c.grant = answerRedacted
	default:
		c.grant = answerUnknown
	}
	return c
}

// policyChannel reads the bucket policy and whether policies are blocked, at
// either the bucket or the account level.
func policyChannel(related []terraformplan.ResourceChange, block, account *terraformplan.ResourceChange) channel {
	c := channel{blocked: strongest(
		blockedBy(block, "block_public_policy", "restrict_public_buckets"),
		blockedBy(account, "block_public_policy", "restrict_public_buckets"),
	)}
	if block != nil {
		c.sources = blockProvenance(block)
	}

	policy := findType(related, typeBucketPolicy)
	if policy == nil {
		return c
	}
	document := policy.After.Field("policy")
	c.sources = append(c.sources, declared.Source(model.CloudAWS, policy.Address, "policy", document))

	switch document.State() {
	case terraformplan.StateKnown:
		grants, determined := policyGrantsPublic(document.Text())
		switch {
		case !determined:
			c.grant = answerUnknown
		case grants:
			c.grant = answerYes
		}
	case terraformplan.StateRedacted:
		c.grant = answerRedacted
	default:
		c.grant = answerUnknown
	}
	return c
}

// blockedBy reports whether either of two block flags is set.
func blockedBy(block *terraformplan.ResourceChange, flags ...string) answer {
	if block == nil {
		return answerNo
	}

	result := answerNo
	for _, flag := range flags {
		value := block.After.Field(flag)
		switch value.State() {
		case terraformplan.StateKnown:
			if value.Bool() {
				return answerYes
			}
		case terraformplan.StateRedacted:
			result = answerRedacted
		default:
			if result != answerRedacted {
				result = answerUnknown
			}
		}
	}
	return result
}

// strongest combines several independent blocks. A definite yes from any of
// them shuts the route; otherwise the least readable answer wins, because a
// control that could not be read is not a control that permits.
func strongest(answers ...answer) answer {
	result := answerNo
	for _, candidate := range answers {
		switch {
		case candidate == answerYes:
			return answerYes
		case candidate == answerRedacted:
			result = answerRedacted
		case candidate == answerUnknown && result != answerRedacted:
			result = answerUnknown
		}
	}
	return result
}

// aclsDisabled reports whether ownership controls turn ACLs off for the bucket.
// BucketOwnerEnforced makes an ACL impossible to apply at all, so an ACL
// granting public access cannot take effect and the apply would fail.
func aclsDisabled(controls *terraformplan.ResourceChange) answer {
	if controls == nil {
		return answerNo
	}

	rules := controls.After.Field("rule")
	if rules.Kind() != terraformplan.KindArray || rules.Len() == 0 {
		return unreadable(rules)
	}

	result := answerNo
	for i := range rules.Len() {
		ownership := rules.At(i).Field("object_ownership")
		switch ownership.State() {
		case terraformplan.StateKnown:
			if ownership.Text() == "BucketOwnerEnforced" {
				return answerYes
			}
		case terraformplan.StateRedacted:
			result = answerRedacted
		default:
			if result != answerRedacted {
				result = answerUnknown
			}
		}
	}
	return result
}

func unreadable(value terraformplan.Value) answer {
	switch value.State() {
	case terraformplan.StateRedacted:
		return answerRedacted
	case terraformplan.StateKnown, terraformplan.StateAbsent:
		return answerNo
	default:
		return answerUnknown
	}
}

// blocksEveryRoute reports whether the block shuts both routes, which is what
// makes prevention provable without seeing the policies and ACLs that already
// exist on the bucket.
func blocksEveryRoute(block *terraformplan.ResourceChange) bool {
	if block == nil {
		return false
	}
	for _, flag := range []string{"block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets"} {
		value := block.After.Field(flag)
		if value.State() != terraformplan.StateKnown || !value.Bool() {
			return false
		}
	}
	return true
}

// accountBlockFor returns the account-wide block governing a bucket.
//
// The block belongs to the AWS account its provider instance points at. A
// bucket created through a different instance is in a different account, and
// the block says nothing about it — which matters most in exactly the plans
// that use this resource, where an organization baseline sits alongside
// workload buckets elsewhere.
//
// Two blocks for one provider instance contradict each other. The second
// return value says so, because "no block was found" and "the blocks disagree"
// lead to opposite conclusions: the first leaves a route open, the second
// leaves it in doubt.
func accountBlockFor(subject terraformplan.ResourceChange, scope []terraformplan.ResourceChange) (*terraformplan.ResourceChange, bool) {
	var found *terraformplan.ResourceChange
	for i := range scope {
		if scope[i].Type != typeAccountBlock || beingRemoved(scope[i]) ||
			!sameProviderInstance(subject, scope[i]) {
			continue
		}
		if found != nil {
			return nil, true
		}
		found = &scope[i]
	}
	return found, false
}

// unresolvedControls reports the account-wide block when the plan does not
// contain one for this bucket's account. It overrides every bucket-level
// setting, so without it the plan cannot prove what will actually be reachable
// — only what the change asks for.
func unresolvedControls(subject terraformplan.ResourceChange, scope []terraformplan.ResourceChange) []model.MissingControl {
	if found, unresolved := accountBlockFor(subject, scope); found != nil && !unresolved {
		return nil
	}
	return []model.MissingControl{{
		CheckID: "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK",
		// Not "is not part of this plan": a mapper sees the admissible changes,
		// so a block present only as a read is invisible to it and the sentence
		// would tell a reader to add what they have already added. What is true
		// either way is that this change does not set it.
		Reason: "This change does not set the account-level S3 public access block, " +
			"which overrides bucket-level settings.",
		Cloud: model.CloudAWS,
	}}
}

// findType returns the single control of a kind attached to a subject.
//
// Two controls of one kind on one bucket is a configuration that will fail at
// apply, and there is no principled way to choose between them. Reporting the
// contradiction as ambiguous is the only honest answer; picking one would state
// a determination the plan does not support.
func findType(changes []terraformplan.ResourceChange, resourceType string) *terraformplan.ResourceChange {
	found, ambiguous := findOne(changes, resourceType)
	if ambiguous {
		return nil
	}
	return found
}

func findOne(changes []terraformplan.ResourceChange, resourceType string) (*terraformplan.ResourceChange, bool) {
	var found *terraformplan.ResourceChange
	for i := range changes {
		if changes[i].Type != resourceType || beingRemoved(changes[i]) {
			continue
		}
		if found != nil {
			return nil, true
		}
		found = &changes[i]
	}
	return found, false
}

func blockProvenance(block *terraformplan.ResourceChange) []model.Provenance {
	if block == nil {
		return nil
	}
	out := make([]model.Provenance, 0, 4)
	for _, flag := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		out = append(out, declared.Source(model.CloudAWS, block.Address, flag, block.After.Field(flag)))
	}
	return out
}

// sameProviderInstance reports whether two changes were created through the
// same provider configuration, and therefore in the same AWS account.
//
// An empty provider config key is not the default instance. It is the
// configuration declining to say — which is what a sanitized plan with no
// configuration block leaves behind for everything in it. Treating two
// silences as a match attributed an account-wide block to a bucket in an
// account nobody had named.
//
// The block's own account_id is not a second opinion: the plan never states
// which account the bucket is in, so there is nothing to compare it against.
func sameProviderInstance(subject, control terraformplan.ResourceChange) bool {
	if subject.ProviderConfigKey == "" || control.ProviderConfigKey == "" {
		return false
	}
	return subject.ProviderConfigKey == control.ProviderConfigKey
}

// beingRemoved reports that a change destroys its object outright. Such a
// control will not exist after apply, so it protects nothing — and a plan that
// removes a block while granting public access is exactly the change worth
// reporting. A replacement is not a removal: the object is there afterwards.
func beingRemoved(change terraformplan.ResourceChange) bool {
	return change.IsDestructive() && !change.IsReplace()
}

// policyGrantsPublic reports whether a bucket policy grants access to everyone,
// and whether that could be determined at all.
//
// A statement naming everyone but carrying a condition is not proof of public
// access: the condition may restrict it to a VPC endpoint or an organization.
// Reporting such a policy as public produces findings nobody trusts, so it is
// reported as undetermined instead.
func policyGrantsPublic(document string) (grants, determined bool) {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(document), &parsed); err != nil || len(parsed.Statement) == 0 {
		return false, false
	}

	statements, ok := decodeStatements(parsed.Statement)
	if !ok {
		return false, false
	}

	for _, statement := range statements {
		if statement.Effect != "Allow" {
			continue
		}
		if len(statement.NotPrincipal) > 0 {
			// Everyone except somebody is a shape this build does not reason
			// about.
			return false, false
		}
		if !principalIsEveryone(statement.Principal) {
			continue
		}
		if hasConditions(statement.Condition) {
			return false, false
		}
		if deniesEveryone(statements) {
			// An explicit deny overrides an allow, so this policy grants
			// nothing to everyone — but which actions each statement covers
			// decides the rest, and this build does not model that. A policy
			// with no public allow at all needs none of this reasoning.
			return false, false
		}
		return true, true
	}
	return false, true
}

// deniesEveryone reports an unconditional deny to everyone, which overrides any
// allow and makes the policy's effect something this build does not model well
// enough to call public.
func deniesEveryone(statements []policyStatement) bool {
	for _, statement := range statements {
		if statement.Effect == "Deny" && principalIsEveryone(statement.Principal) &&
			!hasConditions(statement.Condition) {
			return true
		}
	}
	return false
}

// hasConditions reports whether a condition block actually restricts anything.
// An empty block is written often enough, and it restricts nothing.
func hasConditions(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var conditions map[string]json.RawMessage
	if err := json.Unmarshal(raw, &conditions); err != nil {
		// Unreadable rather than absent: something is there.
		return true
	}
	return len(conditions) > 0
}

type policyStatement struct {
	Effect       string          `json:"Effect"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Condition    json.RawMessage `json:"Condition"`
}

func decodeStatements(raw json.RawMessage) ([]policyStatement, bool) {
	var many []policyStatement
	if err := json.Unmarshal(raw, &many); err == nil {
		return many, true
	}
	var one policyStatement
	if err := json.Unmarshal(raw, &one); err == nil {
		return []policyStatement{one}, true
	}
	return nil, false
}

// principalIsEveryone reports whether a principal names the anonymous public,
// in any of the spellings AWS accepts.
func principalIsEveryone(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}

	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return text == "*"
	}

	var byType map[string]json.RawMessage
	if err := json.Unmarshal(raw, &byType); err != nil {
		return false
	}
	entry, present := byType["AWS"]
	if !present {
		return false
	}
	if err := json.Unmarshal(entry, &text); err == nil {
		return text == "*"
	}
	var list []string
	if err := json.Unmarshal(entry, &list); err != nil {
		return false
	}
	for _, principal := range list {
		if principal == "*" {
			return true
		}
	}
	return false
}

// Governs reports the buckets an account-wide block applies to.
//
// It names none of them: it is scoped to the provider instance, not to a
// resource, so the configuration records no reference and the reference-based
// default finds nothing. Without this, an account block in a plan whose buckets
// were all judged some other way would be reported as a resource nothing
// examined — which is false, since every bucket verdict consults it.
func (m Mapper) Governs(resource terraformplan.ResourceChange,
	scope []terraformplan.ResourceChange) []string {

	if resource.Type != typeAccountBlock {
		return nil
	}

	var buckets []string
	for i := range scope {
		if scope[i].Type == typeBucket && sameProviderInstance(scope[i], resource) {
			buckets = append(buckets, scope[i].Address)
		}
	}
	return buckets
}

// Bindings declares which S3 resources govern which, and through what.
//
// Every bucket-scoped control carries the bucket's name or id in "bucket", and
// that argument alone is the application. A policy document interpolating a
// bucket ARN, or an ordering dependency, names a bucket without being applied
// to it.
//
// A bucket declares nothing: it makes no claims about what governs it, so a
// reference it writes is a mention. An account-wide block declares nothing
// either — it is scoped to the provider instance rather than to a resource,
// and says so through Governs.
func (Mapper) Bindings() []declared.Binding {
	var relations []declared.Binding
	for _, control := range []string{
		typePublicAccessBlock, typeBucketPolicy, typeBucketACL, typeOwnershipControls,
	} {
		relations = append(relations, declared.Binding{
			From: control, Attribute: "bucket", To: typeBucket})
	}
	// An ingress rule names the group it belongs to, and the attribute it names
	// it by is the provider's own: a rule written against a group the plan does
	// not contain reaches nothing, which is the honest answer rather than a rule
	// attached to whichever group happened to be nearby.
	relations = append(relations, declared.Binding{
		From: typeIngressRule, Attribute: "security_group_id", To: typeSecurityGroup})

	// An Aurora instance names the cluster it belongs to, and the cluster is
	// what carries the security groups -- the schema puts the endpoint switch on
	// the instance and the allow list on the cluster. This is the edge that lets
	// a cluster defer to the instances that answer for it.
	//
	// No binding is declared from a database to its security groups, and that is
	// deliberate. An edge there would make a group's own verdict defer to the
	// databases in front of it, so an Aurora cluster with no instance in the
	// plan would read as answered-for by a judged security group when nothing
	// answered. The database mapper reaches its groups through the references
	// the configuration records, which exist whether or not a binding does, so
	// the correlation is kept and the spurious deferral is not.
	return append(relations, declared.Binding{
		From: typeClusterInstance, Attribute: attrClusterIdentifier, To: typeRDSCluster})
}

// Environment reads a resource's declared environment with this provider's
// vocabulary, so a control resource is asked the same question as a subject.
func (m Mapper) Environment(change terraformplan.ResourceChange) model.Fact[string] {
	return declared.Environment(change, attrTags, model.CloudAWS)
}
