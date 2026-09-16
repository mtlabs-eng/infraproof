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
// controls it folds into a bucket.
func (Mapper) Interprets(resourceType string) bool {
	switch resourceType {
	case typeBucket, typePublicAccessBlock, typeBucketPolicy,
		typeBucketACL, typeOwnershipControls, typeAccountBlock:
		return true
	}
	return false
}

// IsSubject reports that only the bucket is normalized in its own right.
func (Mapper) IsSubject(resourceType string) bool { return resourceType == typeBucket }

// Map normalizes a bucket together with the controls that refer to it.
func (m Mapper) Map(subject terraformplan.ResourceChange, related, scope []terraformplan.ResourceChange) model.NormalizedResource {
	capabilities := model.ObjectStorageCapabilities{
		PublicAccess: m.publicAccess(subject, related),
		Unresolved:   unresolvedControls(scope),
	}
	return model.NormalizedResource{
		Address:       subject.Address,
		Provider:      subject.ProviderName,
		Cloud:         model.CloudAWS,
		Family:        model.FamilyObjectStorage,
		Destructive:   subject.IsDestructive(),
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
func (m Mapper) publicAccess(subject terraformplan.ResourceChange, related []terraformplan.ResourceChange) model.Fact[bool] {
	block := findType(related, typePublicAccessBlock)
	acl := aclChannel(related, block)
	policy := policyChannel(related, block)

	sources := append(acl.sources, policy.sources...)
	sources = append(sources, provenance(subject.Address, "bucket"))

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
	if blocksEveryRoute(block) {
		return model.Known(false, blockProvenance(block)...).Canonical()
	}
	return model.Unknown[bool](sources...).Canonical()
}

// aclChannel reads the bucket ACL and whether ACLs are blocked.
func aclChannel(related []terraformplan.ResourceChange, block *terraformplan.ResourceChange) channel {
	c := channel{blocked: blockedBy(block, "block_public_acls", "ignore_public_acls")}
	if block != nil {
		c.sources = blockProvenance(block)
	}

	acl := findType(related, typeBucketACL)
	if acl == nil {
		return c
	}
	value := acl.After.Field("acl")
	c.sources = append(c.sources, provenance(acl.Address, "acl"))

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

// policyChannel reads the bucket policy and whether policies are blocked.
func policyChannel(related []terraformplan.ResourceChange, block *terraformplan.ResourceChange) channel {
	c := channel{blocked: blockedBy(block, "block_public_policy", "restrict_public_buckets")}
	if block != nil {
		c.sources = blockProvenance(block)
	}

	policy := findType(related, typeBucketPolicy)
	if policy == nil {
		return c
	}
	document := policy.After.Field("policy")
	c.sources = append(c.sources, provenance(policy.Address, "policy"))

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

// unresolvedControls reports the account-wide block when the plan does not
// contain it. It overrides every bucket-level setting, so without it the plan
// cannot prove what will actually be reachable — only what the change asks for.
func unresolvedControls(scope []terraformplan.ResourceChange) []model.MissingControl {
	if findType(scope, typeAccountBlock) != nil {
		return nil
	}
	return []model.MissingControl{{
		CheckID: "AWS_ACCOUNT_PUBLIC_ACCESS_BLOCK",
		Reason:  "The account-level S3 public access block is not part of this plan and overrides bucket-level settings.",
		Cloud:   model.CloudAWS,
	}}
}

func findType(changes []terraformplan.ResourceChange, resourceType string) *terraformplan.ResourceChange {
	for i := range changes {
		if changes[i].Type == resourceType {
			return &changes[i]
		}
	}
	return nil
}

func blockProvenance(block *terraformplan.ResourceChange) []model.Provenance {
	if block == nil {
		return nil
	}
	out := make([]model.Provenance, 0, 4)
	for _, flag := range []string{"block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"} {
		out = append(out, provenance(block.Address, flag))
	}
	return out
}

func provenance(address, attribute string) model.Provenance {
	return model.Provenance{ResourceAddress: address, AttributePath: attribute, Cloud: model.CloudAWS}
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
		if len(statement.Condition) > 0 {
			return false, false
		}
		return true, true
	}
	return false, true
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
