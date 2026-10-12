package policy_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
)

func stepsOf(t *testing.T, result policy.Result, rule, address string) []evidence.VerificationStep {
	t.Helper()
	for _, f := range result.Findings {
		if f.RuleID == rule && f.Resource != nil && f.Resource.Address == address {
			return evidence.Canonical(evidence.Bundle{Findings: []evidence.Finding{f}}).Findings[0].VerificationSteps
		}
	}
	t.Fatalf("no %s finding about %s", rule, address)
	return nil
}

// findingOf is the one finding of a rule about an address, in canonical order.
func findingOf(t *testing.T, result policy.Result, rule, address string) evidence.Finding {
	t.Helper()
	for _, f := range result.Findings {
		if f.RuleID == rule && f.Resource != nil && f.Resource.Address == address {
			return evidence.Canonical(evidence.Bundle{Findings: []evidence.Finding{f}}).Findings[0]
		}
	}
	t.Fatalf("no %s finding about %s", rule, address)
	return evidence.Finding{}
}

// assertSameBesidesSteps is the "nowhere else" half of a criterion 3 pair: with
// the steps removed, the two findings are identical.
func assertSameBesidesSteps(t *testing.T, a, b evidence.Finding) {
	t.Helper()
	a.VerificationSteps, b.VerificationSteps = nil, nil
	if !reflect.DeepEqual(a, b) {
		t.Errorf("the findings differ beyond their steps\n a %+v\n b %+v", a, b)
	}
}

func assertSteps(t *testing.T, got []evidence.VerificationStep, want ...evidence.VerificationStep) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("steps\n got %v\nwant %v", got, want)
	}
}

func step(fact string, m evidence.VerificationMethod) evidence.VerificationStep {
	return evidence.VerificationStep{Fact: fact, Method: m}
}

// The model and evidence spell every shared method identically, because the
// policy converts one to the other by type conversion.
func TestEveryModelMethodIsAnEvidenceMethod(t *testing.T) {
	for _, m := range []model.Method{model.MethodStated, model.MethodProviderDefault,
		model.MethodPolicyDocument, model.MethodReferenceResolved, model.MethodDocumentedTable,
		model.MethodPriorState, model.MethodConfigurationUnrecorded} {
		if !evidence.VerificationMethod(m).Valid() {
			t.Errorf("model method %q is not a valid evidence method", m)
		}
	}
}

func TestADatabaseBehindAnOpenGroupNamesTheHopAndTheGate(t *testing.T) {
	result := evaluateDatabase(t, "aws", "real-databases", requiringPrivate())
	assertSteps(t, stepsOf(t, result, policy.RuleDatabasePublicReachable, "aws_db_instance.reachable"),
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodReferenceResolved),
		step("database.port", evidence.MethodDocumentedTable),
		step("database.public_endpoint", evidence.MethodPlanStatedValue),
		step("network.public_ingress", evidence.MethodPlanStatedValue),
	)
}

// Criterion 4, the stated half: rds-port-written writes port 1433 and the group
// in front of it opens 1433 alone, so the port decided and its step says the
// plan stated it. The engine-derived half is the test above.
func TestAStatedPortIsStatedInTheStep(t *testing.T) {
	result := evaluateDatabase(t, "aws", "rds-port-written", requiringPrivate())
	assertSteps(t, stepsOf(t, result, policy.RuleDatabasePublicReachable, "aws_db_instance.offport"),
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodReferenceResolved),
		step("database.port", evidence.MethodPlanStatedValue),
		step("database.public_endpoint", evidence.MethodPlanStatedValue),
		step("network.public_ingress", evidence.MethodPlanStatedValue),
	)
}

// Criterion 3, GCP ipv4_enabled: the pair differs in that one method and in
// nothing else.
func TestTheIPv4DefaultChangesOneStepAndNothingElse(t *testing.T) {
	written := stepsOf(t, evaluateDatabase(t, "gcp", "real-databases", requiringPrivate()),
		policy.RuleDatabasePublicReachable, "google_sql_database_instance.reachable")
	unwritten := stepsOf(t, evaluateDatabase(t, "gcp", "real-databases-ipv4-unwritten", requiringPrivate()),
		policy.RuleDatabasePublicReachable, "google_sql_database_instance.default_endpoint")
	assertSteps(t, written,
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodPlanStatedValue),
		step("database.public_endpoint", evidence.MethodPlanStatedValue),
	)
	assertSteps(t, unwritten,
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodPlanStatedValue),
		step("database.public_endpoint", evidence.MethodProviderDefault),
	)
}

// Criterion 3, GCP direction. fw-public-direction-written and
// fw-public-priority-written are the pair: identical plans whose configurations
// differ only in writing `direction = "INGRESS"`. The findings differ in the
// method of that step and nowhere else.
//
// fw-public-direction-omitted leaves the field out of after altogether, a shape
// no real plan has, so it is not the half of the pair; it still reads as the
// default. fw-public, from milestone 08, records no allow and no source in its
// configuration, so the plan cannot attribute what the grant rests on and the
// step says so -- it read provider-default until the adversarial review.
func TestTheDirectionDefaultChangesOneStepAndNothingElse(t *testing.T) {
	written := evaluateNetwork(t, "gcp", "fw-public-direction-written", declaringPort())
	unwritten := evaluateNetwork(t, "gcp", "fw-public-priority-written", declaringPort())
	assertSameBesidesSteps(t,
		findingOf(t, written, policy.RuleNetworkPublicIngress, "google_compute_firewall.web"),
		findingOf(t, unwritten, policy.RuleNetworkPublicIngress, "google_compute_firewall.web"))
	assertSteps(t, stepsOf(t, written, policy.RuleNetworkPublicIngress, "google_compute_firewall.web"),
		step("contract.network.public_ports", evidence.MethodIntentComparison),
		step("network.public_ingress", evidence.MethodPlanStatedValue))
	assertSteps(t, stepsOf(t, unwritten, policy.RuleNetworkPublicIngress, "google_compute_firewall.web"),
		step("contract.network.public_ports", evidence.MethodIntentComparison),
		step("network.public_ingress", evidence.MethodProviderDefault))

	omitted := stepsOf(t, evaluateNetwork(t, "gcp", "fw-public-direction-omitted", declaringPort()),
		policy.RuleNetworkPublicIngress, "google_compute_firewall.web")
	assertSteps(t, omitted,
		step("contract.network.public_ports", evidence.MethodIntentComparison),
		step("network.public_ingress", evidence.MethodProviderDefault))
	unrecorded := stepsOf(t, evaluateNetwork(t, "gcp", "fw-public", declaringPort()),
		policy.RuleNetworkPublicIngress, "google_compute_firewall.web")
	assertSteps(t, unrecorded,
		step("contract.network.public_ports", evidence.MethodIntentComparison),
		step("network.public_ingress", evidence.MethodConfigurationUnrecorded))
}

func TestAPolicyDocumentGrantIsInterpretedInTheStep(t *testing.T) {
	assertSteps(t, stepsOf(t, evaluate(t, "aws", "public-policy"), policy.RuleStoragePublic, "aws_s3_bucket.assets"),
		step("contract.object_storage.exposure", evidence.MethodIntentComparison),
		step("object_storage.public_access", evidence.MethodPolicyDocumentInterpreted))
}

// The ACL channel's pair: public-acl-flags-written writes every bucket block
// flag, public-acl leaves them to the provider. The grant rests on the flags
// answering "not blocked", so the step follows them.
func TestTheBlockFlagDefaultChangesTheACLStep(t *testing.T) {
	assertSteps(t, stepsOf(t, evaluate(t, "aws", "public-acl-flags-written"), policy.RuleStoragePublic, "aws_s3_bucket.assets"),
		step("contract.object_storage.exposure", evidence.MethodIntentComparison),
		step("object_storage.public_access", evidence.MethodPlanStatedValue))
	assertSteps(t, stepsOf(t, evaluate(t, "aws", "public-acl"), policy.RuleStoragePublic, "aws_s3_bucket.assets"),
		step("contract.object_storage.exposure", evidence.MethodIntentComparison),
		step("object_storage.public_access", evidence.MethodProviderDefault))
	assertSameBesidesSteps(t,
		findingOf(t, evaluate(t, "aws", "public-acl-flags-written"), policy.RuleStoragePublic, "aws_s3_bucket.assets"),
		findingOf(t, evaluate(t, "aws", "public-acl"), policy.RuleStoragePublic, "aws_s3_bucket.assets"))
}

func TestEveryGenericRuleSaysHowItKnows(t *testing.T) {
	resource := model.NormalizedResource{
		Address: "aws_s3_bucket.assets", Provider: "registry.terraform.io/hashicorp/aws",
		Cloud: model.CloudAWS, Family: model.FamilyObjectStorage, Destructive: true,
		Environment: model.Known("production", model.MethodStated,
			model.Provenance{ResourceAddress: "aws_s3_bucket.assets", AttributePath: "tags.environment"}),
	}
	graph := model.Graph{Resources: []model.NormalizedResource{resource}}
	contract := intent.Contract{SchemaVersion: "1.2", ChangeID: "t", Environment: "staging",
		AllowedClouds: []string{"gcp"}, DestructiveChanges: intent.DestructiveForbidden}

	assertSteps(t, stepsOf(t, policy.DestructiveChange(contract, graph), policy.RuleDestructiveChange, resource.Address),
		step("change.destructive", evidence.MethodPlanAction),
		step("contract.destructive_changes", evidence.MethodIntentComparison))
	assertSteps(t, stepsOf(t, policy.CloudAllowed(contract, graph), policy.RuleCloudNotAllowed, resource.Address),
		step("contract.allowed_clouds", evidence.MethodIntentComparison),
		step("resource.cloud", evidence.MethodPlanStatedValue))
	assertSteps(t, stepsOf(t, policy.EnvironmentMatch(contract, graph), policy.RuleEnvironmentMismatch, resource.Address),
		step("contract.environment", evidence.MethodIntentComparison),
		step("resource.environment", evidence.MethodPlanStatedValue))
}

// Review Focus 4: a gate admitting every usable port decides without the port,
// so the finding names no port step; a gate open on the port alone names one.
func TestThePortStepAppearsOnlyWhenThePortDecided(t *testing.T) {
	hasPortStep := func(r policy.Result) bool {
		for _, f := range r.Findings {
			for _, s := range f.VerificationSteps {
				if s.Fact == "database.port" {
					return true
				}
			}
		}
		return false
	}
	contract := declaringExposure(intent.ExposurePrivate)

	everyPort := policy.DatabaseExposure(contract, reachable(known(true), unknownBool(), knownPort(5432),
		group("aws_security_group.db", known(true), rngR(model.ProtocolTCP, 0, 65535))))
	if len(everyPort.Findings) == 0 {
		t.Fatal("a group open on every port in front of a public endpoint produced no finding")
	}
	if hasPortStep(everyPort) {
		t.Error("every port was admitted, so the port decided nothing, and a port step was emitted")
	}

	onePort := policy.DatabaseExposure(contract, reachable(known(true), unknownBool(), knownPort(5432),
		group("aws_security_group.db", known(true), rngR(model.ProtocolTCP, 5432, 5432))))
	if len(onePort.Findings) == 0 {
		t.Fatal("a group open on the database port produced no finding")
	}
	if !hasPortStep(onePort) {
		t.Error("the port decided reachability and no port step was emitted")
	}
}

// Review Focus 1: a KNOWN fact with no method reaches render as an error, not
// as a step.
func TestAZeroMethodNeverReachesABundle(t *testing.T) {
	// The zero method, passed explicitly: what a mapper that forgot would emit.
	resource := model.NormalizedResource{
		Address: "aws_s3_bucket.assets", Provider: "registry.terraform.io/hashicorp/aws",
		Cloud: model.CloudAWS, Family: model.FamilyObjectStorage,
		ObjectStorage: &model.ObjectStorageCapabilities{PublicAccess: model.Known(true, model.Method(""),
			model.Provenance{ResourceAddress: "aws_s3_bucket.assets", AttributePath: "acl"})},
	}
	result := policy.StorageExposure(privateStorage, model.Graph{Resources: []model.NormalizedResource{resource}})
	bundle := evidence.Bundle{SchemaVersion: evidence.SchemaVersion, Decision: evidence.DecisionBlock,
		Summary: "s", Subject: evidence.Subject{IntentSource: "i", PlanFormatVersion: "1.x",
			PlanDigest:   "sha256:" + strings.Repeat("0", 64),
			IntentDigest: "sha256:" + strings.Repeat("0", 64)},
		Verification: []evidence.Verification{{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"}},
		Findings:     result.Findings, Unknowns: []evidence.Unknown{}}
	// The method is what must be refused, not some other part of the step.
	if err := bundle.Validate(); err == nil || !strings.Contains(err.Error(), "verification_steps") ||
		!strings.Contains(err.Error(), "unrecognized verification method") {
		t.Errorf("a fact with no method validated, or was refused for another reason: %v", err)
	}
}
