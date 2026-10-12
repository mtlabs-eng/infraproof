package policy_test

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/intent"
	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/policy"
	"github.com/mtlabs-eng/infraproof/internal/providers"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
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

// Criterion 3, GCP ipv4_enabled: a true pair. real-sql-ipv4-written and
// real-sql-ipv4-unwritten are real create plans of one instance whose
// configurations differ only in writing `ipv4_enabled = true` inside a written
// ip_configuration; the plans' after values are identical. The findings differ
// in the method of that step and nowhere else.
//
// This used to compare two different instances from two different plans, so
// "nowhere else" could not have held and was never asserted.
func TestTheIPv4DefaultChangesOneStepAndNothingElse(t *testing.T) {
	written := evaluateDatabase(t, "gcp", "real-sql-ipv4-written", requiringPrivate())
	unwritten := evaluateDatabase(t, "gcp", "real-sql-ipv4-unwritten", requiringPrivate())
	const address = "google_sql_database_instance.db"
	assertSameBesidesSteps(t,
		findingOf(t, written, policy.RuleDatabasePublicReachable, address),
		findingOf(t, unwritten, policy.RuleDatabasePublicReachable, address))
	assertSteps(t, stepsOf(t, written, policy.RuleDatabasePublicReachable, address),
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodPlanStatedValue),
		step("database.public_endpoint", evidence.MethodPlanStatedValue),
	)
	assertSteps(t, stepsOf(t, unwritten, policy.RuleDatabasePublicReachable, address),
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

// ENVIRONMENT_MISMATCH through the mapper rather than a fact built by hand: the
// real plan rds-partial-allow-list writes tags = { environment = "staging" },
// so the environment is stated. The same plan without its configuration records
// nothing about who wrote the tag.
func TestAnEnvironmentReadFromAPlanSaysHowItKnows(t *testing.T) {
	contract := intent.Contract{SchemaVersion: "1.2", ChangeID: "t", Environment: "production"}
	plan := planAt(t, "aws", "rds-partial-allow-list")
	assertSteps(t, stepsOf(t, policy.EnvironmentMatch(contract, providers.Normalize(plan, providers.Default())),
		policy.RuleEnvironmentMismatch, "aws_db_instance.partial"),
		step("contract.environment", evidence.MethodIntentComparison),
		step("resource.environment", evidence.MethodPlanStatedValue))

	for i := range plan.ResourceChanges {
		plan.ResourceChanges[i].Declared = false
		plan.ResourceChanges[i].Configured = false
		plan.ResourceChanges[i].Stated = nil
	}
	assertSteps(t, stepsOf(t, policy.EnvironmentMatch(contract, providers.Normalize(plan, providers.Default())),
		policy.RuleEnvironmentMismatch, "aws_db_instance.partial"),
		step("contract.environment", evidence.MethodIntentComparison),
		step("resource.environment", evidence.MethodConfigurationUnrecorded))
}

func planAt(t *testing.T, cloud, fixture string) terraformplan.Plan {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "providers", cloud, "testdata", fixture+".json"))
	if err != nil {
		t.Fatalf("reading %s: %v", fixture, err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %s: %v", fixture, err)
	}
	return plan
}

// A gate open on every usable port reaches a database whatever it listens on, so
// when the port is unknown, or is a value that is not a port, the port did not
// decide and the finding names no port step. A step there would carry the method
// of a port nobody used -- for an unknown one, no method at all.
func TestAnUnusablePortBehindAGateOpenOnEveryPortNamesNoPortStep(t *testing.T) {
	for name, port := range map[string]model.Fact[int]{
		"unknown": unknownPort(),
		"zero":    knownPort(0),
	} {
		result := policy.DatabaseExposure(declaringExposure(intent.ExposurePrivate),
			reachable(known(true), unknownBool(), port,
				group("aws_security_group.db", known(true), rngR(model.ProtocolTCP, 1, 65535))))
		if len(result.Findings) == 0 {
			t.Fatalf("%s: no finding for a gate open on every usable port", name)
		}
		for _, f := range result.Findings {
			for _, s := range f.VerificationSteps {
				if s.Fact == "database.port" {
					t.Errorf("%s port: the finding names a port step %v, but the port did not decide", name, s)
				}
			}
		}
	}
}

// D2: reference-resolved means a value obtainable only by resolving a
// reference -- the security groups a database reaches through
// vpc_security_group_ids. A grant written on its own ACL, IAM or firewall
// resource is stated; the reference that joins it to a bucket or a server only
// locates where it applies, and does not relabel it.
func TestAJoinThatOnlyLocatesAGrantIsNotReferenceResolved(t *testing.T) {
	assertSteps(t, stepsOf(t, evaluate(t, "aws", "public-acl-flags-written"), policy.RuleStoragePublic, "aws_s3_bucket.assets"),
		step("contract.object_storage.exposure", evidence.MethodIntentComparison),
		step("object_storage.public_access", evidence.MethodPlanStatedValue))
	assertSteps(t, stepsOf(t, evaluate(t, "gcp", "public-iam-member-prevention-written"), policy.RuleStoragePublic, "google_storage_bucket.assets"),
		step("contract.object_storage.exposure", evidence.MethodIntentComparison),
		step("object_storage.public_access", evidence.MethodPlanStatedValue))
	assertSteps(t, stepsOf(t, evaluateDatabase(t, "azure", "sql-reachable", requiringPrivate()),
		policy.RuleDatabasePublicReachable, "azurerm_mssql_server.db"),
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodPlanStatedValue),
		step("database.public_endpoint", evidence.MethodPlanStatedValue))
}

// The new methods reach a finding. real-rds-unwritten-update is a real update
// plan whose Aurora instance writes neither publicly_accessible nor port, both
// carried from state; the group in front of it opens 5432 alone, so the port
// decided.
func TestValuesCarriedFromStateArePriorStateInTheSteps(t *testing.T) {
	result := evaluateDatabase(t, "aws", "real-rds-unwritten-update", requiringPrivate())
	assertSteps(t, stepsOf(t, result, policy.RuleDatabasePublicReachable, "aws_rds_cluster_instance.i"),
		step("contract.database.exposure", evidence.MethodIntentComparison),
		step("database.admitted_by", evidence.MethodReferenceResolved),
		step("database.port", evidence.MethodPriorState),
		step("database.public_endpoint", evidence.MethodPriorState),
		step("network.public_ingress", evidence.MethodPlanStatedValue),
	)
}
