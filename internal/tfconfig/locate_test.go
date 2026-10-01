package tfconfig_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
	"github.com/mtlabs-eng/infraproof/internal/tfconfig"
)

// loadPlan parses a plan fixture. Tests name fixtures; production code never
// does.
func loadPlan(t *testing.T, parts ...string) terraformplan.Plan {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(parts...))
	if err != nil {
		t.Fatalf("reading plan: %v", err)
	}
	plan, err := terraformplan.Parse(raw)
	if err != nil {
		t.Fatalf("parsing plan: %v", err)
	}
	return plan
}

// about returns a bundle with one finding about an address, whose evidence
// names a resource and an attribute path.
func about(address, evidenceAddress, path string) evidence.Bundle {
	return evidence.Bundle{
		SchemaVersion: evidence.SchemaVersion,
		Decision:      evidence.DecisionBlock,
		Summary:       "A change the tests do not care about.",
		Subject: evidence.Subject{
			IntentSource:      "intent.json",
			IntentDigest:      "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			PlanFormatVersion: "1.2",
			PlanDigest:        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
		Verification: []evidence.Verification{
			{Name: "terraform_plan", Status: evidence.VerificationVerified, Method: "terraform-plan-json"},
		},
		Findings: []evidence.Finding{{
			RuleID:      "STORAGE_PUBLIC",
			Severity:    evidence.SeverityCritical,
			Disposition: evidence.DispositionBlock,
			Claim:       "A claim the tests do not care about.",
			Resource: &evidence.Resource{
				Address:  address,
				Provider: "registry.terraform.io/hashicorp/aws",
				Cloud:    evidence.CloudAWS,
			},
			Evidence: []evidence.EvidenceRef{{
				Source:          "terraform_plan",
				ResourceAddress: evidenceAddress,
				Path:            path,
			}},
			Remediation: "A remediation the tests do not care about.",
		}},
		Unknowns: []evidence.Unknown{},
	}
}

// annotate runs the locator and fails on an error, returning the one finding.
func annotate(t *testing.T, bundle evidence.Bundle, plan terraformplan.Plan, root string) evidence.Finding {
	t.Helper()
	located, err := tfconfig.Annotate(bundle, plan, root)
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if err := located.Validate(); err != nil {
		t.Fatalf("the located bundle is invalid: %v", err)
	}
	return located.Findings[0]
}

// nothingLocated asserts that a finding carries no position at all.
//
// Both fields, because they are reached by different code: the resource lookup
// is the first call, which fills the directory cache, and the evidence lookup is
// the second, which reads it. Independent review found that every refusal test
// here checked only the first, so a mutation that made the cache report an
// unresolved directory as resolved -- locating a module that climbed out of the
// configuration directory inside the root module -- survived the whole suite.
func nothingLocated(t *testing.T, finding evidence.Finding, because string) {
	t.Helper()
	if finding.Resource != nil && finding.Resource.Location != nil {
		t.Fatalf("%s was located at %+v", because, finding.Resource.Location)
	}
	for i, ref := range finding.Evidence {
		if ref.Location != nil {
			t.Fatalf("%s was located through evidence[%d] at %+v", because, i, ref.Location)
		}
	}
}

// at compares a location with what a reader would see by opening the file.
func at(t *testing.T, got *evidence.Location, file string, line int) {
	t.Helper()
	if got == nil {
		t.Fatalf("no location, want %s:%d", file, line)
	}
	if got.File != file || got.Line != line {
		t.Fatalf("location = %s:%d, want %s:%d", got.File, got.Line, file, line)
	}
}

// TestLocatesADeclarationInTheRootModule covers the ordinary case, against the
// configuration Terraform itself turned into this plan.
func TestLocatesADeclarationInTheRootModule(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")

	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	at(t, finding.Resource.Location, "main.tf", 11)
	at(t, finding.Evidence[0].Location, "main.tf", 12)
}

// TestLocatesADeclarationInsideALocalModule covers the milestone's second
// criterion: a finding inside module.storage lands in that module's directory,
// which is found by following the source the plan states.
func TestLocatesADeclarationInsideALocalModule(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")

	finding := annotate(t, about(
		"module.storage.terraform_data.inner",
		"module.storage.terraform_data.inner",
		"input"), plan, root)

	at(t, finding.Resource.Location, "modules/storage/main.tf", 1)
	at(t, finding.Evidence[0].Location, "modules/storage/main.tf", 2)
}

// TestLocatesThroughAChainOfModules covers a module inside a module: the
// directory is the root's, joined with each source along the way.
func TestLocatesThroughAChainOfModules(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")

	finding := annotate(t, about(
		"module.storage.module.inner.terraform_data.inner",
		"module.storage.module.inner.terraform_data.inner",
		"input"), plan, root)

	at(t, finding.Resource.Location, "modules/storage/inner/main.tf", 3)
	at(t, finding.Evidence[0].Location, "modules/storage/inner/main.tf", 4)
}

// TestLocatesThroughARepeatedModule covers the join the two halves of a plan
// need: resource_changes spells module.keyed["eu"] and configuration keys the
// one call module.keyed. Both instances are declared in one directory.
func TestLocatesThroughARepeatedModule(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")

	finding := annotate(t, about(
		`module.keyed["eu"].terraform_data.inner`,
		`module.keyed["eu"].terraform_data.inner`,
		"input"), plan, root)
	at(t, finding.Resource.Location, "modules/storage/main.tf", 1)

	nested := annotate(t, about(
		`module.keyed["eu"].module.inner.terraform_data.inner`,
		`module.keyed["eu"].module.inner.terraform_data.inner`,
		"input"), plan, root)
	at(t, nested.Resource.Location, "modules/storage/inner/main.tf", 3)
}

// TestLocatesAFindingAgainstAShippedAwsConfiguration covers what a reader
// actually gets: the finding points at the bucket's block, and the evidence at
// the argument that decided it, in a different resource.
func TestLocatesAFindingAgainstAShippedAwsConfiguration(t *testing.T) {
	root := filepath.Join("testdata", "aws")
	plan := loadPlan(t, "..", "providers", "aws", "testdata", "public-acl.json")

	finding := annotate(t, about("aws_s3_bucket.assets", "aws_s3_bucket_acl.assets", "acl"), plan, root)

	at(t, finding.Resource.Location, "main.tf", 6)
	at(t, finding.Evidence[0].Location, "main.tf", 25)
}

// TestLocatesANestedEvidencePathByItsFirstSegment covers an evidence path that
// names something inside an argument. The argument is where a reader goes; what
// is inside it is not written on its own line in the general case, and this
// build does not evaluate the expression to find out.
func TestLocatesANestedEvidencePathByItsFirstSegment(t *testing.T) {
	root := filepath.Join("testdata", "aws")
	plan := loadPlan(t, "..", "providers", "aws", "testdata", "public-acl.json")

	finding := annotate(t, about("aws_s3_bucket.assets", "aws_s3_bucket.assets", "tags.environment"), plan, root)

	at(t, finding.Evidence[0].Location, "main.tf", 9)
}

// TestFallsBackToTheBlockWhenAnArgumentIsNotWrittenThere covers the decision
// this milestone took before implementation: an argument set from a variable, a
// local, a module input or a dynamic block is not in the block, and the answer
// is the block's line rather than nothing and rather than a guess.
func TestFallsBackToTheBlockWhenAnArgumentIsNotWrittenThere(t *testing.T) {
	root := filepath.Join("testdata", "aws")
	plan := loadPlan(t, "..", "providers", "aws", "testdata", "public-acl.json")

	finding := annotate(t, about("aws_s3_bucket.assets", "aws_s3_bucket_acl.assets", "expected_bucket_owner"), plan, root)

	at(t, finding.Evidence[0].Location, "main.tf", 23)
}

// TestReportsNoLocationWhenTheDeclarationHasMoved is the criterion the whole
// milestone turns on. The configuration has moved on since the plan was made,
// and the nearest block is not the answer: nothing is.
func TestReportsNoLocationWhenTheDeclarationHasMoved(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")
	root := filepath.Join("testdata", "renamed")

	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	nothingLocated(t, finding, "a moved declaration")
}

// TestReportsNoLocationWhenTwoDeclarationsMatch covers the file that answers
// twice. Terraform refuses it, and a build that cannot prove these are the files
// the plan came from may still be handed it; two answers is not an answer.
func TestReportsNoLocationWhenTwoDeclarationsMatch(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")
	root := filepath.Join("testdata", "ambiguous")

	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	nothingLocated(t, finding, "an ambiguous declaration")
}

// TestReadsNothingThroughAModuleSourceThatClimbsOut covers the milestone's
// security criterion. The module's files exist and are readable; they are
// outside the configuration directory, so they are not read and nothing is
// reported from them.
func TestReadsNothingThroughAModuleSourceThatClimbsOut(t *testing.T) {
	root := filepath.Join("testdata", "escaping")
	plan := loadPlan(t, root, "plan.json")

	// The file the module points at is really there, or this test would pass
	// for the wrong reason.
	outside := filepath.Join("testdata", "outside", "main.tf")
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("this test needs %s to exist: %v", outside, err)
	}

	finding := annotate(t, about(
		"module.shared.terraform_data.x",
		"module.shared.terraform_data.x",
		"input"), plan, root)

	nothingLocated(t, finding, "a declaration outside the configuration directory")
}

// TestReportsNoLocationForARemoteModule covers the source this build does not
// resolve. A registry module's files live under .terraform/modules behind a
// manifest, which is a different input with a different lifetime.
func TestReportsNoLocationForARemoteModule(t *testing.T) {
	root := filepath.Join("testdata", "remote")
	plan := loadPlan(t, root, "plan.json")

	finding := annotate(t, about(
		"module.shared.terraform_data.x",
		"module.shared.terraform_data.x",
		"input"), plan, root)

	nothingLocated(t, finding, "a remote module")
}

// TestReportsNoLocationForAnAddressThePlanDoesNotHave covers the join failing at
// the other end. A bundle naming something the plan does not is not a bundle
// this build produced, and it gets no location rather than a search by name.
func TestReportsNoLocationForAnAddressThePlanDoesNotHave(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")

	finding := annotate(t, about("terraform_data.absent", "terraform_data.absent", "input"), plan, root)

	nothingLocated(t, finding, "an address the plan does not carry")
}

// TestLocatesUnknownsAsWell covers the records that are not findings. An unknown
// carries the same evidence references, and a reader needs the line for the
// same reason.
func TestLocatesUnknownsAsWell(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")

	bundle := about("terraform_data.root", "terraform_data.root", "input")
	address := "terraform_data.root"
	bundle.Unknowns = []evidence.Unknown{{
		CheckID:         "SOMETHING_UNDETERMINED",
		Required:        false,
		Reason:          "A reason the tests do not care about.",
		ResourceAddress: &address,
		Evidence: []evidence.EvidenceRef{{
			Source:          "terraform_plan",
			ResourceAddress: "terraform_data.root",
			Path:            "input",
		}},
	}}

	located, err := tfconfig.Annotate(bundle, plan, root)
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	at(t, located.Unknowns[0].Evidence[0].Location, "main.tf", 12)
}

// TestRefusesAConfigurationDirectoryThatIsNotThere covers the one failure that
// is the caller's mistake rather than an absence. A directory that cannot be
// opened was almost certainly the wrong argument, and silently locating nothing
// would leave that undiscovered.
func TestRefusesAConfigurationDirectoryThatIsNotThere(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")

	if _, err := tfconfig.Annotate(about("terraform_data.root", "terraform_data.root", "input"),
		plan, filepath.Join("testdata", "nowhere")); err == nil {
		t.Fatal("a configuration directory that is not there was accepted")
	}
}

// TestLeavesABundleWithNothingToLocateAlone covers the shape of the change: a
// location is added to what is there and nothing else is touched.
func TestLeavesABundleWithNothingToLocateAlone(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")

	bundle := about("terraform_data.root", "terraform_data.root", "input")
	bundle.Findings[0].Resource = nil

	located, err := tfconfig.Annotate(bundle, plan, root)
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if located.Decision != bundle.Decision || located.Summary != bundle.Summary {
		t.Fatal("the verdict changed")
	}
	if located.Findings[0].Resource != nil {
		t.Fatal("a resource appeared")
	}
	at(t, located.Findings[0].Evidence[0].Location, "main.tf", 12)
}

// TestLocatingDoesNotChangeTheVerdict covers the rule that locations are
// additional and never load-bearing.
func TestLocatingDoesNotChangeTheVerdict(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")
	bundle := about("terraform_data.root", "terraform_data.root", "input")

	located, err := tfconfig.Annotate(bundle, plan, root)
	if err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if located.Decision != bundle.Decision {
		t.Fatalf("decision = %q, want %q", located.Decision, bundle.Decision)
	}
	if len(located.Findings) != len(bundle.Findings) || len(located.Unknowns) != len(bundle.Unknowns) {
		t.Fatal("locating added or removed a record")
	}
	if located.Findings[0].Disposition != bundle.Findings[0].Disposition {
		t.Fatal("locating changed a disposition")
	}
}

// TestDoesNotChangeTheBundleItWasGiven covers the copy. A caller that keeps the
// bundle it passed in must still hold the bundle it passed in.
func TestDoesNotChangeTheBundleItWasGiven(t *testing.T) {
	root := filepath.Join("testdata", "generated")
	plan := loadPlan(t, root, "plan.json")
	bundle := about("terraform_data.root", "terraform_data.root", "input")

	if _, err := tfconfig.Annotate(bundle, plan, root); err != nil {
		t.Fatalf("Annotate: %v", err)
	}
	if bundle.Findings[0].Resource.Location != nil {
		t.Fatal("the bundle passed in was changed")
	}
	if bundle.Findings[0].Evidence[0].Location != nil {
		t.Fatal("the evidence passed in was changed")
	}
}

// TestDistinguishesADataSourceFromAResource covers the kind. A data source and a
// managed resource can share a type and a name, and the plan says which one it
// is about; matching without the kind finds two declarations where there is one.
func TestDistinguishesADataSourceFromAResource(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")
	root := filepath.Join("testdata", "kinds")

	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	at(t, finding.Resource.Location, "main.tf", 8)
}

// TestSkipsFilesTerraformItselfSkips covers a file that is not configuration. A
// name beginning with a dot is not loaded by Terraform, so no plan was made from
// it, and a line out of it would be a line out of a file that never ran.
func TestSkipsFilesTerraformItselfSkips(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")
	root := filepath.Join("testdata", "hidden")

	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	nothingLocated(t, finding, "a declaration in a file Terraform ignores")
}

// TestAnAddressThePlanDoesNotHaveMatchesNothing covers why the lookup refuses an
// unknown address instead of carrying on with what a missing entry would be. A
// resource change that was never found has no type and no name, and a
// declaration with neither is a declaration that would answer for it.
func TestAnAddressThePlanDoesNotHaveMatchesNothing(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")
	root := filepath.Join("testdata", "emptylabels")

	finding := annotate(t, about("terraform_data.absent", "terraform_data.absent", "input"), plan, root)

	nothingLocated(t, finding, "an unknown address")
}

// TestDoesNotFollowARemoteSourceIntoALocalDirectory covers the collision the
// local-path rule exists for. The fixture ships a directory whose path spells
// the registry address, and following the source as though it were a path lands
// in it -- reporting a line from files the module never used.
func TestDoesNotFollowARemoteSourceIntoALocalDirectory(t *testing.T) {
	root := filepath.Join("testdata", "remote")
	plan := loadPlan(t, root, "plan.json")

	collision := filepath.Join(root, "terraform-aws-modules", "s3-bucket", "aws", "main.tf")
	if _, err := os.Stat(collision); err != nil {
		t.Fatalf("this test needs %s to exist: %v", collision, err)
	}

	finding := annotate(t, about(
		"module.shared.terraform_data.x",
		"module.shared.terraform_data.x",
		"input"), plan, root)

	nothingLocated(t, finding, "a remote source followed into a local directory")
}

// TestReadsNothingThroughASourceThatLeavesAndComesBack covers the path a lexical
// check would clean away. "../escaping" from the configuration root leaves the
// directory and returns to it, so joining the names cancels the climb and the
// guard sees a directory inside the root -- which it would read, attributing the
// root module's declarations to a module. Whether it is the same directory is a
// question about symbolic links, and the source left the root either way.
func TestReadsNothingThroughASourceThatLeavesAndComesBack(t *testing.T) {
	root := filepath.Join("testdata", "escaping")
	plan := loadPlan(t, root, "plan-returning.json")

	finding := annotate(t, about(
		"module.shared.terraform_data.x",
		"module.shared.terraform_data.x",
		"input"), plan, root)

	nothingLocated(t, finding, "a source that climbed out and back")
}

// TestRefusesAChainOfModuleCallsThatDoesNotEnd covers a plan this package did
// not parse. Plan is a public structure, and a chain of calls that names itself
// would be followed for as long as it was offered; the bound is the number of
// calls, because a chain longer than that has revisited one.
func TestRefusesAChainOfModuleCallsThatDoesNotEnd(t *testing.T) {
	plan := terraformplan.Plan{
		FormatVersion: "1.2",
		ResourceChanges: []terraformplan.ResourceChange{{
			Address:       "module.a.module.b.terraform_data.x",
			ModuleAddress: "module.a.module.b",
			Mode:          terraformplan.ModeManaged,
			Type:          "terraform_data",
			Name:          "x",
		}},
		ModuleCalls: map[string]terraformplan.ModuleCall{
			"module.a.module.b": {Address: "module.a.module.b", Parent: "module.a", Source: "./b"},
			"module.a":          {Address: "module.a", Parent: "module.a.module.b", Source: "./a"},
		},
	}
	root := filepath.Join("testdata", "generated")

	finding := annotate(t, about(
		"module.a.module.b.terraform_data.x",
		"module.a.module.b.terraform_data.x",
		"input"), plan, root)

	nothingLocated(t, finding, "a chain that does not end")
}

// TestReadsNothingPastTheRunBudget covers the bound on the work one run does.
// The declaration is real and is where the test says it is; it is not located,
// because this build stopped reading before it got there.
func TestReadsNothingPastTheRunBudget(t *testing.T) {
	root := t.TempDir()
	// Each file is comfortably inside the per-file bound, so what stops the
	// read is the budget for the run rather than any one file.
	filler := strings.Repeat("# filler\n", 40_000)
	for i := range 25 {
		name := filepath.Join(root, fmt.Sprintf("a%02d.tf", i))
		if err := os.WriteFile(name, []byte(filler), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	declaration := "resource \"terraform_data\" \"root\" {\n  input = \"x\"\n}\n"
	if err := os.WriteFile(filepath.Join(root, "zz.tf"), []byte(declaration), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	plan := loadPlan(t, "testdata", "generated", "plan.json")
	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	nothingLocated(t, finding, "a declaration past the run's reading budget")
}

// TestReadsNothingFromAFileTooLarge covers the same bound on one file. Nothing
// real is this big, and a position from a file read only partly is a position in
// a file this build has not seen.
func TestReadsNothingFromAFileTooLarge(t *testing.T) {
	root := t.TempDir()
	source := "resource \"terraform_data\" \"root\" {\n  input = \"x\"\n}\n" +
		strings.Repeat("# filler\n", 70_000)
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte(source), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	plan := loadPlan(t, "testdata", "generated", "plan.json")
	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	nothingLocated(t, finding, "a declaration in a file past the size bound")
}

// TestAcceptsAConfigurationDirectoryNamedThroughAParent covers the argument a
// caller is entitled to write. "--config ../infra" is ordinary, and the guard
// refuses a path that names a parent directory, so the root is resolved once
// before anything is asked of the filesystem.
func TestAcceptsAConfigurationDirectoryNamedThroughAParent(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")
	// A leading parent segment, which is the form joining cannot clean away and
	// the form a caller writes: this package's own directory reached from inside
	// it. It is what "--config ../infra" looks like to the guard.
	through := filepath.Join("..", "tfconfig", "testdata", "generated")

	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, through)

	at(t, finding.Resource.Location, "main.tf", 11)
}

// hostileNames are file names a filesystem accepts and the Evidence Bundle
// contract does not. A backslash is an ordinary byte in a name on Unix, and so
// is a line break.
func hostileNames() map[string]string {
	return map[string]string{
		"backslash":       `we\ird.tf`,
		"line feed":       "we\nird.tf",
		"carriage return": "we\rird.tf",
	}
}

// TestAFileNameTheContractRefusesIsNotALocation covers the one promise this
// milestone cannot break: a location may not change a verdict.
//
// A location is composed from a directory entry's name, and the contract holds
// that field to a path it can spell. A name the contract refuses used to be
// composed anyway, which made the bundle invalid after the verdict was decided --
// so a renderer refused it, the command reported an internal failure, and a
// change that blocks produced no report at all. The file names in a
// configuration directory are not this build's to choose.
func TestAFileNameTheContractRefusesIsNotALocation(t *testing.T) {
	plan := loadPlan(t, "testdata", "generated", "plan.json")
	declaration := "resource \"terraform_data\" \"root\" {\n  input = \"x\"\n}\n"

	for name, file := range hostileNames() {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, file), []byte(declaration), 0o600); err != nil {
				t.Skipf("this filesystem refuses the name: %v", err)
			}

			// annotate validates the bundle it gets back, which is the assertion
			// that matters: an unspellable location must not be composed.
			finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

			nothingLocated(t, finding, "a name the contract refuses")
		})
	}
}

// TestADirectoryNameTheContractRefusesIsNotALocation covers the same thing one
// level up: the path is composed from the module directory as well, and a module
// source naming a directory with a line break in it is a path the contract
// refuses just as firmly.
func TestADirectoryNameTheContractRefusesIsNotALocation(t *testing.T) {
	root := t.TempDir()
	module := "mod\nule"
	if err := os.MkdirAll(filepath.Join(root, module), 0o700); err != nil {
		t.Skipf("this filesystem refuses the name: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, module, "main.tf"),
		[]byte("resource \"terraform_data\" \"x\" {\n  input = \"x\"\n}\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	plan := terraformplan.Plan{
		FormatVersion: "1.2",
		ResourceChanges: []terraformplan.ResourceChange{{
			Address:       "module.shared.terraform_data.x",
			ModuleAddress: "module.shared",
			Mode:          terraformplan.ModeManaged,
			Type:          "terraform_data",
			Name:          "x",
		}},
		ModuleCalls: map[string]terraformplan.ModuleCall{
			"module.shared": {Address: "module.shared", Source: "./" + module},
		},
	}

	finding := annotate(t, about(
		"module.shared.terraform_data.x",
		"module.shared.terraform_data.x",
		"input"), plan, root)

	nothingLocated(t, finding, "a directory name the contract refuses")
}

// TestAFileTooLargeDiscardsTheDeclarationsBesideIt covers why a directory that
// could not be read whole is discarded whole.
//
// The declaration in the file this build refused could have been the second match
// that makes the answer ambiguous. Keeping the ones already scanned would report
// a unique position for something this build cannot know is unique -- which is
// the wrong line the milestone exists to prevent, arrived at by being helpful.
//
// The fixture is built so the two cases differ: both files declare the resource
// the plan names, and the oversized one sorts second, so a partial scan would
// have exactly one match in hand.
func TestAFileTooLargeDiscardsTheDeclarationsBesideIt(t *testing.T) {
	root := t.TempDir()
	declaration := "resource \"terraform_data\" \"root\" {\n  input = \"x\"\n}\n"
	if err := os.WriteFile(filepath.Join(root, "a_main.tf"), []byte(declaration), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	oversized := strings.Repeat("# filler\n", 70_000) + declaration
	if err := os.WriteFile(filepath.Join(root, "z_huge.tf"), []byte(oversized), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	plan := loadPlan(t, "testdata", "generated", "plan.json")
	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	nothingLocated(t, finding, "a declaration beside a file this build refused to read")
}

// TestAFileThatCannotBeLexedDiscardsTheDeclarationsBesideIt is the oversized-file
// rule for the other reason a file is not read: this build could not lex it. The
// declaration in it could have been the second match, so a position from the files
// beside it would be a position this build cannot know is unique.
func TestAFileThatCannotBeLexedDiscardsTheDeclarationsBesideIt(t *testing.T) {
	root := t.TempDir()
	declaration := "resource \"terraform_data\" \"root\" {\n  input = \"x\"\n}\n"
	if err := os.WriteFile(filepath.Join(root, "a_main.tf"), []byte(declaration), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Declares the same resource, and ends inside a string.
	broken := declaration + "resource \"terraform_data\" \"root\" {\n  input = \"unterminated\n"
	if err := os.WriteFile(filepath.Join(root, "z_broken.tf"), []byte(broken), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	plan := loadPlan(t, "testdata", "generated", "plan.json")
	finding := annotate(t, about("terraform_data.root", "terraform_data.root", "input"), plan, root)

	nothingLocated(t, finding, "a declaration beside a file this build could not lex")
}

// TestADataAddressLocatesTheDataBlock covers the direction the kind test did not.
// It probed a managed address only, so forcing every lookup to "resource" was the
// identity for it -- and the reverse, a data address resolving to the resource
// block of the same type and name, is a wrong line.
func TestADataAddressLocatesTheDataBlock(t *testing.T) {
	plan := terraformplan.Plan{
		FormatVersion: "1.2",
		ResourceChanges: []terraformplan.ResourceChange{{
			Address: "data.terraform_data.root",
			Mode:    terraformplan.ModeData,
			Type:    "terraform_data",
			Name:    "root",
		}},
	}
	root := filepath.Join("testdata", "kinds")

	finding := annotate(t, about(
		"data.terraform_data.root",
		"data.terraform_data.root",
		"input"), plan, root)

	at(t, finding.Resource.Location, "main.tf", 4)
	at(t, finding.Evidence[0].Location, "main.tf", 5)
}
