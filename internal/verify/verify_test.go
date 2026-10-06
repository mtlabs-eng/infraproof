package verify_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/render"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/verify"
)

const contract = `{
  "schema_version": "1.0",
  "change_id": "add-private-staging-assets",
  "environment": "staging",
  "allowed_clouds": ["aws"],
  "destructive_changes": "forbidden",
  "resources": [{"family": "object_storage", "exposure": "private"}]
}`

const publicPlan = `{
  "format_version": "1.2",
  "resource_changes": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "tags": {"environment": "staging"}}}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "acl": "public-read"}}}
  ],
  "configuration": {"root_module": {"resources": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "expressions": {}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "expressions": {"bucket": {"references": [
       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
  ]}}
}`

func write(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	return path
}

// TestOneVerificationForEveryCaller is what makes "the adapter returns what the
// command returns" a property rather than a coincidence.
//
// The command used to wire the five steps itself. A second caller wiring them
// again would agree until one of them was changed, and the milestone's
// criterion — that MCP results are semantically identical to CLI results for
// the same files — would then be false in a way no test could see.
func TestOneVerificationForEveryCaller(t *testing.T) {
	bundle, err := verify.FromFiles(
		write(t, "intent.json", contract),
		write(t, "plan.json", publicPlan),
		verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}

	if bundle.Decision != evidence.DecisionBlock {
		t.Errorf("decision = %q, want BLOCK for a public-read bucket under a private contract",
			bundle.Decision)
	}
	if err := bundle.Validate(); err != nil {
		t.Errorf("the bundle does not satisfy its own contract: %v", err)
	}
	if bundle.Subject.PlanDigest == "" || bundle.Subject.IntentDigest == "" {
		t.Error("the bundle does not identify the bytes it was reached from")
	}
}

// TestUnreadableInputIsAnErrorAndNotAVerdict keeps the two apart at the new
// boundary, as the command already kept them apart at its own: a report reached
// from inputs that could not be read would be a verdict about nothing.
func TestUnreadableInputIsAnErrorAndNotAVerdict(t *testing.T) {
	good := write(t, "intent.json", contract)
	plan := write(t, "plan.json", publicPlan)

	cases := map[string][2]string{
		"no such contract":           {filepath.Join(t.TempDir(), "absent.json"), plan},
		"no such plan":               {good, filepath.Join(t.TempDir(), "absent.json")},
		"contract is not a contract": {write(t, "bad.json", `{"schema_version": "1.0"}`), plan},
		"plan is not a plan":         {good, write(t, "bad.json", `{"format_version": "9.0"}`)},
		"plan is not JSON":           {good, write(t, "bad.json", `schema_version: "1.0"`)},
	}

	for name, paths := range cases {
		t.Run(name, func(t *testing.T) {
			bundle, err := verify.FromFiles(paths[0], paths[1], verify.Options{})
			if err == nil {
				t.Fatalf("unreadable input produced a verdict: %q", bundle.Decision)
			}
			if bundle.Decision != "" {
				t.Errorf("a failed verification returned a decision as well as an error: %q",
					bundle.Decision)
			}
		})
	}
}

// configuredPlan is the plan the shipped aws configuration matches, by address.
const configuredPlan = `{
  "format_version": "1.2",
  "resource_changes": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "tags": {"environment": "staging"}}}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "provider_name": "registry.terraform.io/hashicorp/aws",
     "change": {"actions": ["create"], "before": null,
                "after": {"bucket": "assets", "acl": "public-read"}}}
  ],
  "configuration": {"root_module": {"resources": [
    {"address": "aws_s3_bucket.assets", "mode": "managed", "type": "aws_s3_bucket",
     "name": "assets", "expressions": {}},
    {"address": "aws_s3_bucket_acl.assets", "mode": "managed", "type": "aws_s3_bucket_acl",
     "name": "assets", "expressions": {"bucket": {"references": [
       "aws_s3_bucket.assets.id", "aws_s3_bucket.assets"]}}}
  ]}}
}`

// awsConfiguration is the configuration directory internal/tfconfig ships for
// exactly these addresses.
func awsConfiguration() string {
	return filepath.Join("..", "tfconfig", "testdata", "aws")
}

// TestNoConfigurationDirectoryChangesNothing covers the milestone's
// compatibility criterion. Without the directory the verification is the one it
// was before this milestone, byte for byte.
func TestNoConfigurationDirectoryChangesNothing(t *testing.T) {
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", publicPlan)

	bundle, err := verify.FromFiles(intent, plan, verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(raw), "location") {
		t.Fatalf("a verification with no configuration directory carried a location: %s", raw)
	}
}

// TestAConfigurationDirectoryAddsOnlyLocations covers the other half of the same
// rule: locations are additional and never load-bearing. The two bundles are
// compared field by field with the locations stripped out, so anything else that
// moved would show here.
func TestAConfigurationDirectoryAddsOnlyLocations(t *testing.T) {
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", configuredPlan)

	plain, err := verify.FromFiles(intent, plan, verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	located, err := verify.FromFiles(intent, plan, verify.Options{ConfigRoot: awsConfiguration()})
	if err != nil {
		t.Fatalf("FromFiles with a configuration directory: %v", err)
	}

	if evidence.ExitCode(plain.Decision) != evidence.ExitCode(located.Decision) {
		t.Fatalf("exit code changed: %d then %d",
			evidence.ExitCode(plain.Decision), evidence.ExitCode(located.Decision))
	}

	// Something must have been located, or this test would pass by locating
	// nothing at all.
	if located.Findings[0].Resource.Location == nil {
		t.Fatal("nothing was located, so this test proves nothing")
	}

	stripped := located
	stripped.Findings = slices.Clone(located.Findings)
	for i := range stripped.Findings {
		finding := &stripped.Findings[i]
		if finding.Resource != nil {
			resource := *finding.Resource
			resource.Location = nil
			finding.Resource = &resource
		}
		finding.Evidence = slices.Clone(finding.Evidence)
		for j := range finding.Evidence {
			finding.Evidence[j].Location = nil
		}
	}
	stripped.Unknowns = slices.Clone(located.Unknowns)
	for i := range stripped.Unknowns {
		stripped.Unknowns[i].Evidence = slices.Clone(stripped.Unknowns[i].Evidence)
		for j := range stripped.Unknowns[i].Evidence {
			stripped.Unknowns[i].Evidence[j].Location = nil
		}
	}

	want, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	got, err := json.Marshal(stripped)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("locating changed more than the locations\n--- with locations stripped ---\n%s\n--- without ---\n%s", got, want)
	}
}

// TestAConfigurationDirectoryThatCannotBeReadIsAnError keeps the distinction the
// rest of this package keeps. A directory that cannot be opened was the caller's
// mistake, not a fact about the change, and reporting a verdict from it would
// hide the mistake.
func TestAConfigurationDirectoryThatCannotBeReadIsAnError(t *testing.T) {
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", publicPlan)

	bundle, err := verify.FromFiles(intent, plan,
		verify.Options{ConfigRoot: filepath.Join(t.TempDir(), "nowhere")})
	if err == nil {
		t.Fatalf("a configuration directory that is not there produced a verdict: %q", bundle.Decision)
	}
	if bundle.Decision != "" {
		t.Errorf("a failed verification returned a decision as well as an error: %q", bundle.Decision)
	}
}

// TestALocatedBundleStillSatisfiesItsContract covers the obligation every
// producer in this build has: what it emits validates.
func TestALocatedBundleStillSatisfiesItsContract(t *testing.T) {
	bundle, err := verify.FromFiles(
		write(t, "intent.json", contract),
		write(t, "plan.json", configuredPlan),
		verify.Options{ConfigRoot: awsConfiguration()})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}

	if err := bundle.Validate(); err != nil {
		t.Fatalf("a located bundle does not satisfy its own contract: %v", err)
	}
}

// TestNoConfigurationDirectoryReadsNoFile covers what "no flag, no file read"
// means, which the test beside it could not see.
//
// Independent review removed the guard on an empty ConfigRoot and the whole suite
// still passed: filepath.Abs("") resolves to the process working directory, so a
// plain run from inside a Terraform directory read its .tf files and reported
// positions from them. The test that claimed to cover this passed only because
// the test binary's working directory happened to hold no .tf file. This one puts
// one there.
func TestNoConfigurationDirectoryReadsNoFile(t *testing.T) {
	// Resolved before the working directory changes, or they name nothing.
	intent := write(t, "intent.json", contract)
	plan := write(t, "plan.json", configuredPlan)

	elsewhere := t.TempDir()
	configuration, err := os.ReadFile(filepath.Join(awsConfiguration(), "main.tf"))
	if err != nil {
		t.Fatalf("reading the shipped configuration: %v", err)
	}
	if err := os.WriteFile(filepath.Join(elsewhere, "main.tf"), configuration, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Chdir(elsewhere)

	bundle, err := verify.FromFiles(intent, plan, verify.Options{})
	if err != nil {
		t.Fatalf("FromFiles: %v", err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(raw), "location") {
		t.Fatalf("a run with no configuration directory read the working directory:\n%s", raw)
	}
}

// planFixtures returns every plan this repository ships, by path.
func planFixtures(t *testing.T) []string {
	t.Helper()
	var found []string
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".json" || !strings.Contains(path, "testdata") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if _, err := terraformplan.Parse(raw); err != nil {
			// Not a plan, or a plan this build refuses. Either way it is not a
			// fixture this comparison is about.
			return nil
		}
		found = append(found, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walking fixtures: %v", err)
	}
	if len(found) < 20 {
		t.Fatalf("found only %d plan fixtures, which is too few to be the set", len(found))
	}
	return found
}

// TestEveryFixtureIsUnchangedWhenNothingMatches covers the milestone's
// compatibility criterion across the whole fixture set rather than one plan.
//
// The criterion was written as "byte-identical", and what is provable in a suite
// is narrower and worth stating exactly: for every plan this repository ships, a
// verification against a configuration directory that declares nothing produces
// the same bytes as one with no directory at all. Nothing is added when nothing
// matched, in any fixture, in any field.
//
// The test that used to stand for this checked one plan for the absence of a
// substring.
func TestEveryFixtureIsUnchangedWhenNothingMatches(t *testing.T) {
	intent := write(t, "intent.json", contract)
	empty := t.TempDir()

	for _, fixture := range planFixtures(t) {
		t.Run(fixture, func(t *testing.T) {
			plain, err := verify.FromFiles(intent, fixture, verify.Options{})
			if err != nil {
				t.Skipf("this fixture is not verifiable: %v", err)
			}
			against, err := verify.FromFiles(intent, fixture, verify.Options{ConfigRoot: empty})
			if err != nil {
				t.Fatalf("FromFiles with a configuration directory: %v", err)
			}

			want, err := json.Marshal(plain)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			got, err := json.Marshal(against)
			if err != nil {
				t.Fatalf("marshalling: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("a configuration directory that declares nothing changed the bundle\n got: %s\nwant: %s", got, want)
			}
			if strings.Contains(string(want), "location") {
				t.Fatalf("a verification with no configuration directory carried a location: %s", want)
			}
		})
	}
}

// baselineKey names a fixture's golden by its path, flattened. Two fixtures in
// different directories share a file name, and the key has to tell them apart.
func baselineKey(fixture string) string {
	cleaned := filepath.ToSlash(filepath.Clean(fixture))
	cleaned = strings.TrimPrefix(cleaned, "../../")
	cleaned = strings.TrimSuffix(cleaned, ".json")
	return strings.ReplaceAll(cleaned, "/", "_") + ".json"
}

// TestEveryFixtureProducesItsBaselineBundle is the mechanical form of the
// milestone 08 criterion that object-storage verdicts do not change.
//
// The goldens were generated from the commit before any of that milestone's
// behaviour landed, against a contract this repository ships, so each one records
// what this build said about that plan before the network family existed. A
// normalizer change that moved a storage verdict by one field would otherwise be
// argued about; here it is a diff.
//
// The contract is a committed file rather than a temporary one so that the bundle
// records a stable intent source and digest. A path under t.TempDir() would make
// every golden depend on where the test ran.
//
// What it covers, measured rather than claimed: making the AWS mapper stop
// claiming buckets fails 36 of these subtests. What it does not cover is a branch
// this one contract never reaches -- it declares object storage private, so the
// disposition for an undeclared exposure is never taken here. That branch is held
// by internal/policy's own tests, and mutating it fails two of them. Recording a
// second contract to reach it would double 63 goldens to catch what is already
// caught where it belongs.
func TestEveryFixtureProducesItsBaselineBundle(t *testing.T) {
	intent := filepath.Join("testdata", "baseline", "intent.json")

	// Atomic because subtests may run in parallel; nothing here asks for that
	// today, and a counter that silently undercounts if one ever does would
	// weaken the only assertion holding this test up.
	var compared atomic.Int64
	// Every golden has to be consumed by a comparison, which is the assertion a
	// floor cannot make. planFixtures discards a plan terraformplan refuses --
	// before any subtest exists -- so a stricter parse removed the fixture from
	// the loop and the count simply dropped. That is the exact verdict change
	// the Fatalf below says this test catches, and it slipped past a floor three
	// below the real count.
	consumed := map[string]bool{}
	for _, fixture := range planFixtures(t) {
		key := baselineKey(fixture)
		golden := filepath.Join("testdata", "baseline", key)
		want, err := os.ReadFile(golden)
		if err != nil {
			// A fixture with no baseline was added after the baseline was
			// recorded, which is what a milestone adding a family does. There is
			// nothing to compare it against, and recording one now from the
			// current behaviour would be calling today's answer a baseline.
			continue
		}

		t.Run(fixture, func(t *testing.T) {
			bundle, err := verify.FromFiles(intent, fixture, verify.Options{})
			if err != nil {
				// Not a skip. A fixture that had a baseline and stopped being
				// verifiable is the verdict change this test exists to catch --
				// a stricter parse, a new refusal, a recovered panic. Skipping
				// it hid all 63 comparisons behind a green run, which an
				// independent review demonstrated by making every verification
				// return an error and watching this test pass.
				t.Fatalf("this fixture had a baseline and is no longer verifiable: %v", err)
			}
			got, err := render.JSON(bundle)
			if err != nil {
				t.Fatalf("render.JSON: %v", err)
			}
			if string(got) != string(want) {
				t.Fatalf("this plan's verdict changed since the baseline was recorded\n--- now ---\n%s\n--- baseline ---\n%s",
					got, want)
			}
			compared.Add(1)
		})
		consumed[key] = true
	}

	// Every recorded golden, compared. Not a floor: a floor three below the real
	// count let three goldens go missing in silence, and the fixture a stricter
	// parse would drop is exactly the one this test exists for.
	//
	// The count is incremented inside the subtest, after the comparison.
	// Counting fixtures that had a baseline counted intent rather than work.
	entries, err := filepath.Glob(filepath.Join("testdata", "baseline", "internal_*.json"))
	if err != nil {
		t.Fatalf("listing the baselines: %v", err)
	}
	// intent.json lives here too and is the contract, not a golden; the prefix
	// is what baselineKey produces from a fixture path.
	goldens := entries
	// The recorded set, as a number, because comparing the count against itself
	// cannot see a baseline going missing: delete a golden and both sides of the
	// equality fall together. Raise it when a baseline is deliberately added;
	// never lower it. This is the guard the version constant has, for the same
	// reason.
	const recorded = 63
	if len(goldens) < recorded {
		t.Fatalf("found %d baselines and %d are recorded; a verdict nobody compares is a "+
			"verdict that can change in silence", len(goldens), recorded)
	}
	for _, golden := range goldens {
		if !consumed[filepath.Base(golden)] {
			t.Errorf("%s is recorded and no fixture reached it; a plan this build stopped being "+
				"able to read is removed from the loop rather than failing in it",
				filepath.Base(golden))
		}
	}
	if total := int(compared.Load()); total != len(goldens) {
		t.Fatalf("compared %d fixtures against %d recorded baselines", total, len(goldens))
	}
}
