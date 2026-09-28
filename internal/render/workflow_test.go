package render_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/render"
)

// workflowPath is the file a repository copies. It is in this repository so
// that the contract between the rendering and the workflow is one thing rather
// than two that agree until one of them changes.
//
// It sits under docs/examples rather than under .github/workflows, because a
// file there is a workflow GitHub tries to run and this repository has no
// Terraform to verify. It is still tested: a template nobody checks is a
// template that stops matching the tool it drives.
var workflowPath = filepath.Join("..", "..", "docs", "examples", "infraproof-workflow.yml")

func workflow(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("reading the workflow: %v", err)
	}
	return string(raw)
}

// TestTheWorkflowFindsTheMarkerWhereTheReviewPutsIt is the coupling that would
// otherwise break in silence.
//
// The workflow reads the first line of the review to decide whether to edit an
// existing comment or post a new one. Moving the marker, or putting anything
// before it, turns every push into a new comment -- and nothing would fail.
func TestTheWorkflowFindsTheMarkerWhereTheReviewPutsIt(t *testing.T) {
	out, err := render.Review(contractBundle())
	if err != nil {
		t.Fatalf("render.Review: %v", err)
	}

	first, _, found := strings.Cut(string(out), "\n")
	if !found {
		t.Fatal("the review is a single line")
	}
	if !strings.HasPrefix(first, "<!--") || !strings.Contains(first, render.Marker(contractBundle().Subject)) {
		t.Errorf("the first line is not the marker: %q", first)
	}

	text := workflow(t)
	if !strings.Contains(text, `marker="$(head -n 1 review.md)"`) {
		t.Error("the workflow no longer reads the marker from the first line; if the review " +
			"moved it, both places have to say so")
	}

	// The prefix, not the whole marker. A plan JSON carries a timestamp, so the
	// digest -- and the rest of the marker -- differs on every run even when
	// nothing changed, and matching the whole thing would append a comment per
	// run rather than update one.
	if !strings.Contains(text, `startswith("<!-- infraproof:")`) {
		t.Error("the workflow matches on something other than the marker prefix, so it will " +
			"post a new comment on every run")
	}
	// An empty review is not a marker, and an empty prefix matches every
	// comment on the pull request.
	if !strings.Contains(text, "[ ! -s review.md ]") {
		t.Error("the workflow does not check that there is a review to post; an empty one " +
			"matches every comment and overwrites somebody else's")
	}
	if !strings.Contains(text, `"<!-- infraproof:"*)`) {
		t.Error("the workflow does not check the shape of what it read before searching with it")
	}
}

// TestTheWorkflowCanObtainTheThingItRuns covers the step that made the whole
// template fail on its first run in any repository: it built a package that
// exists in this repository and not in the one the file is copied into.
func TestTheWorkflowCanObtainTheThingItRuns(t *testing.T) {
	text := workflow(t)

	if strings.Contains(text, "go build -o infraproof ./cmd/infraproof") {
		t.Error("the workflow builds a package that is not in the repository it runs in")
	}
	if !strings.Contains(text, "go install github.com/mtlabs-eng/infraproof/cmd/infraproof@") {
		t.Error("the workflow does not fetch the tool it then runs")
	}
	if strings.Contains(text, "./infraproof check") {
		t.Error("the workflow runs a binary from the working directory, which is the user's " +
			"repository rather than this one")
	}
}

// TestTheVerdictDecidesTheCheck is the milestone's criterion, asserted against
// the file rather than against a claim. Every exit code that must fail the job
// has to reach the failing branch, and the two that must not have to reach the
// passing one.
func TestTheVerdictDecidesTheCheck(t *testing.T) {
	verdict := section(t, workflow(t), "- name: Apply the verdict", "")

	for _, passing := range []string{"0)", "2)"} {
		if !strings.Contains(verdict, passing) {
			t.Errorf("exit %s is not handled as a pass", strings.TrimSuffix(passing, ")"))
		}
	}
	// Anything else fails, and it must be the default rather than a list: a
	// list is a thing someone adds a case to.
	if !strings.Contains(verdict, "*)") || !strings.Contains(verdict, "exit 1") {
		t.Error("the verdict step has no failing default")
	}
	for _, failing := range []string{"3)", "4)", "10)", "11)"} {
		if strings.Contains(verdict, failing) {
			t.Errorf("exit %s has its own branch; a BLOCK, an UNKNOWN or a failure must fail "+
				"the check, and a branch is where that stops being true",
				strings.TrimSuffix(failing, ")"))
		}
	}
}

// TestTheWorkflowAsksForNoMoreThanItNeeds keeps the permission a repository
// grants small and stated.
//
// A workflow that can write on a pull request is the only thing here that can
// write anything. Everything else it does is read a file and run a binary, and
// a permission block that drifted wider would go unnoticed in a file nobody
// re-reads.
func TestTheWorkflowAsksForNoMoreThanItNeeds(t *testing.T) {
	text := workflow(t)

	// Asked of the block rather than of the file. Commenting the block out left
	// every required string present and the run holding whatever the repository
	// grants by default.
	permissions := section(t, text, "\npermissions:\n", "\nenv:")
	for _, required := range []string{"contents: read", "pull-requests: write"} {
		if !strings.Contains(permissions, required) {
			t.Errorf("the permissions block does not declare %q:%s", required, permissions)
		}
	}
	if strings.Contains(text, "#permissions:") || strings.Contains(text, "# permissions:") {
		t.Error("the permissions block is commented out, so the run gets whatever the " +
			"repository grants by default")
	}
	for _, wider := range []string{"issues: write", "checks: write", "statuses: write",
		"write-all", "deployments: write"} {
		if strings.Contains(text, wider) {
			t.Errorf("the workflow asks for %q", wider)
		}
	}
	for name, forbidden := range map[string]string{
		"write access to the repository":     "contents: write",
		"the ability to run other workflows": "actions: write",
		"package publishing":                 "packages: write",
		"identity tokens":                    "id-token: write",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the workflow asks for %s", name)
		}
	}

	// The only secret it may name is the token the run is given. Anything else
	// is a credential this build has no reason to be near.
	if strings.Contains(text, "secrets.") {
		t.Error("the workflow reads a secret; the verifier needs none and the comment needs " +
			"only the token the run already has")
	}
}

// TestTheWorkflowUsesFormatsThatExist keeps the file from naming an output this
// build does not produce.
func TestTheWorkflowUsesFormatsThatExist(t *testing.T) {
	text := workflow(t)

	// Asked of the command rather than of the file: the sentence explaining why
	// --slurp is there also contains the word, so a check over the whole text
	// passes for a command that no longer uses it.
	//
	// --paginate runs the filter once per page, so without --slurp the lookup
	// answers once per page and the result is several lines rather than an id.
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "existing=") || strings.Contains(trimmed, "gh api \"repos/$REPO/issues/$PR/comments\"") {
			if strings.Contains(trimmed, "--paginate") && !strings.Contains(trimmed, "--slurp") {
				t.Errorf("the comment lookup pages without slurping, so it returns one answer "+
					"per page rather than one answer: %s", trimmed)
			}
		}
	}
	if !strings.Contains(text, "-F body=@review.md") {
		t.Error("the comment step does not read the body from the file; -f would post the " +
			"literal text \"@review.md\"")
	}
	for _, format := range []string{"--format review", "--format json"} {
		if !strings.Contains(text, format) {
			t.Errorf("the workflow does not use %q", format)
		}
	}
	if strings.Contains(text, "--format markdown") {
		t.Error("the workflow posts the long report rather than the review; a comment is read " +
			"in a diff view")
	}
}

// TestTheWorkflowDoesNotHandTheVerifierACredential is the milestone's rule,
// asserted where it would be broken: in the file a repository copies.
func TestTheWorkflowDoesNotHandTheVerifierACredential(t *testing.T) {
	text := workflow(t)

	verify := section(t, text, "- name: Verify", "- uses: actions/upload-artifact")
	if !strings.Contains(verify, "--format review > review.md") {
		t.Error("the verifier does not write the review to the file the comment step reads")
	}
	for _, forbidden := range []string{"GH_TOKEN", "GITHUB_TOKEN", "secrets.", "AWS_", "ARM_", "GOOGLE_"} {
		if strings.Contains(verify, forbidden) {
			t.Errorf("the step that runs the verifier is given %s", forbidden)
		}
	}
}

// section returns the text between two markers, so a test can ask about one
// step rather than the whole file.
func section(t *testing.T, text, from, to string) string {
	t.Helper()
	start := strings.Index(text, from)
	if start < 0 {
		t.Fatalf("the workflow has no %q", from)
	}
	if to == "" {
		return text[start:]
	}
	end := strings.Index(text[start:], to)
	if end < 0 {
		t.Fatalf("the workflow has no %q after %q", to, from)
	}
	return text[start : start+end]
}
