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
var workflowPath = filepath.Join("..", "..", ".github", "workflows", "infraproof.yml")

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

	if !strings.Contains(workflow(t), `marker="$(head -n 1 review.md)"`) {
		t.Error("the workflow no longer reads the marker from the first line; if the review " +
			"moved it, both places have to say so")
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

	for _, required := range []string{"contents: read", "pull-requests: write"} {
		if !strings.Contains(text, required) {
			t.Errorf("the workflow does not declare %q", required)
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
	end := strings.Index(text[start:], to)
	if end < 0 {
		t.Fatalf("the workflow has no %q after %q", to, from)
	}
	return text[start : start+end]
}
