package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/mcp"
)

// TestOneVersionForTheWholeBuild holds two constants together.
//
// The command reports one version and the adapter reports another to every
// client that connects to it. They are written in two files, and nothing tied
// them, so a release that changed one would have a build telling two stories
// about which build it is -- and the one a coding agent is told is the one
// nobody reads.
func TestOneVersionForTheWholeBuild(t *testing.T) {
	if version != mcp.Version {
		t.Errorf("the command says it is %q and the adapter says it is %q; a release changes "+
			"both or neither", version, mcp.Version)
	}
}

// TestTheVersionIsTheOneThatWasTagged ties the constant to the tag, which is the
// one pair nothing held.
//
// The command and the adapter were held to each other and neither to the
// repository, so v0.2.0 was tagged, pushed, and installed from the public proxy
// while the binary still said 0.1.0. A tool that is wrong about which tool it is
// cannot be reported in a bug, and the first thing anyone pastes into one is this
// line.
//
// What it requires is that the constant is not behind the newest tag. A release is
// tagged after the commit that prepares it, so during preparation the constant is
// ahead and that is correct -- a test that demanded equality would be red through
// every release. Behind is the defect: a binary that says it is older than one
// somebody has already installed.
//
// It skips where git or the tags are not there, which is every build from a module
// cache.
func TestTheVersionIsTheOneThatWasTagged(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not on PATH, so there is no tag to compare against")
	}

	out, err := exec.Command(git, "tag", "--list", "v*", "--sort=-v:refname").Output()
	if err != nil {
		t.Skipf("git tags are not available here: %v", err)
	}
	tags := strings.Fields(string(out))
	if len(tags) == 0 {
		t.Skip("this checkout has no version tags")
	}

	if newest := strings.TrimPrefix(tags[0], "v"); behind(version, newest) {
		t.Errorf("the newest tag is %q and this build says it is %q; a release changes the tag "+
			"and the constant together, or it ships a binary that is wrong about itself",
			tags[0], version)
	}
}

// behind reports whether one dotted version is older than another. It compares
// numerically, because "0.10.0" is newer than "0.9.0" and text says otherwise.
func behind(have, want string) bool {
	mine, theirs := strings.Split(have, "."), strings.Split(want, ".")
	for i := range max(len(mine), len(theirs)) {
		if field(mine, i) != field(theirs, i) {
			return field(mine, i) < field(theirs, i)
		}
	}
	return false
}

// field returns one numeric field of a dotted version, or zero where there is
// none. A field that is not a number compares as zero, which is the reading that
// cannot make an older build look newer.
func field(fields []string, i int) int {
	if i >= len(fields) {
		return 0
	}
	value, err := strconv.Atoi(fields[i])
	if err != nil {
		return 0
	}
	return value
}

// TestWhatTheDocumentsTellPeopleToInstallIsThisVersion holds the last pair that
// nothing held.
//
// The command and the adapter are tied to each other, and both to the newest
// tag. The documents are what a reader actually runs: the README's install line,
// the pull-request guide, and the example workflow all pin a version, and the
// guide says why -- a verifier that changes under you is a verdict you cannot
// reproduce. A release that bumped the constants and left those behind would
// hand every new reader a build older than the one being released, which is the
// same defect as a binary wrong about itself, one step further out.
//
// Pins are required to match exactly rather than merely not be behind. A
// document is not mid-release the way a constant is: it either tells people to
// install this build or it tells them to install another one.
func TestWhatTheDocumentsTellPeopleToInstallIsThisVersion(t *testing.T) {
	pins, err := documentPins(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("walking the documents: %v", err)
	}
	if len(pins) == 0 {
		t.Fatal("no document pins a version, so this test asserts nothing")
	}
	for _, pin := range pins {
		if pin.version != version {
			t.Errorf("%s tells a reader to install v%s and this build is %s; a release moves "+
				"the constants and the documents together, or it publishes instructions for "+
				"a build nobody is releasing", pin.path, pin.version, version)
		}
	}
}

// pin is one install line a document hands a reader.
type pin struct {
	path, version string
}

// documentPins finds every version a document under root tells a reader to
// install.
func documentPins(root string) ([]pin, error) {
	pinned := regexp.MustCompile(`infraproof@v([0-9]+\.[0-9]+\.[0-9]+)`)

	var pins []pin
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "testdata" {
				return filepath.SkipDir
			}
			// Another checkout below this one: its documents are its own.
			if path != root {
				if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
					return filepath.SkipDir
				}
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".md", ".yml", ".yaml":
		default:
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range pinned.FindAllStringSubmatch(string(raw), -1) {
			pins = append(pins, pin{path: path, version: match[1]})
		}
		return nil
	})
	return pins, err
}

// TestAnotherCheckoutInsideTheTreeIsNotThisBuildsDocuments keeps the document
// walk inside this checkout.
//
// A git worktree or a clone placed under the repository -- `.claude/worktrees/`
// is where review agents put theirs -- carries its own README at whatever
// version it was checked out at. Reading it made the release of 0.5.0 fail on a
// reviewer's copy of 0.4.0's README, which no reader of this build is ever
// handed. A checkout announces itself with a `.git` entry, a directory for a
// clone and a file for a worktree, and the walk stops at either.
func TestAnotherCheckoutInsideTheTreeIsNotThisBuildsDocuments(t *testing.T) {
	root := t.TempDir()
	write := func(path, content string) {
		t.Helper()
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "go install github.com/mtlabs-eng/infraproof/cmd/infraproof@v9.9.9\n")
	write("docs/GUIDE.md", "go install github.com/mtlabs-eng/infraproof/cmd/infraproof@v9.9.9\n")
	write(".claude/worktrees/agent/.git", "gitdir: /elsewhere\n")
	write(".claude/worktrees/agent/README.md", "go install github.com/mtlabs-eng/infraproof/cmd/infraproof@v0.1.0\n")
	write("vendor-clone/.git/HEAD", "ref: refs/heads/main\n")
	write("vendor-clone/README.md", "go install github.com/mtlabs-eng/infraproof/cmd/infraproof@v0.2.0\n")

	pins, err := documentPins(root)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, pin := range pins {
		paths = append(paths, filepath.ToSlash(strings.TrimPrefix(pin.path, root+string(filepath.Separator))))
	}
	if got, want := strings.Join(paths, ","), "README.md,docs/GUIDE.md"; got != want {
		t.Errorf("pins were read from %q, want only this checkout's %q", got, want)
	}
}
