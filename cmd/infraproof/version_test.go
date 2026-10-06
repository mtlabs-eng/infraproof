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
	root := filepath.Join("..", "..")
	pinned := regexp.MustCompile(`infraproof@v([0-9]+\.[0-9]+\.[0-9]+)`)

	var found int
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name == ".git" || name == "testdata" {
				return filepath.SkipDir
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
			found++
			if match[1] != version {
				t.Errorf("%s tells a reader to install v%s and this build is %s; a release moves "+
					"the constants and the documents together, or it publishes instructions for "+
					"a build nobody is releasing", path, match[1], version)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the documents: %v", err)
	}
	if found == 0 {
		t.Fatal("no document pins a version, so this test asserts nothing")
	}
}
