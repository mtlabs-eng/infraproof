package main

import (
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
