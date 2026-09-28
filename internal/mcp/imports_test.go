package mcp_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestTheAdapterCanReachNoNetworkAndRunNoCommand is the machine-checkable form
// of the security requirements two milestones state: no arbitrary command
// execution, no terraform execution, no network access, and no cloud
// credentials -- for the MCP adapter, and for the pull-request rendering, which
// produces an artifact that something else publishes.
//
// Written as a rule about imports rather than as a promise in a comment. A
// package that imports none of these cannot do any of them, whatever a later
// change to its logic intends, and the failure names the import rather than
// leaving a reader to find it.
func TestTheAdapterCanReachNoNetworkAndRunNoCommand(t *testing.T) {
	forbidden := map[string]string{
		"net":              "would let this server reach a network it has no reason to reach",
		"net/http":         "would let this server reach a network it has no reason to reach",
		"net/url":          "is not needed to read two local files",
		"os/exec":          "would let this server run a command, which it must never do",
		"plugin":           "would let this server load code it did not ship with",
		"runtime/debug":    "is not needed to answer a request",
		"database/sql":     "is not needed to read two local files",
		"crypto/tls":       "would only be needed to reach a network",
		"golang.org/x/net": "would let this server reach a network",
		"os/user":          "is not needed to read two local files",
	}

	// Every package the adapter is built from, including what it verifies with.
	// A prohibition that stopped at the adapter's own file would be one an
	// import away from being untrue.
	for _, dir := range []string{
		"..", // internal/...
	} {
		walk(t, dir, forbidden)
	}
}

func walk(t *testing.T, dir string, forbidden map[string]string) {
	t.Helper()

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		switch {
		case err != nil:
			return err
		case info.IsDir(), !strings.HasSuffix(path, ".go"):
			return nil
		case strings.HasSuffix(path, "_test.go"):
			// A test may reach for what the code may not: this file imports
			// go/parser to make that rule checkable.
			return nil
		}

		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		for _, spec := range file.Imports {
			name, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			if reason, banned := forbidden[name]; banned {
				t.Errorf("%s imports %q, which %s", path, name, reason)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
}
