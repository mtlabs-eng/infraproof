// Package pathguard decides whether a caller may read a path.
//
// The adapter is handed paths by something else -- an agent, a client, a
// person -- and a verifier that reads whatever it is pointed at is a file
// reader with extra steps. Milestone 05 requires that nothing outside
// explicitly allowed roots is reachable, and this is the one place that is
// decided, so that "we check the path" is a claim about one function rather
// than about every call site that remembered to.
package pathguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Guard allows paths inside a fixed set of roots and refuses everything else.
type Guard struct {
	roots []string
}

// ErrOutsideRoots reports a path the guard will not read.
//
// It is one error for every refusal, and deliberately says nothing about the
// filesystem: a message that distinguished "outside the roots" from "outside
// the roots and not there anyway" would answer questions about a directory the
// caller was not given.
var ErrOutsideRoots = errors.New("is outside every allowed root")

// New builds a guard over the given roots.
//
// A guard with no roots is refused rather than built, because the only thing
// such a guard could do is allow nothing -- and a caller that meant to allow
// something would find out at the first request rather than at startup. There
// is no default root for the same reason the rest of this build has no default
// permissions: a root nobody wrote down is a permission granted by omission.
//
// Each root is resolved through its symbolic links once, here. On macOS every
// temporary directory is reached through one, so a guard that kept the name it
// was given would refuse every path under its own root.
func New(roots []string) (*Guard, error) {
	if len(roots) == 0 {
		return nil, errors.New("no allowed root was given, and a guard without one can allow nothing")
	}

	resolved := make([]string, 0, len(roots))
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			return nil, errors.New("an allowed root is empty")
		}

		absolute, err := filepath.Abs(root)
		if err != nil {
			return nil, fmt.Errorf("allowed root %s: %w", root, err)
		}
		real, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			return nil, fmt.Errorf("allowed root %s: %w", root, err)
		}
		info, err := os.Stat(real)
		if err != nil {
			return nil, fmt.Errorf("allowed root %s: %w", root, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("allowed root %s is not a directory", root)
		}
		resolved = append(resolved, real)
	}
	return &Guard{roots: resolved}, nil
}

// Resolve returns the real path of a file inside one of the roots, or
// ErrOutsideRoots.
//
// The path is resolved through its symbolic links before it is compared, so a
// name inside a root that leads to a file outside one is refused: the check is
// about which file is read, not about how it was spelled. A path that cannot be
// resolved at all is refused the same way, because a guard that fell back to
// comparing the name would be answering a different question than the one it
// was asked.
func (g *Guard) Resolve(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%s %w", path, ErrOutsideRoots)
	}
	real, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", fmt.Errorf("%s %w", path, ErrOutsideRoots)
	}

	for _, root := range g.roots {
		if contains(root, real) {
			return real, nil
		}
	}
	return "", fmt.Errorf("%s %w", path, ErrOutsideRoots)
}

// contains reports whether a resolved path is the root or sits beneath it.
//
// The comparison is per path element. A prefix comparison on the string would
// admit a sibling directory whose name merely starts the same way, which is the
// oldest way out of a confinement there is.
func contains(root, path string) bool {
	if path == root {
		return true
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}
