// Package pathguard decides which files a caller may read, and opens them.
//
// The adapter is handed paths by something else -- an agent, a client, a
// person -- and a verifier that reads whatever it is pointed at is a file
// reader with extra steps. Milestone 05 requires that nothing outside
// explicitly allowed roots is reachable, and this is the one place that is
// decided.
//
// It returns an open file rather than a name it approved. A guard that answers
// "this name is inside a root" has answered about the filesystem as it was, and
// between that answer and the caller's read a regular file can become a symlink
// pointing anywhere: the check passes and the read escapes. Independent review
// of this milestone did exactly that, eight times in twenty-five attempts. The
// name never leaves this package now, so there is nothing for anyone to
// re-point.
package pathguard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Guard opens files inside a fixed set of roots and refuses everything else.
type Guard struct {
	roots []root
}

type root struct {
	// name is the root as the operator wrote it, for diagnostics.
	name string
	// info identifies the directory itself, so a path is matched by which
	// directory it is under rather than by how that directory is spelled. A
	// filesystem that folds case or Unicode form -- macOS by default -- has one
	// directory under several names, and comparing the names refuses files that
	// are genuinely inside the root.
	info os.FileInfo
	// open is the operating system's own confinement. Every path is opened
	// through it, which refuses a symlink out of the root and does so without a
	// window: it walks the path itself rather than approving a name for someone
	// else to open.
	open *os.Root
}

// ErrOutsideRoots reports a path the guard will not read.
//
// It is one error for every refusal, and deliberately says nothing about the
// filesystem: a message that distinguished "outside the roots" from "outside
// the roots and not there anyway" would answer questions about a directory the
// caller was not given.
var ErrOutsideRoots = errors.New("is outside every allowed root")

// ErrNamesAParent reports a path that names a parent directory.
//
// Separate from ErrOutsideRoots because a caller acts on the two differently.
// One message for every refusal is right about existence -- saying whether a
// file outside the roots is there answers a question about a directory the
// caller was not given -- and wrong about a path the caller wrote: telling them
// a climbing path is outside every root is false when the file is inside one,
// and a reader concludes the root is too narrow and asks for a wider one, which
// is the opposite of the fix. The path is theirs; repeating the rule discloses
// nothing.
var ErrNamesAParent = errors.New(
	"names a parent directory; give the path to the file rather than a route to it")

// ErrTooDeep reports a path with more components than the guard will walk.
//
// Deciding which root holds a path walks up from the path, asking the
// filesystem about each ancestor, and the number of ancestors is the caller's
// to choose. A hundred thousand components cost thirty seconds of stat calls
// for a path that was never going to open -- and it happens before the
// verification deadline, which is the only other bound the server has.
var ErrTooDeep = errors.New("names more directories than this build will walk")

// ErrIsADirectory reports a path that names a directory rather than a file.
//
// Separate for the reason ErrNamesAParent is: a root is inside the roots, and
// telling a caller it is outside them sends them to widen a root that already
// holds what they named.
var ErrIsADirectory = errors.New("names a directory rather than a file")

// maxComponents bounds how many directories a path may name, counted from the
// filesystem root rather than from the allowed root -- which is what the check
// measures, and is the smaller number of the two. A deeply nested project is
// tens of directories and sits some way down the disk; this is past both and
// short of what an unbounded walk costs.
const maxComponents = 256

// New builds a guard over the given roots.
//
// A guard with no roots is refused rather than built, because the only thing
// such a guard could do is allow nothing -- and a caller that meant to allow
// something would find out at the first request rather than at startup. There
// is no default root for the same reason the rest of this build has no default
// permissions: a root nobody wrote down is a permission granted by omission.
func New(roots []string) (*Guard, error) {
	if len(roots) == 0 {
		return nil, errors.New("no allowed root was given, and a guard without one can allow nothing")
	}

	guard := &Guard{}
	for _, name := range roots {
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("an allowed root is empty")
		}
		absolute, err := filepath.Abs(name)
		if err != nil {
			return nil, fmt.Errorf("allowed root %s: %w", name, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, fmt.Errorf("allowed root %s: %w", name, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("allowed root %s is not a directory", name)
		}
		opened, err := os.OpenRoot(absolute)
		if err != nil {
			return nil, fmt.Errorf("allowed root %s: %w", name, err)
		}
		guard.roots = append(guard.roots, root{name: absolute, info: info, open: opened})
	}
	return guard, nil
}

// Close releases the directories the guard holds open.
func (g *Guard) Close() error {
	var errs []error
	for _, r := range g.roots {
		if err := r.open.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Open returns the file at path, if it is inside a root.
//
// The open does not wait. A named pipe with no writer would otherwise block
// here, before the caller could look at what kind of file it is, and the server
// would stop for as long as whoever placed it there cared to leave it.
//
// A path naming a parent directory is refused rather than cleaned. Removing
// "nested/.." lexically also removes whatever "nested" was a link to, so the
// path names one file and another is read -- which lands inside a root and is
// still a report about something the argument did not name.
func (g *Guard) Open(path string) (*os.File, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, refuse(path)
	}
	if climbs(path) {
		return nil, fmt.Errorf("%s %w", path, ErrNamesAParent)
	}
	// Counted against the text, in one pass, before anything asks the
	// filesystem about any of it.
	if strings.Count(filepath.ToSlash(absolute), "/") > maxComponents {
		return nil, fmt.Errorf("%s %w", path, ErrTooDeep)
	}

	for _, r := range g.roots {
		relative, inside := beneath(r, absolute)
		if !inside {
			continue
		}
		if relative == "" {
			return nil, fmt.Errorf("%s %w", path, ErrIsADirectory)
		}
		file, err := r.open.OpenFile(relative, os.O_RDONLY|nonBlocking, 0)
		if err != nil {
			// Either the operating system refused the path as an escape, or
			// the file is not there. Both are one refusal, for the reason
			// ErrOutsideRoots gives.
			return nil, refuse(path)
		}
		return file, nil
	}
	return nil, refuse(path)
}

func refuse(path string) error {
	return fmt.Errorf("%s %w", path, ErrOutsideRoots)
}

// climbs reports whether a path names a parent directory anywhere along it.
func climbs(path string) bool {
	for _, element := range strings.Split(filepath.ToSlash(path), "/") {
		if element == ".." {
			return true
		}
	}
	return false
}

// beneath returns the path of absolute relative to the root, and whether it is
// under it at all.
//
// The walk compares directories rather than names. filepath.Rel compares text,
// which is the right answer on a filesystem that distinguishes every byte and
// the wrong one on macOS, where "Case" and "case" are one directory: a byte
// comparison there refuses a file that is genuinely inside the root, and the
// refusal says it is outside, which is false.
func beneath(r root, absolute string) (string, bool) {
	var elements []string
	current := absolute

	for {
		if info, err := os.Stat(current); err == nil && os.SameFile(info, r.info) {
			if len(elements) == 0 {
				// The path is the root itself: inside the roots, and not
				// something to read.
				return "", true
			}
			return filepath.Join(elements...), true
		}

		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		elements = append([]string{filepath.Base(current)}, elements...)
		current = parent
	}
}
