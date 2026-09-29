package pathguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MaxDirectoryEntries bounds how many entries a directory may hold before the
// guard refuses to enumerate it at all.
//
// The milestone's requirement is that a directory too large is refused rather
// than walked, and the refusal has to come before any of it is opened: a caller
// that discovers the bound halfway through has already read half a directory it
// was not supposed to read. A Terraform module is a handful of files; this is
// far past any real one and short of what an unbounded enumeration costs.
const MaxDirectoryEntries = 1024

// ErrTooManyEntries reports a directory the guard will not enumerate.
var ErrTooManyEntries = errors.New("holds more entries than this build will enumerate")

// ErrNotADirectory reports a path named where a directory belongs.
//
// Separate from ErrOutsideRoots for the reason ErrIsADirectory is: a caller that
// handed over a file name has a different mistake to fix than one that reached
// outside the roots, and telling them the file is outside a root that holds it
// sends them to widen the root instead.
var ErrNotADirectory = errors.New("names a file rather than a directory")

// Files calls fn once for each regular file directly in dir whose name ends in
// one of the suffixes, with the file already open and closed afterwards. Names
// are yielded in lexical order, and are base names rather than paths.
//
// It is deliberately not recursive. A Terraform module is the files in one
// directory and not those in its subdirectories -- a subdirectory is a different
// module -- so a recursive read would attribute one module's declarations to
// another, which is exactly the wrong line this milestone exists to avoid.
//
// It hands over open files rather than names for the reason Open does: a name
// the guard approved is a name someone else can re-point between the approval
// and the read. Nothing derived from the enumeration is ever reopened.
//
// A symbolic link is not a regular file and is skipped, whether it points inside
// a root or out of one. Terraform's own module loader reads the files in a
// directory; a link there is an unusual thing to find, and reading through one
// means the file whose line is reported is not the file that was named.
//
// An empty suffix list yields nothing. It is not "every file": a guard that
// answered with everything when asked for nothing would read a private key
// because a caller forgot an argument.
func (g *Guard) Files(dir string, suffixes []string, fn func(name string, f *os.File) error) error {
	if len(suffixes) == 0 {
		return nil
	}

	absolute, err := filepath.Abs(dir)
	if err != nil {
		return refuse(dir)
	}
	if climbs(dir) {
		return fmt.Errorf("%s %w", dir, ErrNamesAParent)
	}
	if strings.Count(filepath.ToSlash(absolute), "/") > maxComponents {
		return fmt.Errorf("%s %w", dir, ErrTooDeep)
	}

	for _, r := range g.roots {
		relative, inside := beneath(r, absolute)
		if !inside {
			continue
		}
		return r.list(dir, relative, suffixes, fn)
	}
	return refuse(dir)
}

// list enumerates one directory inside a root.
//
// Everything about the directory is asked of the root's own open handle rather
// than of the filesystem by name, so a path that leaves the root -- through a
// linked directory, or a link placed while this runs -- is refused by the
// operating system rather than by a check this package wrote.
func (r root) list(named, relative string, suffixes []string, fn func(string, *os.File) error) error {
	if relative != "" {
		info, err := r.open.Stat(relative)
		if err != nil {
			// Either the root refused the path as an escape, or it is not
			// there. Both are one refusal, for the reason ErrOutsideRoots
			// gives.
			return refuse(named)
		}
		if !info.IsDir() {
			return fmt.Errorf("%s %w", named, ErrNotADirectory)
		}
	}

	within := "."
	if relative != "" {
		within = filepath.ToSlash(relative)
	}
	entries, err := fs.ReadDir(r.open.FS(), within)
	if err != nil {
		return refuse(named)
	}
	// Before anything is opened: a caller that learns the bound halfway through
	// has already read half of a directory it should not have read.
	if len(entries) > MaxDirectoryEntries {
		return fmt.Errorf("%s %w", named, ErrTooManyEntries)
	}

	for _, entry := range entries {
		if !entry.Type().IsRegular() || !matches(entry.Name(), suffixes) {
			continue
		}
		if err := r.yield(named, filepath.Join(relative, entry.Name()), entry.Name(), fn); err != nil {
			return err
		}
	}
	return nil
}

// yield opens one file and hands it to the caller.
func (r root) yield(named, relative, name string, fn func(string, *os.File) error) error {
	file, err := r.open.OpenFile(relative, os.O_RDONLY|nonBlocking, 0)
	if err != nil {
		return refuse(named)
	}
	defer file.Close()

	// The directory entry said this was a regular file; the open file is asked
	// again, because between the two the name could have been replaced by a
	// device or a pipe, and reading one of those is not reading configuration.
	//
	// No test stages it. The entry check above already refuses everything a
	// test can put there before the open, and the window this closes needs the
	// replacement to happen between the two calls -- so this line is here for
	// the same reason Open returns a handle instead of a name, and is the one
	// place in this package a mutation survives the suite.
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return refuse(named)
	}
	return fn(name, file)
}

// matches reports whether a name ends in one of the suffixes.
//
// The comparison is case-sensitive, because Terraform's is: a file named
// "MAIN.TF" is not configuration to it, and reporting a line from one would
// report a line from a file the plan was never made from.
func matches(name string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}
