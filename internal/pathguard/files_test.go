package pathguard_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/pathguard"
)

// collect reads every file the guard yields for a directory, keyed by name.
func collect(t *testing.T, g *pathguard.Guard, dir string, suffixes []string) map[string]string {
	t.Helper()
	got := map[string]string{}
	err := g.Files(dir, suffixes, func(name string, f *os.File) error {
		raw, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		got[name] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("Files(%s): %v", dir, err)
	}
	return got
}

// TestFilesYieldsMatchingFilesInOneDirectory is the ordinary case. A Terraform
// module is the files in one directory and not its subdirectories, so the
// enumeration is deliberately not recursive: a nested directory is a different
// module, and reading it here would attribute its declarations to this one.
func TestFilesYieldsMatchingFilesInOneDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("root"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "variables.tf"), []byte("vars"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("prose"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "modules", "storage"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "modules", "storage", "main.tf"), []byte("inner"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	guard, err := pathguard.New([]string{dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	got := collect(t, guard, dir, []string{".tf"})
	if len(got) != 2 || got["main.tf"] != "root" || got["variables.tf"] != "vars" {
		t.Fatalf("root directory yielded %v, want main.tf and variables.tf only", got)
	}

	inner := collect(t, guard, filepath.Join(dir, "modules", "storage"), []string{".tf"})
	if len(inner) != 1 || inner["main.tf"] != "inner" {
		t.Fatalf("nested directory yielded %v, want its own main.tf", inner)
	}
}

// TestFilesRefusesADirectoryOutsideEveryRoot covers the whole reason this
// package exists. Enumeration is a read like any other and is confined the same
// way.
func TestFilesRefusesADirectoryOutsideEveryRoot(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "main.tf"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	var yielded []string
	err = guard.Files(outside, []string{".tf"}, func(name string, f *os.File) error {
		yielded = append(yielded, name)
		return nil
	})
	if !errors.Is(err, pathguard.ErrOutsideRoots) {
		t.Fatalf("error = %v, want ErrOutsideRoots", err)
	}
	if len(yielded) != 0 {
		t.Fatalf("a refused directory still yielded %v", yielded)
	}
}

// TestFilesRefusesAClimbingPath covers the path that lands inside a root while
// naming something else along the way, for the reason Open refuses it: removing
// "nested/.." lexically also removes whatever "nested" was a link to.
func TestFilesRefusesAClimbingPath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	// Assembled rather than joined: filepath.Join cleans the ".." away, and the
	// path a caller wrote is what the guard has to refuse.
	climbing := root + string(filepath.Separator) + "nested" +
		string(filepath.Separator) + ".." + string(filepath.Separator) + "nested"
	err = guard.Files(climbing, []string{".tf"}, func(string, *os.File) error {
		t.Fatal("a climbing path yielded a file")
		return nil
	})
	if !errors.Is(err, pathguard.ErrNamesAParent) {
		t.Fatalf("error = %v, want ErrNamesAParent", err)
	}
}

// TestFilesDoesNotFollowASymbolicLinkOutOfTheRoot is the escape this milestone
// has to be proof against: a module directory holding a link to somewhere else
// on the disk. The link is neither read nor reported.
func TestFilesDoesNotFollowASymbolicLinkOutOfTheRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege this test will not ask for")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.tf"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("root"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.tf"), filepath.Join(root, "linked.tf")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	got := map[string]string{}
	err = guard.Files(root, []string{".tf"}, func(name string, f *os.File) error {
		raw, err := io.ReadAll(f)
		if err != nil {
			return err
		}
		got[name] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if _, present := got["linked.tf"]; present {
		t.Fatalf("a symbolic link out of the root was read: %v", got)
	}
	if got["main.tf"] != "root" {
		t.Fatalf("the ordinary file was not read: %v", got)
	}
}

// TestFilesDoesNotFollowASymbolicLinkedDirectory covers the same escape one
// level up: the directory named is a link pointing outside.
func TestFilesDoesNotFollowASymbolicLinkedDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic links need a privilege this test will not ask for")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.tf"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "modules")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	err = guard.Files(filepath.Join(root, "modules"), []string{".tf"}, func(name string, f *os.File) error {
		t.Fatalf("a linked directory yielded %s", name)
		return nil
	})
	if err == nil {
		t.Fatal("a directory that is a link out of the root should be refused")
	}
}

// TestFilesRefusesADirectoryWithTooManyEntries covers the bound the milestone
// requires: a directory too large is refused rather than walked.
func TestFilesRefusesADirectoryWithTooManyEntries(t *testing.T) {
	root := t.TempDir()
	for i := range pathguard.MaxDirectoryEntries + 1 {
		name := filepath.Join(root, "f"+strconv.Itoa(i)+".tf")
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	var yielded int
	err = guard.Files(root, []string{".tf"}, func(string, *os.File) error {
		yielded++
		return nil
	})
	if !errors.Is(err, pathguard.ErrTooManyEntries) {
		t.Fatalf("error = %v, want ErrTooManyEntries", err)
	}
	if yielded != 0 {
		t.Fatalf("a refused directory yielded %d files", yielded)
	}
}

// TestFilesRefusesAFileWhereADirectoryIsExpected keeps the two refusals
// distinguishable, as Open does: a caller handed a file name has a different
// mistake to fix than one handed a path outside the roots.
func TestFilesRefusesAFileWhereADirectoryIsExpected(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "main.tf")
	if err := os.WriteFile(path, []byte("root"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	err = guard.Files(path, []string{".tf"}, func(string, *os.File) error { return nil })
	if !errors.Is(err, pathguard.ErrNotADirectory) {
		t.Fatalf("error = %v, want ErrNotADirectory", err)
	}
}

// TestFilesStopsAtTheFirstErrorTheCallerReturns covers the contract a caller
// depends on to bound its own work: the walk is abandoned, and the error is the
// caller's own.
func TestFilesStopsAtTheFirstErrorTheCallerReturns(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"a.tf", "b.tf", "c.tf"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	stop := errors.New("enough")
	seen := 0
	err = guard.Files(root, []string{".tf"}, func(string, *os.File) error {
		seen++
		return stop
	})
	if !errors.Is(err, stop) {
		t.Fatalf("error = %v, want the caller's own error", err)
	}
	if seen != 1 {
		t.Fatalf("the walk continued past the error, yielding %d files", seen)
	}
}

// TestFilesYieldsNamesInOrder covers determinism. Two runs over one directory
// must produce the same report, and a map iteration or a filesystem's own order
// would not.
func TestFilesYieldsNamesInOrder(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"c.tf", "a.tf", "b.tf"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	var order []string
	if err := guard.Files(root, []string{".tf"}, func(name string, f *os.File) error {
		order = append(order, name)
		return nil
	}); err != nil {
		t.Fatalf("Files: %v", err)
	}
	want := []string{"a.tf", "b.tf", "c.tf"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}
}

// TestFilesWithNoSuffixesYieldsNothing covers the reading a caller must not be
// given by omission. An empty list is not "every file": a guard that answered
// with everything when asked for nothing would read a private key because a
// caller forgot an argument.
func TestFilesWithNoSuffixesYieldsNothing(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "main.tf"), []byte("root"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer guard.Close()

	if err := guard.Files(root, nil, func(name string, f *os.File) error {
		t.Fatalf("an empty suffix list yielded %s", name)
		return nil
	}); err != nil {
		t.Fatalf("Files: %v", err)
	}
}
