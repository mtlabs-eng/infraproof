package pathguard_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/pathguard"
)

func file(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// TestAPathInsideARootIsAllowed is the ordinary case, and it has to keep
// working or the rest is a refusal to do anything at all.
func TestAPathInsideARootIsAllowed(t *testing.T) {
	root := t.TempDir()
	file(t, root, "plan.json")
	file(t, root, "nested/deep/plan.json")

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The root as the filesystem reaches it, not as the test spelled it. On
	// macOS a temporary directory is under /var, which is a link to
	// /private/var, so the resolved path is correct and does not begin with the
	// name it was given.
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}

	for name, path := range map[string]string{
		"at the root":        filepath.Join(root, "plan.json"),
		"nested":             filepath.Join(root, "nested/deep/plan.json"),
		"through a dot":      filepath.Join(root, ".", "plan.json"),
		"through a doubling": filepath.Join(root, "nested", "..", "plan.json"),
	} {
		t.Run(name, func(t *testing.T) {
			resolved, err := guard.Resolve(path)
			if err != nil {
				t.Fatalf("a path inside the root was refused: %v", err)
			}
			if !strings.HasPrefix(resolved, real+string(filepath.Separator)) {
				t.Errorf("resolved outside the root: %q", resolved)
			}
			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("the resolved path does not name the file: %v", err)
			}
		})
	}
}

// TestNothingOutsideARootIsReachable covers every way out of a directory that
// does not need a symlink.
func TestNothingOutsideARootIsReachable(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := file(t, outside, "secret.json")
	file(t, root, "plan.json")

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sibling := root + "-sibling"
	if err := os.MkdirAll(sibling, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	file(t, sibling, "plan.json")

	for name, path := range map[string]string{
		"an absolute path elsewhere": secret,
		"climbing out":               filepath.Join(root, "..", filepath.Base(outside), "secret.json"),
		"climbing far out":           filepath.Join(root, "..", "..", "..", "etc", "passwd"),
		"a sibling sharing a prefix": filepath.Join(sibling, "plan.json"),
		"the root's parent":          filepath.Dir(root),
	} {
		t.Run(name, func(t *testing.T) {
			if resolved, err := guard.Resolve(path); err == nil {
				t.Errorf("a path outside every root was allowed: %q -> %q", path, resolved)
			}
		})
	}
}

// TestASymlinkIsNotADoorOutOfTheRoot is the case a prefix comparison cannot
// see. The name is inside the root and the file is not.
func TestASymlinkIsNotADoorOutOfTheRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege this test does not assume")
	}

	root := t.TempDir()
	outside := t.TempDir()
	file(t, outside, "secret.json")
	file(t, root, "plan.json")

	if err := os.Symlink(filepath.Join(outside, "secret.json"), filepath.Join(root, "link.json")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "door")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for name, path := range map[string]string{
		"a link to a file outside":      filepath.Join(root, "link.json"),
		"a link to a directory outside": filepath.Join(root, "door", "secret.json"),
	} {
		t.Run(name, func(t *testing.T) {
			if resolved, err := guard.Resolve(path); err == nil {
				t.Errorf("a symlink led out of the root: %q -> %q", path, resolved)
			}
		})
	}
}

// TestARootThatIsItselfASymlinkStillWorks is the other direction, and the one a
// naive fix breaks. On macOS every temporary directory is reached through one:
// /var is a link to /private/var, so a guard that compares the name it was
// given refuses every path under its own root.
func TestARootThatIsItselfASymlinkStillWorks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege this test does not assume")
	}

	real := t.TempDir()
	file(t, real, "plan.json")

	linked := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(real, linked); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	guard, err := pathguard.New([]string{linked})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for name, path := range map[string]string{
		"named through the link": filepath.Join(linked, "plan.json"),
		"named directly":         filepath.Join(real, "plan.json"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := guard.Resolve(path); err != nil {
				t.Errorf("a path inside the root was refused: %v", err)
			}
		})
	}
}

// TestAGuardWithNoRootsAllowsNothing keeps the default from being a permission
// nobody wrote. A server started without a root has been told where it may read
// from: nowhere.
func TestAGuardWithNoRootsAllowsNothing(t *testing.T) {
	if _, err := pathguard.New(nil); err == nil {
		t.Fatal("a guard with no roots was built, and would have had to allow something")
	}
	if _, err := pathguard.New([]string{}); err == nil {
		t.Fatal("a guard with an empty root list was built")
	}
}

// TestARootMustExistAndBeADirectory refuses at startup rather than on the first
// call, when the operator is still watching.
func TestARootMustExistAndBeADirectory(t *testing.T) {
	dir := t.TempDir()
	plain := file(t, dir, "notadir.json")

	for name, root := range map[string]string{
		"no such directory": filepath.Join(dir, "absent"),
		"a file":            plain,
		"empty":             "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := pathguard.New([]string{root}); err == nil {
				t.Errorf("a root that is not a usable directory was accepted: %q", root)
			}
		})
	}
}

// TestTheErrorNamesTheRuleAndNotTheFilesystem keeps a refusal from becoming a
// probe. Saying whether the path exists tells a caller about a filesystem it
// was not given access to.
func TestTheErrorNamesTheRuleAndNotTheFilesystem(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	present := file(t, outside, "present.json")

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, existing := guard.Resolve(present)
	_, absent := guard.Resolve(filepath.Join(outside, "absent.json"))
	if existing == nil || absent == nil {
		t.Fatal("a path outside the root was allowed")
	}

	// The same rule, named the same way, for a file that is there and one that
	// is not. Comparing the whole message would compare the two paths, which
	// differ because the test made them differ; what must not differ is what
	// the refusal says about the filesystem.
	for name, err := range map[string]error{"present": existing, "absent": absent} {
		if !errors.Is(err, pathguard.ErrOutsideRoots) {
			t.Errorf("the %s file was refused for some other reason: %v", name, err)
		}
		for _, leak := range []string{"no such file", "does not exist", "not found"} {
			if strings.Contains(strings.ToLower(err.Error()), leak) {
				t.Errorf("the refusal for the %s file reports the filesystem: %v", name, err)
			}
		}
	}
}
