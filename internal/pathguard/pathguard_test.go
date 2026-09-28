package pathguard_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

	for name, path := range map[string]string{
		"at the root":   filepath.Join(root, "plan.json"),
		"nested":        filepath.Join(root, "nested/deep/plan.json"),
		"through a dot": filepath.Join(root, ".", "plan.json"),
	} {
		t.Run(name, func(t *testing.T) {
			file, err := guard.Open(path)
			if err != nil {
				t.Fatalf("a path inside the root was refused: %v", err)
			}
			defer file.Close()
			body, err := io.ReadAll(file)
			if err != nil {
				t.Fatalf("the file could not be read: %v", err)
			}
			if string(body) != "{}" {
				t.Errorf("read %q, want the file that was written", body)
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
			if file, err := guard.Open(path); err == nil {
				_ = file.Close()
				t.Errorf("a path outside every root was opened: %q", path)
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
			if file, err := guard.Open(path); err == nil {
				_ = file.Close()
				t.Errorf("a symlink led out of the root: %q", path)
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
			file, err := guard.Open(path)
			if err != nil {
				t.Errorf("a path inside the root was refused: %v", err)
				return
			}
			_ = file.Close()
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

	_, existing := guard.Open(present)
	_, absent := guard.Open(filepath.Join(outside, "absent.json"))
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

// TestASymlinkInstalledWhileReadingIsNotFollowed is the gap between checking a
// name and opening it.
//
// A guard that answers "this name is inside a root" has answered about the
// filesystem as it was. The caller then opens that name, and between the two a
// regular file can become a symlink pointing anywhere. The check passes, the
// read escapes, and what comes back is a file the operator never allowed.
//
// So the guard opens the file itself and hands back the handle. There is no
// name for anything to re-point in between.
func TestASymlinkInstalledWhileReadingIsNotFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege this test does not assume")
	}

	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.json"), []byte("OUTSIDE"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	target := filepath.Join(root, "plan.json")
	if err := os.WriteFile(target, []byte("INSIDE"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// One swapper that dwells in each state, rather than several racing as fast
	// as they can.
	//
	// The fast version was worse than the slow one it replaced: four goroutines
	// removing and recreating the file keep it absent most of the time, so the
	// open almost never reaches the moment between the check and the read with
	// a regular file in place. Measured against a reintroduced check-then-open
	// race, the tight loop caught it once in twenty runs and the shape it
	// replaced caught it fourteen times. Density is not the property; being in
	// the window when the reader arrives is.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			for _, asLink := range []bool{false, true} {
				select {
				case <-stop:
					return
				default:
				}
				_ = os.Remove(target)
				if asLink {
					_ = os.Symlink(filepath.Join(outside, "secret.json"), target)
				} else {
					_ = os.WriteFile(target, []byte("INSIDE"), 0o600)
				}
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()
	defer func() { close(stop); <-done }()

	for i := 0; i < 20000; i++ {
		file, err := guard.Open(target)
		if err != nil {
			// A refusal is fine: the file may not exist at this instant, or it
			// may be a link, and both are answers. Reading the outside file is
			// not.
			continue
		}
		body, err := io.ReadAll(file)
		_ = file.Close()
		if err != nil {
			continue
		}
		if strings.Contains(string(body), "OUTSIDE") {
			t.Fatalf("a symlink installed while opening led out of the root, on attempt %d", i)
		}
	}
}

// TestARootIsFoundHoweverItIsSpelled covers the filesystem this is developed
// on. APFS folds case and Unicode form by default, so "Case" and "case" are one
// directory -- and a guard comparing bytes refuses a file that is genuinely
// inside its root. The refusal then says the file is outside every allowed
// root, which is false and tells the caller nothing they can act on.
func TestARootIsFoundHoweverItIsSpelled(t *testing.T) {
	root := filepath.Join(t.TempDir(), "Case")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "plan.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	folded := filepath.Join(filepath.Dir(root), "case", "plan.json")
	if _, err := os.Stat(folded); err != nil {
		t.Skip("this filesystem distinguishes case, so there is nothing to fold")
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	file, err := guard.Open(folded)
	if err != nil {
		t.Fatalf("a file inside the root was refused for its spelling: %v", err)
	}
	_ = file.Close()
}

// TestAPathThatClimbsIsRefusedRatherThanCleaned covers a substitution nobody
// asked for.
//
// Cleaning "root/link/../plan.json" lexically removes the link along with the
// climb, so the path names one file and another is read. It lands inside a root,
// so nothing escapes -- but reporting on a file the argument did not name is an
// unstated fact matching another, which is the thing this build exists to
// refuse.
func TestAPathThatClimbsIsRefusedRatherThanCleaned(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "plan.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Built without filepath.Join, which cleans the climb away before the guard
	// can see it -- which is the whole point: the cleaning is what substitutes
	// one file for another, so a test that cleans first tests nothing.
	climbing := root + string(filepath.Separator) + "nested" +
		string(filepath.Separator) + ".." + string(filepath.Separator) + "plan.json"
	if file, err := guard.Open(climbing); err == nil {
		_ = file.Close()
		t.Error("a path that climbs was cleaned into a different one and read")
	}
}

// TestWhichSymlinksInsideARootStillWork states a restriction rather than
// leaving it to be discovered.
//
// The confinement walks the path itself instead of approving a name, which is
// what closes the window between the two. The cost is that it judges a link by
// the target as written: one written relative to where it sits resolves inside
// the root and opens, and one written as an absolute path does not, even when
// it names a file in the same root.
//
// That is a real refusal of a real arrangement -- a repository can hold either
// kind. It is accepted rather than worked around, because working around it
// means resolving the link here and handing back a name, which is the defect
// this design exists to remove. It is documented in docs/MCP.md so a caller
// meets it as a rule and not as a puzzle.
func TestWhichSymlinksInsideARootStillWork(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation needs a privilege this test does not assume")
	}

	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(real, "plan.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink("real", filepath.Join(root, "relative")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Symlink(real, filepath.Join(root, "absolute")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	file, err := guard.Open(filepath.Join(root, "relative", "plan.json"))
	if err != nil {
		t.Errorf("a link written relative to where it sits, naming a file in the same root, "+
			"was refused: %v", err)
	} else {
		_ = file.Close()
	}

	if file, err := guard.Open(filepath.Join(root, "absolute", "plan.json")); err == nil {
		_ = file.Close()
		t.Error("a link written as an absolute path was followed; if that is now allowed, " +
			"the documentation and this test should say so")
	}
}

// TestAPathIsRefusedBeforeItIsWalked bounds what a caller can make the guard
// spend.
//
// Deciding which root holds a path walks up from the path, asking the
// filesystem about each ancestor. The number of ancestors is the caller's to
// choose: a hundred thousand components cost thirty seconds of stat calls for a
// path that was never going to open, and it happens before the verification
// deadline, which is the only bound the server has. The count is checked first,
// against the string, which costs one pass.
func TestAPathIsRefusedBeforeItIsWalked(t *testing.T) {
	root := t.TempDir()
	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Built in one allocation. Joining a hundred thousand times is quadratic in
	// the test itself, which would make this measure the wrong thing.
	deep := root + strings.Repeat(string(filepath.Separator)+"a", 100000)

	done := make(chan error, 1)
	go func() {
		file, err := guard.Open(filepath.Join(deep, "plan.json"))
		if err == nil {
			_ = file.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a path a hundred thousand components deep was opened")
		} else if !errors.Is(err, pathguard.ErrTooDeep) {
			t.Errorf("refused for some other reason, which would pass this test while the "+
				"bound did nothing: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a path a hundred thousand components deep took more than two seconds to refuse; " +
			"the cost of deciding is the caller's to choose, and nothing else bounds it")
	}
}

// TestAnOrdinaryDepthIsStillAllowed keeps the bound off paths people write. A
// deeply nested project is a project, not an attack.
func TestAnOrdinaryDepthIsStillAllowed(t *testing.T) {
	root := t.TempDir()

	nested := root
	for range 40 {
		nested = filepath.Join(nested, "module")
	}
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	path := filepath.Join(nested, "plan.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	file, err := guard.Open(path)
	if err != nil {
		t.Fatalf("a path forty directories deep was refused: %v", err)
	}
	_ = file.Close()
}

// TestARefusalSaysWhichRuleItIs separates two refusals a caller acts on
// differently.
//
// One message for every refusal is right about existence: saying whether a file
// outside the roots is there answers a question about a directory the caller
// was not given. It is wrong about a path the caller wrote: telling them a
// climbing path is "outside every allowed root" is false when the file is
// inside one, and a model reading it concludes the root is wrong and asks for a
// wider one -- the opposite of the fix.
func TestARefusalSaysWhichRuleItIs(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "plan.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	guard, err := pathguard.New([]string{root})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	climbing := root + string(filepath.Separator) + "nested" +
		string(filepath.Separator) + ".." + string(filepath.Separator) + "plan.json"
	_, climbErr := guard.Open(climbing)
	if climbErr == nil {
		t.Fatal("a climbing path was opened")
	}
	if !errors.Is(climbErr, pathguard.ErrNamesAParent) {
		t.Errorf("a climbing path was refused as something else: %v", climbErr)
	}
	if errors.Is(climbErr, pathguard.ErrOutsideRoots) {
		t.Error("a path inside the root was reported as outside it, which is false and sends " +
			"a caller to widen the root")
	}

	_, outsideErr := guard.Open(filepath.Join(t.TempDir(), "plan.json"))
	if !errors.Is(outsideErr, pathguard.ErrOutsideRoots) {
		t.Errorf("a path outside every root was refused as something else: %v", outsideErr)
	}

	// The root itself is inside the roots and is not a file. Saying it is
	// outside them is the same false sentence, and sends a caller to widen a
	// root that already contains what they named.
	_, rootErr := guard.Open(root)
	if rootErr == nil {
		t.Fatal("the root directory was opened as a file")
	}
	if errors.Is(rootErr, pathguard.ErrOutsideRoots) {
		t.Errorf("the root was reported as outside itself: %v", rootErr)
	}
	if !errors.Is(rootErr, pathguard.ErrIsADirectory) {
		t.Errorf("the root was refused as something other than a directory: %v", rootErr)
	}
}
