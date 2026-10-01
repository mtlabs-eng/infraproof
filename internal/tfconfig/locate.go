package tfconfig

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
	"github.com/mtlabs-eng/infraproof/internal/pathguard"
	"github.com/mtlabs-eng/infraproof/internal/terraformplan"
)

// maxFileBytes bounds one configuration file, and maxTotalBytes bounds
// everything one run reads. A module is a handful of files of a few kilobytes;
// both are far past any real configuration and short of what an unbounded read
// costs. Past either, nothing more is read and nothing more is located, because
// a location this build did not verify is a location it must not report.
const (
	maxFileBytes  = 512 << 10
	maxTotalBytes = 8 << 20
)

// Annotate returns the bundle with a source location on every finding and
// evidence reference one could be found for.
//
// A plan carries no source positions anywhere, so a location is found in the
// configuration and then checked: the declaration at the position has to be the
// one the plan states, by kind, type and name, in the directory the module
// resolves to. Anything else -- a declaration renamed, moved or deleted since
// the plan was made, two that match, a module whose source this build does not
// resolve -- produces no location. Absence is an answer, and it is the safe one:
// nothing ties a plan to the files that produced it, and a line that is merely
// plausible sends a reader to the wrong code with the tool's authority behind it.
//
// Nothing it adds can change a verdict. It returns a canonical copy, so the
// bundle the caller passed in is untouched.
//
// The only error is the configuration directory itself. A directory that cannot
// be opened was almost certainly the wrong argument, and locating nothing
// silently would leave that undiscovered; everything after it is an absence
// rather than a failure.
func Annotate(bundle evidence.Bundle, plan terraformplan.Plan, root string) (evidence.Bundle, error) {
	finder, err := newLocator(plan, root)
	if err != nil {
		return evidence.Bundle{}, err
	}
	defer finder.close()

	out := evidence.Canonical(bundle)
	for i := range out.Findings {
		finding := &out.Findings[i]
		if finding.Resource != nil {
			finding.Resource.Location = finder.declarationAt(finding.Resource.Address)
		}
		for j := range finding.Evidence {
			finding.Evidence[j].Location = finder.evidenceAt(finding.Evidence[j])
		}
	}
	for i := range out.Unknowns {
		for j := range out.Unknowns[i].Evidence {
			out.Unknowns[i].Evidence[j].Location = finder.evidenceAt(out.Unknowns[i].Evidence[j])
		}
	}
	return out, nil
}

// locator answers where a plan address is written.
type locator struct {
	guard *pathguard.Guard
	root  string

	// changes is the plan's own account of every address, so that identifying a
	// declaration never means parsing an address. A bundle names an address; the
	// plan already broke that address into a kind, a type, a name and a module,
	// and this build reads those rather than deriving them a second time.
	changes map[string]terraformplan.ResourceChange
	calls   map[string]terraformplan.ModuleCall

	dirs    map[string]string
	scanned map[string][]placed
	// remaining is what is left of this run's reading budget. Once spent, later
	// lookups find nothing rather than reading further.
	remaining int64
}

// placed is a declaration together with the file it was found in.
type placed struct {
	declaration
	file string
}

func newLocator(plan terraformplan.Plan, root string) (*locator, error) {
	// Resolved once, here, because the guard refuses a path that names a parent
	// directory and a caller is entitled to write one: "--config ../infra" is an
	// ordinary argument. The guard resolves its own roots the same way, so the
	// two agree about which directory this is, and every path handed to it from
	// here on is built from the resolved one.
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	guard, err := pathguard.New([]string{absolute})
	if err != nil {
		return nil, err
	}

	finder := &locator{
		guard:     guard,
		root:      absolute,
		changes:   make(map[string]terraformplan.ResourceChange, len(plan.ResourceChanges)),
		calls:     plan.ModuleCalls,
		dirs:      map[string]string{},
		scanned:   map[string][]placed{},
		remaining: maxTotalBytes,
	}
	for _, change := range plan.ResourceChanges {
		finder.changes[change.Address] = change
	}
	return finder, nil
}

func (l *locator) close() { _ = l.guard.Close() }

// declarationAt returns where the resource at a plan address is declared.
func (l *locator) declarationAt(address string) *evidence.Location {
	found, dir, ok := l.find(address)
	if !ok {
		return nil
	}
	return at(dir, found.file, found.Line)
}

// evidenceAt returns where an evidence reference's data is written: the argument
// itself when it is written in the block, and the block otherwise.
//
// An argument set from a variable, a local, a module input or a dynamic block is
// not in that block at all, and the block is where a reader goes to find out
// what set it. Reporting nothing there would withhold the one position this
// build is sure of.
func (l *locator) evidenceAt(ref evidence.EvidenceRef) *evidence.Location {
	found, dir, ok := l.find(ref.ResourceAddress)
	if !ok {
		return nil
	}
	if line, written := found.Attributes[firstSegment(ref.Path)]; written {
		return at(dir, found.file, line)
	}
	return at(dir, found.file, found.Line)
}

// at builds a location from a directory relative to the configuration root, a
// file name inside it, and a line -- and reports none when the contract cannot
// carry the result.
//
// The names come from a filesystem, and the contract holds a location to a path
// it can spell. Composing one it refuses makes the bundle invalid after the
// verdict has been reached, which turns a file called "we\\ird.tf" into an
// internal failure and no report at all for a change that blocks. The rule is
// asked of the package that owns it rather than restated here.
func at(dir, file string, line int) *evidence.Location {
	location := &evidence.Location{File: path.Join(dir, file), Line: line}
	if !location.Valid() {
		return nil
	}
	return location
}

// find returns the one declaration matching a plan address.
//
// Matching is on the plan's own account of the address -- kind, type and name,
// in the directory its module resolves to -- and never on the address text. It
// is the milestone's rule in one place: found once, it is the answer; found
// twice or not at all, there is no answer, and the nearest block is not it.
func (l *locator) find(address string) (placed, string, bool) {
	change, present := l.changes[address]
	if !present {
		return placed{}, "", false
	}
	dir, resolved := l.directoryOf(change.ConfigModuleAddress())
	if !resolved {
		return placed{}, "", false
	}

	kind := "resource"
	if change.Mode == terraformplan.ModeData {
		kind = "data"
	}

	var match placed
	matches := 0
	for _, candidate := range l.declarationsIn(dir) {
		if candidate.Kind == kind && candidate.Type == change.Type && candidate.Name == change.Name {
			match = candidate
			matches++
		}
	}
	if matches != 1 {
		return placed{}, "", false
	}
	return match, dir, true
}

// declarationsIn reads one module directory, once.
func (l *locator) declarationsIn(dir string) []placed {
	if cached, read := l.scanned[dir]; read {
		return cached
	}

	var found []placed
	err := l.guard.Files(filepath.Join(l.root, filepath.FromSlash(dir)), []string{".tf"},
		func(name string, file *os.File) error {
			if ignoredFile(name) {
				return nil
			}
			source, err := l.read(file)
			if err != nil {
				return err
			}
			for _, d := range scan(source) {
				found = append(found, placed{declaration: d, file: name})
			}
			return nil
		})
	if err != nil {
		// A directory that cannot be read is a directory nothing is known
		// about. It is recorded as read so that a plan naming it many times
		// does not ask the filesystem again for the same refusal.
		found = nil
	}

	l.scanned[dir] = found
	return found
}

// read takes one file's bytes, within the bound and within what is left of the
// run's budget.
func (l *locator) read(file *os.File) ([]byte, error) {
	limit := min(int64(maxFileBytes), l.remaining)
	source, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	l.remaining -= int64(len(source))

	if int64(len(source)) > limit {
		// Either this file is past the per-file bound or the run is past its
		// own. Both mean the file was not read whole, and a position from a
		// partial read is a position in a file this build has not seen.
		return nil, errTooLarge
	}
	return source, nil
}

// errTooLarge reports a file this build will not read whole. It never reaches a
// caller: it ends one directory's scan, and the absence of a location is what a
// reader sees.
var errTooLarge = errorString("is larger than this build reads")

type errorString string

func (e errorString) Error() string { return string(e) }

// ignoredFile reports a file Terraform's own module loader skips, so that no
// line is offered from a file no plan was ever made from.
//
// Terraform skips three shapes: a name beginning with a dot, one ending in a
// tilde, and an emacs lock file wrapped in hashes. Only the first can arrive
// here, because the guard yields names ending in ".tf" and the other two do not.
// Restating a rule whose cases cannot occur is how a restatement drifts from the
// rule it copies without any test being able to tell.
func ignoredFile(name string) bool {
	return strings.HasPrefix(name, ".")
}

// firstSegment returns the leading name of an evidence path: "tags" of
// "tags.environment", "grant" of "grant[0].permission".
//
// Only the first segment can be looked for, because only the first is an
// argument of the resource. What is inside it is written wherever the expression
// that produced it is, and finding that out means evaluating HCL, which this
// milestone does not do -- the plan already answers what a value is, and
// answering it twice is how two answers come to disagree.
func firstSegment(attributePath string) string {
	for i := 0; i < len(attributePath); i++ {
		if attributePath[i] == '.' || attributePath[i] == '[' {
			return attributePath[:i]
		}
	}
	return attributePath
}
