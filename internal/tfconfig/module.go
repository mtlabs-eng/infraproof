package tfconfig

import (
	"path"
	"strings"
)

// directoryOf returns the directory a module's declarations are written in,
// relative to the configuration root, and whether this build can resolve it.
//
// It follows the chain of calls the plan recorded, parent by parent, joining
// each source. Nothing about the chain is derived from the module's address:
// taking "module.storage" off the front of "module.storage.module.inner" is a
// prefix rule, and a module name is a repetition key away from being a string no
// prefix rule reads correctly. The plan's walk already knew which call made
// which.
//
// A source this build does not resolve stops it. A registry or remote module's
// files live under .terraform/modules behind a manifest -- a different input,
// with a different lifetime, and one nothing here reads -- so its declarations
// have no location rather than a location in whatever local directory the name
// happens to collide with.
func (l *locator) directoryOf(moduleAddress string) (string, bool) {
	if moduleAddress == "" {
		return ".", true
	}
	if cached, known := l.dirs[moduleAddress]; known {
		return cached, cached != ""
	}

	directory, resolved := l.resolve(moduleAddress)
	if !resolved {
		directory = ""
	}
	l.dirs[moduleAddress] = directory
	return directory, resolved
}

func (l *locator) resolve(moduleAddress string) (string, bool) {
	var sources []string
	for address := moduleAddress; address != ""; {
		call, declared := l.calls[address]
		if !declared {
			// The plan carries no configuration block, or none for this call.
			// Nothing is known about where its declarations are written.
			return "", false
		}
		// A chain cannot be longer than the number of calls without revisiting
		// one, and revisiting one is a chain that does not end. The bound is
		// the map's own size rather than a number chosen here, so it is a fact
		// about the plan rather than a guess about configurations.
		if len(sources) >= len(l.calls) {
			return "", false
		}
		sources = append(sources, call.Source)
		address = call.Parent
	}

	directory := "."
	for i := len(sources) - 1; i >= 0; i-- {
		if !localSource(sources[i]) {
			return "", false
		}
		directory = path.Join(directory, sources[i])
	}
	// A chain that climbs out of the configuration directory resolves to
	// nothing, before anything is opened, which is why the result is an absent
	// location rather than an error.
	//
	// It is not the guard's check repeated. A source that leaves the directory
	// and returns -- "../escaping" from the root called escaping -- cancels out
	// when the names are joined, so the guard sees a path inside the root and
	// reads it, handing one module the declarations of another. Whether it is
	// even the same directory is a question about symbolic links; the source
	// left the root either way.
	if directory == ".." || strings.HasPrefix(directory, "../") {
		return "", false
	}
	return directory, true
}

// localSource reports whether a module source names a directory on disk, using
// the rule Terraform uses: a local path begins with "./" or "../", and every
// other source is a registry address or a remote one.
func localSource(source string) bool {
	return strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../")
}
