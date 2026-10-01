// Package tfconfig finds where a plan's declarations are written.
//
// A Terraform or OpenTofu plan carries no source positions: not on a resource
// change, not in its configuration block, nowhere. What it carries is the
// identity of each declaration and the source of each module call. So a line
// cannot be read out of a plan and has to be found in the .tf files -- and
// nothing ties a plan to the files that produced it. There is no source digest,
// and the files may have changed since.
//
// That is what shapes this package. A location is reported only when the
// declaration found at it matches the one the plan states, in the directory that
// plan's module calls resolve to. A declaration renamed, moved or deleted since
// the plan was made produces no location; so does one that matches twice, a
// module whose source is not a local path, and a file this build cannot lex to
// the end. Absence is an answer, and it is the safe one: a line that is merely
// plausible sends a reader to the wrong code with the tool's authority behind it.
//
// It locates declarations and does not evaluate HCL. The plan already answers
// what a value is, and answering it twice is how two answers come to disagree.
//
// Every read is confined to the configuration directory by internal/pathguard,
// and no content from any file it reads reaches its output: a location is a path
// and a line.
package tfconfig
