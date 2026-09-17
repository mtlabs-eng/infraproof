// Package policy evaluates deterministic rules over the normalized graph.
//
// A rule reads the model and nothing else. It does not know which cloud a
// resource came from, which provider resource carried the value, or how the
// plan was parsed — that knowledge lives in the mappers, and reaches the output
// only as evidence a mapper attached.
//
// That is what makes one rule cover three clouds, and what makes adding a
// fourth a change to the provider registry alone. The import-boundary test in
// this package turns the property into something the compiler enforces rather
// than something a reviewer has to remember.
package policy
