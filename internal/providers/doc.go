// Package providers turns a parsed plan into the normalized graph the rules
// read.
//
// It owns correlation, so that adding a cloud cannot change how resources are
// related to one another. A mapper is handed a subject and the resources that
// refer to it; it decides what those mean for its own cloud and nothing else.
//
// Correlation is by configuration reference, never by attribute value. In a
// plan, a control resource's bucket field holds the bucket's id, which is
// unknown until apply — so matching on values would fail exactly where
// correlation matters.
//
// Nothing outside this package and the command may import a provider
// subpackage. The universal rules depend on the model alone, which is what
// makes them universal.
package providers
