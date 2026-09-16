// Package terraformplan parses Terraform and OpenTofu plan JSON into a
// provider-neutral raw change representation.
//
// It is the only package that knows the Terraform plan format, and it makes no
// judgement about what a change means: there is no resource-type registry, no
// cloud semantics, and no policy. Every resource change in the input appears in
// the output, including types no mapper will ever recognize.
//
// The package exists to preserve five states that a careless parser collapses.
// A field may be absent, explicitly null, false, zero, unknown until apply, or
// marked sensitive, and downstream rules reach different conclusions for each.
// Absence in particular is never a provider default.
//
// Values Terraform marks sensitive are discarded while reading. Only the path
// and the redacted state survive, so no part of this package holds a sensitive
// value that a later output path could disclose.
//
// Known behaviour: a JSON object containing a duplicate key resolves to the
// last occurrence, which is the encoding/json decoder's rule.
package terraformplan
