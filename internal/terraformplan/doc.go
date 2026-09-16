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
// Reading is deliberately pessimistic, because plan JSON arrives from coding
// agents and third-party tooling as well as from Terraform itself:
//
//   - A mask whose shape cannot be applied to the value it describes — an
//     object mask over a string, an array mask shorter than the array it
//     covers, a mask node that is not a boolean, object or array — marks rather
//     than being ignored. A contradiction can be resolved toward disclosing a
//     value the producer asked to protect, or toward withholding one that may
//     have been safe; only the second is tolerable to be wrong about.
//   - Content after the plan document is rejected. A file holding a second
//     plan would otherwise be read as the first alone, so the change a human
//     reviews and the change this package reads would differ.
//   - Two masks that describe incompatible shapes over a value that is absent
//     cannot be reconciled against the value, so both claims are honoured
//     rather than one being silently dropped.
//   - A rejected plan returns its digest and nothing else. A half-built plan
//     invites a caller to act on data the parser refused to vouch for.
//
// One spelling is deliberately excluded from that pessimism. A mask node of
// JSON null is read as no mask at all, where a node of 1 or "yes" marks its
// subtree. The asymmetry is intended: null is the established spelling of
// absence in this format — Terraform writes it for the prior value of a
// created resource — whereas a number or a string in a mask position is
// nonsense, and nonsense is the case worth being pessimistic about.
//
// Known behaviour: a JSON object containing a duplicate key resolves to the
// last occurrence, which is the encoding/json decoder's rule.
package terraformplan
