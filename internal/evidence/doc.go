// Package evidence defines the InfraProof Evidence Bundle: the canonical,
// machine-readable result of a verification.
//
// The package models the Version 1 contract documented in
// docs/EVIDENCE-BUNDLE.md, validates its invariants, imposes a deterministic
// ordering on its collections, and maps a decision to a process exit code. It
// performs no I/O, contains no Terraform, cloud, or policy semantics, and never
// terminates the process.
package evidence

// SchemaVersion is the Evidence Bundle contract version this package writes.
// Readers accept any 1.x version and ignore fields they do not recognize.
const SchemaVersion = "1.1"

// intentDigestMinor is the minor version that added subject.intent_digest. A
// bundle declaring an earlier one predates the field, and refusing it would be
// a breaking change inside a major version — which this contract says needs a
// new major version.
const intentDigestMinor = 1
