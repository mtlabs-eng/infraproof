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
const SchemaVersion = "1.0"
