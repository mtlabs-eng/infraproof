// Package intent loads and validates the Intent Contract: the structured,
// human-confirmed record of what a change is allowed and expected to do.
//
// The contract expresses declared intent, not truth. This package records its
// digest and checks its internal consistency; authentication, approval identity
// and cryptographic authorization are future concerns.
//
// It knows nothing about Terraform, clouds, or the Evidence Bundle. A contract
// is meaningful on its own, and the comparison against a plan belongs to the
// policy engine.
package intent
