// Package model is the normalized, cloud-neutral view of an infrastructure
// change.
//
// It knows nothing about Terraform, about any cloud, or about how a plan is
// read. Provider mappers translate into it; policy rules read out of it. That
// direction is the whole point: a rule written against this model applies to
// every cloud a mapper exists for, and adding a cloud cannot require changing a
// rule.
//
// Normalization is deliberately narrow. Two clouds share a capability here only
// where the semantics are genuinely equivalent; anything else stays opaque
// rather than being forced into a shape it does not fit.
//
// Every normalized fact carries its provenance, because a finding a reader
// cannot trace back to a provider attribute is not evidence.
package model
