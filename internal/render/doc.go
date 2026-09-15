// Package render turns an Evidence Bundle into output.
//
// JSON is canonical: byte-identical for identical input, with no timestamp,
// generated identifier, or local path. Markdown is a deterministic rendering of
// the same in-memory bundle, never a second source of truth.
//
// Both renderers validate the bundle first and refuse to render one that
// violates the contract, so invalid evidence cannot reach a consumer.
package render
