package render

import (
	"bytes"
	"encoding/json"

	"github.com/mtlabs-eng/infraproof/internal/evidence"
)

// JSON renders the canonical Evidence Bundle representation: two-space
// indentation, documented key order, a trailing newline, and no HTML escaping,
// so the output is diffable and stable across runs.
//
// It returns the validation error without rendering when the bundle violates
// the contract.
func JSON(b evidence.Bundle) ([]byte, error) {
	if err := b.Validate(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	// Escaping <, > and & would make the output depend on the incidental
	// punctuation of a summary or claim rather than on its content.
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(evidence.Canonical(b)); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
