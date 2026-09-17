package intent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Load reads and validates a contract from a file.
func Load(path string) (Contract, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// The path is the user's own argument, so naming it is not disclosure.
		return Contract{}, fmt.Errorf("reading intent contract %s: %w", path, err)
	}
	return Parse(raw, path)
}

// Parse reads a contract from its exact bytes.
//
// The digest is taken before decoding, so it identifies the file as supplied
// rather than a re-encoding of what was understood. A rejected contract returns
// no Contract at all: a partially read contract is the shape most likely to be
// mistaken for a complete one.
func Parse(raw []byte, source string) (Contract, error) {
	if looksLikeYAML(raw) {
		return Contract{}, fmt.Errorf(
			"reading intent contract %s: YAML is not supported in this build; supply the contract as JSON", source)
	}

	var wire wireContract
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return Contract{}, fmt.Errorf("reading intent contract %s: %w", source, err)
	}
	if decoder.More() {
		return Contract{}, fmt.Errorf(
			"reading intent contract %s: the file holds more than one document", source)
	}

	contract := wire.contract()
	contract.Digest = digest(raw)
	contract.Source = source

	if err := contract.validate(); err != nil {
		return Contract{}, fmt.Errorf("reading intent contract %s: %w", source, err)
	}
	return contract, nil
}

// looksLikeYAML recognizes the deferred format well enough to refuse it by
// name. A YAML file fed to a JSON decoder fails as a syntax error, which tells
// a reader nothing about why their file was rejected.
//
// It is deliberately conservative: valid JSON always begins with one of a small
// set of bytes, so anything else that is not empty is not JSON, and YAML is
// overwhelmingly the format it will be.
func looksLikeYAML(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	switch trimmed[0] {
	case '{', '[', '"', '-', 't', 'f', 'n':
		// JSON's own openers, and "-" which begins a negative number. A YAML
		// list at the top level also begins with "-", but a contract is a
		// mapping, so this costs nothing.
		return false
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return false
	}
	return true
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// wireContract is the on-disk shape. Every field is a pointer or a slice so
// that an omitted field is distinguishable from one written with its zero
// value: "environment": "" is a contract that said something wrong, and an
// omitted environment is a contract that said nothing, and both are invalid for
// different reasons a reader deserves to be told apart.
type wireContract struct {
	SchemaVersion      *string          `json:"schema_version"`
	ChangeID           *string          `json:"change_id"`
	Environment        *string          `json:"environment"`
	AllowedClouds      []string         `json:"allowed_clouds"`
	DestructiveChanges *string          `json:"destructive_changes"`
	Resources          []wireResource   `json:"resources"`
	Constraints        *wireConstraints `json:"constraints"`
}

type wireResource struct {
	Family   *string `json:"family"`
	Exposure *string `json:"exposure"`
	Purpose  string  `json:"purpose"`
}

type wireConstraints struct {
	AllowedRegions []string          `json:"allowed_regions"`
	RequiredTags   map[string]string `json:"required_tags"`
}

func (w wireContract) contract() Contract {
	contract := Contract{
		SchemaVersion:      derefString(w.SchemaVersion),
		ChangeID:           derefString(w.ChangeID),
		Environment:        derefString(w.Environment),
		AllowedClouds:      w.AllowedClouds,
		DestructiveChanges: DestructivePolicy(derefString(w.DestructiveChanges)),
	}
	for _, resource := range w.Resources {
		contract.Resources = append(contract.Resources, ResourceIntent{
			Family:   derefString(resource.Family),
			Exposure: Exposure(derefString(resource.Exposure)),
			Purpose:  resource.Purpose,
		})
	}
	if w.Constraints != nil {
		contract.Constraints = &Constraints{
			AllowedRegions: w.Constraints.AllowedRegions,
			RequiredTags:   w.Constraints.RequiredTags,
		}
	}

	// Presence is recorded separately from value, so validation can tell an
	// omitted field from one written empty.
	contract.present = presence{
		schemaVersion:      w.SchemaVersion != nil,
		changeID:           w.ChangeID != nil,
		environment:        w.Environment != nil,
		allowedClouds:      w.AllowedClouds != nil,
		destructiveChanges: w.DestructiveChanges != nil,
		resources:          w.Resources != nil,
	}
	for _, resource := range w.Resources {
		contract.present.resourceFields = append(contract.present.resourceFields, resourcePresence{
			family:   resource.Family != nil,
			exposure: resource.Exposure != nil,
		})
	}
	return contract
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}
