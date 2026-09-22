package intent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	// The digest is over the bytes as supplied, so trimming a byte order mark
	// for parsing must not change what the contract is identified as.
	body := bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))

	if strings.HasSuffix(strings.ToLower(source), ".yaml") ||
		strings.HasSuffix(strings.ToLower(source), ".yml") {
		// By name as well as by content. A flow-style YAML document begins
		// with "{" and reaches the JSON decoder, where it fails as a syntax
		// error — the puzzle this refusal exists to prevent — and the
		// documentation says the refusal is by name.
		return Contract{}, fmt.Errorf(
			"reading intent contract %s: YAML is not supported in this build; supply the contract as JSON", source)
	}
	if looksLikeYAML(body) {
		return Contract{}, fmt.Errorf(
			"reading intent contract %s: YAML is not supported in this build; supply the contract as JSON", source)
	}

	// A duplicate key is accepted by encoding/json, which silently takes the
	// last occurrence. A contract declaring private exposure and then public
	// would be read as declaring public. DisallowUnknownFields exists to stop a
	// contract being read partially; this stops one being read selectively.
	if err := rejectDuplicateKeys(body); err != nil {
		return Contract{}, fmt.Errorf("reading intent contract %s: %w", source, err)
	}

	var wire wireContract
	decoder := json.NewDecoder(bytes.NewReader(body))
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
// The test is what the document cannot be rather than what it might be: valid
// JSON begins with one of a small, closed set of bytes, so anything else is not
// JSON, and YAML is overwhelmingly what it will be. The document marker "---"
// and a top-level list both begin with "-", which is also how a negative number
// begins, so that one byte is disambiguated by what follows it: a contract is a
// mapping, never a bare number.
func looksLikeYAML(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}

	switch trimmed[0] {
	case '{', '[', '"', 't', 'f', 'n':
		// JSON's own openers.
		return false
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return false
	case '-':
		// A negative number is JSON; "---" is a document marker and "- " opens
		// a list, and neither is.
		rest := trimmed[1:]
		return len(rest) == 0 || rest[0] == '-' || rest[0] == ' ' || rest[0] == '\t' ||
			rest[0] == '\n' || rest[0] == '\r'
	}
	return true
}

// rejectDuplicateKeys walks the document and refuses any object that names a
// field more than once, at any depth.
//
// It is written as a walk rather than a decode because the duplicate is gone by
// the time a decoder has finished: encoding/json keeps the last occurrence and
// reports nothing.
//
// Malformed input is not reported here. The decode that follows produces a
// better message for it, and reporting the same fault twice in two voices tells
// a reader less. But the walk must still stop: it cannot skip a token it failed
// to read and carry on, because a decoder in an error state answers More with
// true indefinitely.
func rejectDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	err := walkForDuplicates(decoder, "", 0)
	if errors.Is(err, errMalformed) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the document %w", err)
	}
	return nil
}

// errMalformed ends the walk without being reported. It carries no payload: the
// input may be a contract a user would rather not see quoted back.
var errMalformed = errors.New("intent: the document could not be tokenized")

// maxDepth bounds how far the walk will descend.
//
// json.Decoder.Token does not apply the nesting limit that Decode does, so this
// walk descended where the standard library refuses — and it descended
// expensively: a 600 KB file of nothing but brackets took forty seconds and two
// gigabytes, and the process died rather than reporting invalid input. Because
// the walk runs before the decode, it removed the standard library's guard from
// the path that runs first.
//
// A contract is a document a human writes. The documented one nests three
// levels and the schema has no recursive structure, so this costs nothing real.
const maxDepth = 64

// walkForDuplicates consumes exactly one JSON value from the decoder.
func walkForDuplicates(decoder *json.Decoder, path string, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("is nested more than %d levels deep", maxDepth)
	}

	token, err := decoder.Token()
	if err != nil {
		return errMalformed
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		// Keys are compared folded, because that is how the decoder matches
		// them: encoding/json fills the field "exposure" names from a key
		// spelled "Exposure", and DisallowUnknownFields does not fire, because
		// a field was matched. Comparing exact bytes let a contract declare
		// private exposure and then public and be read as declaring public.
		//
		// The exception is a field holding names rather than schema fields.
		// Cloud tag keys are case-sensitive, so two that differ only in case
		// are two tags, and refusing them would reject an ordinary contract.
		folded := !holdsNames(path)
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errMalformed
			}
			key, ok := keyToken.(string)
			if !ok {
				return errMalformed
			}
			identity := key
			if folded {
				identity = strings.ToLower(key)
			}
			if seen[identity] {
				return fmt.Errorf("has %s named more than once", join(path, key))
			}
			seen[identity] = true

			if err := walkForDuplicates(decoder, join(path, key), depth+1); err != nil {
				return err
			}
		}
	case '[':
		for i := 0; decoder.More(); i++ {
			if err := walkForDuplicates(decoder, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	}

	// The closing delimiter.
	if _, err := decoder.Token(); err != nil {
		return errMalformed
	}
	return nil
}

// holdsNames reports the contract paths whose keys are names a user chose
// rather than fields this build defines. It is derived from the contract type:
// required_tags is the only map in it.
func holdsNames(path string) bool {
	return path == "constraints.required_tags"
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
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
