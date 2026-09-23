package intent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
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
	if notJSON(body) {
		return Contract{}, fmt.Errorf(
			"reading intent contract %s: this is not JSON; YAML is not supported in this build, "+
				"so supply the contract as JSON", source)
	}

	// A contract that names one field twice is read as saying the second
	// thing. DisallowUnknownFields exists to stop a contract being read
	// partially; this stops one being read selectively.
	if err := rejectRepeatedFields(body); err != nil {
		return Contract{}, fmt.Errorf("reading intent contract %s: the document %w", source, err)
	}

	wire, err := decodeContract(body)
	if err != nil {
		return Contract{}, fmt.Errorf("reading intent contract %s: %w", source, err)
	}

	contract := wire.contract()
	contract.Digest = digest(raw)
	contract.Source = source

	if err := contract.validate(); err != nil {
		return Contract{}, fmt.Errorf("reading intent contract %s: %w", source, err)
	}
	return contract, nil
}

// notJSON reports that a document is not JSON at all, and therefore cannot be
// a contract this build reads.
//
// It asks the decoder rather than inspecting the first byte. An earlier form
// classified the document from a table of openers, which is a restatement of
// the decoder's own grammar: the two agree almost everywhere, and this project
// has now been caught three times by the gap in an "almost". Decoding into a
// raw message accepts every JSON document and no other, which is exactly the
// question being asked.
//
// The message names YAML because that is overwhelmingly what a non-JSON
// contract will be, and because failing as a syntax error at some byte offset
// tells a reader nothing about why their file was rejected.
func notJSON(raw []byte) bool {
	var document json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(raw))
	return decoder.Decode(&document) != nil
}

// maxDepth bounds how far the rewrite will descend.
//
// json.Decoder.Token does not apply the nesting limit that Decode does, so a
// walk over tokens descends where the standard library refuses, and
// expensively: a file of nothing but brackets took forty seconds and two
// gigabytes and died rather than reporting invalid input.
//
// A contract is a document a human writes. The documented one nests three
// levels and the schema has no recursive structure, so this costs nothing real.
const maxDepth = 64

// rejectRepeatedFields refuses a contract that names one field more than once.
//
// encoding/json matches a struct tag case-insensitively, and by more than case:
// it folds with unicode.SimpleFold, under which the long s folds with s. So
// "expoſure" fills the field "exposure" names, DisallowUnknownFields does not
// fire because a field was matched, and a contract declaring private exposure
// and then public is read as declaring public.
//
// An earlier form of this check restated the decoder's relation as
// strings.ToLower and got one that was almost the same. The gap was silent and
// permissive, which is what a restated predicate always gives: there is no
// compiler and no test standing between the two definitions.
//
// So this calls the relation rather than restating it. The document is decoded
// twice, once as written and once with every object's members reversed. Where
// two keys fill one field, the decoder keeps the last, and reversing the order
// changes which one that is; where no two keys collide, order cannot matter and
// the two results are identical. A map is unaffected either way, because two
// keys differing in case are two entries in it — which is why cloud tag names
// need no exception.
func rejectRepeatedFields(raw []byte) error {
	reversed, err := reverseObjectMembers(raw)
	switch {
	case errors.Is(err, errRepeatedKey):
		return err
	case err != nil:
		// Malformed input. The decode that follows reports it, with the
		// message encoding/json produces; saying it twice in two voices tells
		// a reader less.
		return nil //nolint:nilerr // the decode below is the reporting path
	}

	asWritten, err := decodeContract(raw)
	if err != nil {
		return nil //nolint:nilerr // see above
	}
	asReversed, err := decodeContract(reversed)
	if err != nil {
		return nil //nolint:nilerr // see above
	}

	if !reflect.DeepEqual(asWritten, asReversed) {
		return errors.New("names one field more than once, and the two spellings disagree")
	}
	return nil
}

// decodeContract reads the wire shape, rejecting a field this build does not
// know so that a contract is never read partially.
func decodeContract(raw []byte) (wireContract, error) {
	var wire wireContract
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		return wireContract{}, err
	}
	if decoder.More() {
		return wireContract{}, errors.New("the file holds more than one document")
	}
	return wire, nil
}

// reverseObjectMembers re-emits the document with the members of every object
// in the opposite order, leaving arrays and values untouched.
//
// maxDepth bounds it for the same reason it bounded the walk before: Token
// does not apply the nesting limit Decode does, and a document of nothing but
// brackets would otherwise cost whatever it liked.
func reverseObjectMembers(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var out bytes.Buffer
	if err := rewriteValue(decoder, &out, 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// rewriteValue consumes exactly one JSON value and writes it back.
func rewriteValue(decoder *json.Decoder, out *bytes.Buffer, depth int) error {
	if depth > maxDepth {
		return fmt.Errorf("is nested more than %d levels deep", maxDepth)
	}

	token, err := decoder.Token()
	if err != nil {
		return err
	}

	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return writeScalar(out, token)
	}

	switch delimiter {
	case '{':
		var members []string
		// Byte equality is not the decoder's relation; it is a strict subset
		// of it, so checking it here only ever refuses and never admits. It is
		// worth checking because two keys spelled identically produce the same
		// result in either order, and the reversal below cannot see them.
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("an object key must be a string")
			}
			if seen[key] {
				return errRepeatedKey
			}
			seen[key] = true

			var value bytes.Buffer
			if err := rewriteValue(decoder, &value, depth+1); err != nil {
				return err
			}
			encoded, err := json.Marshal(key)
			if err != nil {
				return err
			}
			members = append(members, string(encoded)+":"+value.String())
		}
		slices.Reverse(members)
		out.WriteString("{" + strings.Join(members, ",") + "}")

	case '[':
		var elements []string
		for decoder.More() {
			var element bytes.Buffer
			if err := rewriteValue(decoder, &element, depth+1); err != nil {
				return err
			}
			elements = append(elements, element.String())
		}
		out.WriteString("[" + strings.Join(elements, ",") + "]")
	}

	// The closing delimiter.
	if _, err := decoder.Token(); err != nil {
		return err
	}
	return nil
}

// errRepeatedKey ends the rewrite when an object spells one key twice. It
// carries no payload: the key is a contract value.
var errRepeatedKey = errors.New("names one field more than once")

func writeScalar(out *bytes.Buffer, token json.Token) error {
	encoded, err := json.Marshal(token)
	if err != nil {
		return err
	}
	out.Write(encoded)
	return nil
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
