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
	"unicode"

	"github.com/mtlabs-eng/infraproof/internal/model"
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
	// A document that does not even begin as JSON is a format problem, and
	// saying so beats a byte offset. A document that begins as JSON and then
	// goes wrong is a typo, and there the offset is the only actionable thing
	// in the message — reporting the four commonest ways to mistype JSON as
	// "this is not JSON" sent the author to a question they did not have.
	if notJSON(body) && !opensAsJSON(body) {
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
		var kind *json.UnmarshalTypeError
		if errors.As(err, &kind) {
			// encoding/json names the Go type it was decoding into, which is
			// an implementation detail the reader has no way to act on. The
			// field and the JSON kind are the parts that belong to them.
			if kind.Field == "" {
				return Contract{}, fmt.Errorf(
					"reading intent contract %s: a contract is a JSON object, and this is %s",
					source, article(kind.Value))
			}
			return Contract{}, fmt.Errorf(
				"reading intent contract %s: %s is %s, which is the wrong kind of value",
				source, kind.Field, article(kind.Value))
		}
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

// article prefixes a JSON kind so a message reads as a sentence.
func article(kind string) string {
	switch kind {
	case "array", "object":
		return "an " + kind
	default:
		return "a " + kind
	}
}

// opensAsJSON reports that a document starts the way a JSON contract does.
//
// It is a question about the first token, not about the grammar, which is why
// it may be answered here: a contract is an object, and anything beginning with
// "{" was meant as one. Whether it goes on to be valid JSON is the decoder's to
// say, and its message names the byte that went wrong.
func opensAsJSON(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
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
	reversed, folded, err := reverseObjectMembers(raw)
	switch {
	case errors.Is(err, errRepeatedKey), errors.Is(err, errTooDeep):
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

	// The fold check below subsumes this today: any two keys the decoder
	// merges also fold together, so removing the reversal changes no test.
	// It stays because it is the only check here that asks the decoder rather
	// than modelling it, and foldKey is a model — of a function this package
	// cannot call, in a standard library that may widen the relation without
	// telling anyone. It is not claimed as covered.
	if !reflect.DeepEqual(asWritten, asReversed) {
		return errors.New("names one field more than once, and the two spellings disagree")
	}

	// Reversal sees a field the decoder overwrites. It does not see one the
	// decoder merges: an array element, a pointer already followed, a map
	// already made. For those, two spellings writing to different leaves give
	// the same result in either order, and a contract naming "resources" twice
	// was accepted as the union of both — including one that was invalid
	// written once.
	//
	// So the folded key sets are compared too, using the relation the decoder
	// folds by rather than a guess at it.
	// One probe per object, not per collision. Whether a position matches
	// fields or holds names is a property of the position, so every collision
	// in one object shares the answer — and probing each rewrites and decodes
	// the whole document again, which made a valid contract of many
	// case-spelled tag names quadratic in its own size.
	answered := map[string]bool{}
	for _, candidate := range folded {
		if answered[candidate.path] {
			continue
		}
		matters, err := namesAField(raw, candidate)
		if err != nil {
			return nil //nolint:nilerr // the decode reports malformed input
		}
		answered[candidate.path] = true
		if matters {
			return fmt.Errorf("names %s more than once", candidate.key)
		}
	}
	return nil
}

// namesAField reports whether a key sits where the decoder matches fields, as
// opposed to a map, whose keys are names a user chose and where two spellings
// differing only in case are two entries.
//
// It asks rather than deciding: the key is renamed to one no field can match,
// and the document decoded with unknown fields refused. A struct position
// rejects the rename; a map accepts it.
func namesAField(raw []byte, at collision) (bool, error) {
	const impossible = "\u0000-infraproof-probe"

	renamed, err := rewriteWithRename(raw, at, impossible)
	if err != nil {
		return false, err
	}
	if _, err := decodeContract(renamed); err != nil {
		return true, nil
	}
	return false, nil
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

// errRepeatedKey ends the rewrite when an object spells one key twice. It
// carries no payload: the key is a contract value.
var errRepeatedKey = errors.New("names one field more than once")

// errTooDeep reports a document nested past what the rewrite will descend. It
// is reported rather than swallowed: a bound that protects the walk and tells
// nobody leaves a reader with whatever the decoder says next, which was an
// internal Go type name.
var errTooDeep = fmt.Errorf("is nested more than %d levels deep", maxDepth)

// join builds the path of a member, which locates an object for the probe.
func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// collision names a key that folds onto an earlier one in the same object.
type collision struct {
	// path locates the object, so the probe can rename the key in place.
	path string
	// key is the later spelling, as written.
	key string
}

// rewrite re-emits a document, optionally reversing each object's members and
// optionally renaming one key, and reports the folded-key collisions it saw.
type rewrite struct {
	reverse    bool
	rename     *collision
	renameTo   string
	collisions []collision
}

// reverseObjectMembers re-emits the document with the members of every object
// in the opposite order, leaving arrays and values untouched, and reports every
// key that folds onto an earlier one in its object.
func reverseObjectMembers(raw []byte) ([]byte, []collision, error) {
	pass := rewrite{reverse: true}
	out, err := pass.run(raw)
	return out, pass.collisions, err
}

// rewriteWithRename re-emits the document with one key renamed, leaving the
// order alone.
func rewriteWithRename(raw []byte, at collision, to string) ([]byte, error) {
	pass := rewrite{rename: &at, renameTo: to}
	return pass.run(raw)
}

func (r *rewrite) run(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	var out bytes.Buffer
	if err := r.value(decoder, &out, "", 0); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// value consumes exactly one JSON value and writes it back.
//
// maxDepth bounds it for the same reason it bounded the walk before: Token does
// not apply the nesting limit Decode does, and a document of nothing but
// brackets would otherwise cost whatever it liked.
func (r *rewrite) value(decoder *json.Decoder, out *bytes.Buffer, path string, depth int) error {
	if depth > maxDepth {
		return errTooDeep
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
		// Byte equality is a strict subset of the decoder's relation, so
		// checking it here only ever refuses and never admits. It is worth
		// checking because two keys spelled identically produce the same
		// result in either order, and reversal cannot see them.
		seen := map[string]bool{}
		// And the folded set, using the relation the decoder folds by. A
		// collision here is a candidate: whether it matters depends on whether
		// the position matches fields or holds names, which namesAField asks.
		byFold := map[string]bool{}

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
			if folded := foldKey(key); byFold[folded] {
				r.collisions = append(r.collisions, collision{path: path, key: key})
			} else {
				byFold[folded] = true
			}

			var value bytes.Buffer
			if err := r.value(decoder, &value, join(path, key), depth+1); err != nil {
				return err
			}

			written := key
			if r.rename != nil && r.rename.path == path && r.rename.key == key {
				written = r.renameTo
			}
			encoded, err := json.Marshal(written)
			if err != nil {
				return err
			}
			members = append(members, string(encoded)+":"+value.String())
		}
		if r.reverse {
			slices.Reverse(members)
		}
		out.WriteString("{" + strings.Join(members, ",") + "}")

	case '[':
		var elements []string
		for i := 0; decoder.More(); i++ {
			var element bytes.Buffer
			if err := r.value(decoder, &element, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
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

// foldKey maps a key to a canonical form under the relation encoding/json
// folds by.
//
// It calls unicode.SimpleFold, which is the function the decoder uses, rather
// than approximating it: strings.ToLower is a different relation, and the gap
// between them — the long s folds with s for one and not the other — was a
// contract naming one field twice and being read as saying the second thing.
//
// Taking the orbit's smallest rune gives every member of a fold class the same
// answer without needing to know which member the decoder would pick.
func foldKey(key string) string {
	return strings.Map(func(r rune) rune {
		smallest := r
		for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
			if folded < smallest {
				smallest = folded
			}
		}
		return smallest
	}, key)
}

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
	Family      *string   `json:"family"`
	Exposure    *string   `json:"exposure"`
	PublicPorts *[]string `json:"public_ports"`
	Purpose     string    `json:"purpose"`
}

// Pointers, like every other optional field in the wire contract: a field the
// document omitted and a field it set to empty are different statements, and
// only a pointer keeps them apart.
type wireConstraints struct {
	AllowedRegions *[]string          `json:"allowed_regions"`
	RequiredTags   *map[string]string `json:"required_tags"`
}

func (w wireContract) contract() Contract {
	contract := Contract{
		SchemaVersion:      derefString(w.SchemaVersion),
		ChangeID:           derefString(w.ChangeID),
		Environment:        derefString(w.Environment),
		AllowedClouds:      trimmedEach(w.AllowedClouds),
		DestructiveChanges: DestructivePolicy(derefString(w.DestructiveChanges)),
	}
	for _, resource := range w.Resources {
		contract.Resources = append(contract.Resources, ResourceIntent{
			Family:   derefString(resource.Family),
			Exposure: Exposure(derefString(resource.Exposure)),
			// Parsed best-effort here and validated from the raw values
			// recorded below. This function cannot report an error, and a
			// declaration nobody could parse must be refused rather than
			// quietly dropped -- so the raw strings travel to validation,
			// which is the only place that can say what was wrong with them.
			PublicPorts: parsedPorts(resource.PublicPorts),
			Purpose:     resource.Purpose,
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
			family:      resource.Family != nil,
			exposure:    resource.Exposure != nil,
			publicPorts: resource.PublicPorts != nil,
			rawPorts:    derefSlice(resource.PublicPorts),
		})
	}
	return contract
}

// trimmedEach applies the rule derefString applies to every other string the
// contract carries. A list is not a reason for a different rule: a cloud named
// with a space around it is the cloud, and refusing it told a reader their name
// was unrecognized when it was not.
func trimmedEach(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.TrimSpace(value))
	}
	return out
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

// parsedPorts turns a declaration into ranges, keeping only what parsed.
//
// What it drops is what validation refuses, so a contract that reaches a rule has
// every port it declared. The pointer is preserved: an empty declaration is a
// statement and must not become an absent one.
func parsedPorts(declared *[]string) *[]model.PortRange {
	if declared == nil {
		return nil
	}
	ranges := make([]model.PortRange, 0, len(*declared))
	for _, text := range *declared {
		if parsed, err := parsePortRange(text); err == nil {
			ranges = append(ranges, parsed)
		}
	}
	return &ranges
}
