package terraformplan

import (
	"bytes"
	"encoding/json"
)

// maxKeyDepth bounds how deep the scan below will walk. A plan is nested as
// deeply as its modules and its values, which is tens of levels; a document
// deeper than this is not one Terraform wrote, and walking it would cost stack
// proportional to whatever the producer chose.
const maxKeyDepth = 512

// rejectRepeatedKeys refuses a document that names one key twice inside one
// object.
//
// Two entries at one address are refused in resource_changes and in the
// configuration walk, because an address identifies one resource and keeping
// the last discards what the first said. A repeated JSON key is the same claim
// one level down, and neither check could see it: the plan is decoded into maps,
// and encoding/json collapses repeated members into the last one while
// decoding. So a second "one" under module_calls discarded that module's whole
// configuration -- every reference in it -- before anything could look, and a
// plan stating a public grant reported the grant as undetermined.
//
// It is answered here rather than per field because the field lists are what
// this repository keeps being caught by: module_calls and provider_config are
// the two that move a verdict today, and the next map added would need
// remembering.
// The decode runs before this and has already succeeded, so the
// walk below cannot meet a token the reader rejects. Where it would, it refuses
// the document rather than returning: a scan that stops early and says nothing
// is a document read as checked when it was not, and that shape must not be one
// line of reordering away.
func rejectRepeatedKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return errUnscannable
	}
	return scanValue(decoder, token, "", 0)
}

// scanValue walks one value, having already read its opening token.
func scanValue(decoder *json.Decoder, token json.Token, path string, depth int) error {
	delim, ok := token.(json.Delim)
	if !ok {
		// A scalar is one token and holds no keys.
		return nil
	}

	if depth >= maxKeyDepth {
		return invalid(path, "is nested more than %d levels deep, which this build will not read",
			maxKeyDepth)
	}

	switch delim {
	case '{':
		return scanObject(decoder, path, depth)
	case '[':
		return scanArray(decoder, path, depth)
	default:
		// A closing delimiter cannot open a value.
		return nil
	}
}

func scanObject(decoder *json.Decoder, path string, depth int) error {
	seen := make(map[string]bool)

	for {
		key, err := decoder.Token()
		if err != nil {
			return errUnscannable
		}
		if delim, ok := key.(json.Delim); ok && delim == '}' {
			return nil
		}
		name, ok := key.(string)
		if !ok {
			return errUnscannable
		}

		here := join(path, name)
		if seen[name] {
			// safeToken, like every plan-derived string in a diagnostic: a key
			// is a plan value, and a ParseError has no field able to hold one.
			return invalid(here, "is named more than once, and only one of the two would be read")
		}
		seen[name] = true

		value, err := decoder.Token()
		if err != nil {
			return errUnscannable
		}
		if err := scanValue(decoder, value, here, depth+1); err != nil {
			return err
		}
	}
}

func scanArray(decoder *json.Decoder, path string, depth int) error {
	for i := 0; ; i++ {
		token, err := decoder.Token()
		if err != nil {
			return errUnscannable
		}
		if delim, ok := token.(json.Delim); ok && delim == ']' {
			return nil
		}
		if err := scanValue(decoder, token, path+indexPath(i), depth+1); err != nil {
			return err
		}
	}
}

// join builds a diagnostic path, keeping a key out of it unless it is plainly a
// field name. A key is a plan value and a diagnostic is read in a CI log.
//
// The path is bounded too. Each component is short, and the number of them is
// whatever the producer nested, so a crafted document could otherwise put five
// hundred components on one line. Where it is cut is said rather than left to
// be noticed.
func join(path, name string) string {
	if path == "" {
		return readableKey(name)
	}
	joined := path + "." + readableKey(name)
	if len(joined) <= pathLimit {
		return joined
	}
	return "…" + joined[len(joined)-pathLimit:]
}

// readableKey returns a key a diagnostic may repeat, or a description of one it
// may not.
//
// safeToken exists for a version string and bounds at sixteen characters, which
// is the wrong bound here: "terraform_version" is seventeen, so the field most
// likely to be repeated by a careless producer was reported as unnameable and
// the diagnostic located nothing. A field name is longer than a version and is
// still not free text, so the character set stays and the length grows.
func readableKey(name string) string {
	if name == "" || len(name) > keyLimit {
		return unnameableKey
	}
	for _, char := range name {
		switch {
		case char >= '0' && char <= '9', char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z':
		case char == '.', char == '-', char == '_', char == '/', char == '[', char == ']':
		default:
			return unnameableKey
		}
	}
	return name
}

// errUnscannable reports a document the walk could not read to the end. The
// decode has already accepted it, so this is unreachable; it is an error rather
// than a silent return because the alternative reads an unchecked document as a
// checked one.
var errUnscannable = invalid("", "could not be read to the end while checking for repeated keys")

const (
	// keyLimit bounds how much of one key a diagnostic repeats.
	keyLimit = 64
	// pathLimit bounds the whole path, because the number of components is the
	// producer's to choose.
	pathLimit = 200
	// unnameableKey stands in for a key this build will not put in a log.
	unnameableKey = "a key this build will not repeat"
)
