package terraformplan

import (
	"bytes"
	"encoding/json"
	"strconv"
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
//
// A document this cannot read at all is left alone. The decode reports it, in
// the message encoding/json produces, and saying it twice in two voices tells a
// reader less.
func rejectRepeatedKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()

	token, err := decoder.Token()
	if err != nil {
		return nil
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
			return nil
		}
		if delim, ok := key.(json.Delim); ok && delim == '}' {
			return nil
		}
		name, ok := key.(string)
		if !ok {
			return nil
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
			return nil
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
			return nil
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
func join(path, name string) string {
	safe := safeToken(name)
	if unquoted, err := strconv.Unquote(safe); err == nil {
		name = unquoted
	} else {
		name = "a key this build will not repeat"
	}
	if path == "" {
		return name
	}
	return path + "." + name
}
