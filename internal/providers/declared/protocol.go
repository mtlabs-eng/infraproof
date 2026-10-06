package declared

import "github.com/mtlabs-eng/infraproof/internal/model"

// ProtocolNumber reads a protocol written as its IANA number.
//
// AWS and GCP both accept the numeric form and neither normalizes it -- a real
// plan carries `ip_protocol = "6"` and `protocol = "6"` through verbatim -- so a
// mapper that only knows the names answers UNKNOWN for an ordinary rule.
//
// Only the canonical decimal spelling of a number this model can name is read.
// Anything else is unreadable, including a number IANA does assign to a real
// protocol: an unnameable protocol must not collapse onto one value, because
// coverage between two rules is then decided by equality and a deny on one
// protocol cancels an allow on another. And a non-canonical spelling of a
// number this model does name -- "06", "+6" -- is refused rather than decoded,
// because deciding what a provider makes of it would be inventing a grammar
// instead of reading one.
//
// The second result reports whether the text was read at all, following the
// mappers' own convention: false means undetermined, never "some protocol".
func ProtocolNumber(text string) (model.Protocol, bool) {
	switch text {
	case "1":
		return model.ProtocolICMP, true
	case "6":
		return model.ProtocolTCP, true
	case "17":
		return model.ProtocolUDP, true
	case "58":
		// ICMPv6 carries no ports and asks the same question as ICMP for this
		// family, which is the answer the AWS mapper already gives the
		// "icmpv6" spelling.
		return model.ProtocolICMP, true
	default:
		return model.ProtocolUnrecognized, false
	}
}
