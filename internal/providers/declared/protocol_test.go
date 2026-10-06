package declared_test

import (
	"testing"

	"github.com/mtlabs-eng/infraproof/internal/model"
	"github.com/mtlabs-eng/infraproof/internal/providers/declared"
)

// AWS and GCP both accept a protocol written as its IANA number and neither
// normalizes it: a real plan carries `"6"` through verbatim. The assignment is
// closed and documented, so reading it is reading a fact rather than guessing at
// one -- and refusing it loses the verdict on an ordinary rule.
//
// Everything outside the four this model can name stays unreadable. A number
// nobody here can name is not a protocol this build may compare, which is the
// same answer a spelling it cannot name gets.
func TestAnIANAProtocolNumberIsReadWhenThisModelCanNameIt(t *testing.T) {
	cases := map[string]struct {
		want     model.Protocol
		readable bool
	}{
		"1":  {model.ProtocolICMP, true},
		"6":  {model.ProtocolTCP, true},
		"17": {model.ProtocolUDP, true},
		// ICMPv6 carries no ports and is the same question as ICMP for this
		// family, which is the answer the AWS mapper already gives its "icmpv6"
		// spelling.
		"58": {model.ProtocolICMP, true},
		// Real protocols this model cannot name.
		"50":  {model.ProtocolUnrecognized, false},
		"47":  {model.ProtocolUnrecognized, false},
		"132": {model.ProtocolUnrecognized, false},
		// Not a number at all, and the numbers nothing assigns.
		"tcp": {model.ProtocolUnrecognized, false},
		"":    {model.ProtocolUnrecognized, false},
		"256": {model.ProtocolUnrecognized, false},
		"-1":  {model.ProtocolUnrecognized, false},
		// A spelling that is arithmetically 6 and is not the canonical one. A
		// provider may or may not accept it, and deciding that it means TCP
		// would be this build inventing a grammar rather than reading one --
		// the defect class this whole family keeps producing.
		"06":   {model.ProtocolUnrecognized, false},
		" 6":   {model.ProtocolUnrecognized, false},
		"+6":   {model.ProtocolUnrecognized, false},
		"6.0":  {model.ProtocolUnrecognized, false},
		"0x06": {model.ProtocolUnrecognized, false},
	}

	for text, want := range cases {
		t.Run(text, func(t *testing.T) {
			got, readable := declared.ProtocolNumber(text)
			if readable != want.readable {
				t.Fatalf("readable = %v, want %v", readable, want.readable)
			}
			if got != want.want {
				t.Fatalf("protocol = %q, want %q", got, want.want)
			}
		})
	}
}

// Zero is a real assignment -- IANA reserves it for HOPOPT -- and this model
// cannot name it. It is called out because 0 is also what a failed numeric parse
// produces, and the two must not reach the same answer by accident.
func TestProtocolZeroIsNotReadAsAnythingThisModelNames(t *testing.T) {
	got, readable := declared.ProtocolNumber("0")

	if readable || got != model.ProtocolUnrecognized {
		t.Fatalf("protocol 0 read as %q (readable = %v)", got, readable)
	}
}
