package intent

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mtlabs-eng/infraproof/internal/model"
)

// lastPort is the highest port there is.
const lastPort = 65535

// parsePortRange reads one port declaration: a single port, or two separated by a
// dash.
//
// There is one parser, and validation and loading both call it, because a grammar
// written twice is a grammar that comes to disagree with itself -- the defect
// class this repository keeps finding. What it refuses is refused at the
// boundary: a declaration nobody can read is an invalid contract rather than a
// defaulted one, because a contract that was refused is a contract its author
// fixes, and one that was quietly emptied is a contract that permits nothing
// while appearing to permit something.
//
// Whitespace around a port and around the dash is accepted, for the reason
// trimmedEach accepts it around a cloud name: a port written with a space beside
// it is that port, and refusing it tells a reader their declaration was
// unreadable when it was not.
func parsePortRange(declared string) (model.PortRange, error) {
	text := strings.TrimSpace(declared)
	if text == "" {
		return model.PortRange{}, fmt.Errorf("is blank; write a port such as \"443\" or a range such as \"8000-8100\"")
	}

	low, high, ranged := strings.Cut(text, "-")
	if !ranged {
		port, err := parsePort(text)
		if err != nil {
			return model.PortRange{}, err
		}
		return model.PortRange{From: port, To: port}, nil
	}

	from, err := parsePort(low)
	if err != nil {
		return model.PortRange{}, err
	}
	to, err := parsePort(high)
	if err != nil {
		return model.PortRange{}, err
	}
	if from > to {
		return model.PortRange{}, fmt.Errorf("is %q, whose range runs backwards", safe(text))
	}
	return model.PortRange{From: from, To: to}, nil
}

// parsePort reads one port number.
//
// strconv.Atoi rather than a hand-written digit loop, and then the bounds: a
// number this build accepted and a port that exists are different questions, and
// a negative or a 65536 is the second one failing.
func parsePort(declared string) (int, error) {
	text := strings.TrimSpace(declared)
	if text == "" {
		return 0, fmt.Errorf("names a range with an end missing")
	}
	// Atoi accepts a leading sign, which a port does not have: "+443" and "-1"
	// are not ports, and reading the first as 443 would accept a spelling no
	// provider writes.
	if text[0] == '+' || text[0] == '-' {
		return 0, fmt.Errorf("is %q, which is not a port number", safe(text))
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("is %q, which is not a port number", safe(text))
	}
	if port > lastPort {
		return 0, fmt.Errorf("is %d, and the last port is %d", port, lastPort)
	}
	return port, nil
}

// safe bounds a value quoted back into a diagnostic. The declaration is the
// author's text, and a diagnostic is read in a terminal.
func safe(text string) string {
	const most = 40
	if len(text) > most {
		return text[:most] + "…"
	}
	return text
}
