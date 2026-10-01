package tfconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// marker names the line a case expects the subject's argument to be reported on.
// It is written into the value, so the expected line is read off the file by
// looking for it rather than counted by hand -- a hand-counted expectation is a
// second place for an off-by-one to hide.
const marker = "LOCATE_ME"

// TestScanAgreesWithTerraform asks Terraform which files are configuration and
// checks that this scanner reads every one of them, at the right line.
//
// It exists because four independent reviews of this milestone each found the same
// class of defect and nothing else: this lexer disagreeing with HCL. Each review
// found it by hand-building cases nobody had thought of, and each time that work
// was thrown away with the reviewer's context. The question "where do these two
// disagree?" is worth asking repeatedly, so it is asked here, by a tool, against
// the only authority there is.
//
// The two halves are deliberately asymmetric. For a file Terraform accepts, this
// build must read it and must report the argument where it is written: refusing it
// costs every location in that file, silently, which is the one failure mode no
// other test here can see. For a file Terraform rejects, nothing is required --
// reading one is harmless as long as the position is right, and refusing one is
// the safe answer -- but if this build does read it, the position still has to be
// correct, because a wrong line is worse than none whatever the input.
//
// It needs terraform on PATH and skips without it. No provider is involved: every
// case uses terraform_data, which is builtin, so `terraform init -backend=false`
// downloads nothing and reaches no network. One init serves the whole run; each
// case rewrites main.tf in the same directory, which costs about 35ms.
//
// Set INFRAPROOF_HCL_SWEEP to a count to add that many generated files on top of
// the hand-written cases, for a deeper run than the default.
func TestScanAgreesWithTerraform(t *testing.T) {
	terraform, err := exec.LookPath("terraform")
	if err != nil {
		t.Skip("terraform is not on PATH, and this test is a question for it")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(path, []byte(subject("  input = \"x\"\n")), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	init := exec.Command(terraform, "init", "-backend=false", "-input=false")
	init.Dir = dir
	if out, err := init.CombinedOutput(); err != nil {
		t.Skipf("terraform init failed, so there is nothing to compare against: %v\n%s", err, out)
	}

	cases := agreementCases()
	cases = append(cases, generatedCases(sweepSize(t))...)

	var accepted, rejected int
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want, found := markedLine(t, c.body)
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}

			valid := validates(t, terraform, dir)
			declarations, readable := scan([]byte(c.body))

			if c.refused != "" {
				if !valid {
					t.Fatalf("this case is recorded as a deliberate refusal of valid "+
						"configuration, and Terraform rejects it, so it proves nothing:\n%s", c.body)
				}
				if readable {
					t.Fatalf("this file is meant to be refused because %s, and was read:\n%s",
						c.refused, c.body)
				}
				accepted++
				return
			}

			if valid {
				accepted++
				if !readable {
					t.Fatalf("Terraform accepts this file and this build refused it, "+
						"so nothing in it can be located:\n%s", c.body)
				}
			} else {
				rejected++
				if !readable {
					return
				}
			}

			subject, ok := subjectOf(declarations)
			if !ok {
				if valid {
					t.Fatalf("the subject declaration was not found in a file Terraform accepts:\n%s", c.body)
				}
				return
			}
			if line, written := subject.lineOf("input"); written != found || written && line != want {
				t.Fatalf("input reported at line %d (written %v), want %d (written %v):\n%s",
					line, written, want, found, c.body)
			}
		})
	}

	// A sweep that reached no accepted files, or none Terraform rejected, is a
	// sweep that proved half of what it claims.
	if accepted == 0 || rejected == 0 {
		t.Fatalf("Terraform accepted %d and rejected %d of %d cases; both halves must be exercised",
			accepted, rejected, len(cases))
	}
	t.Logf("%d cases: Terraform accepted %d, rejected %d", len(cases), accepted, rejected)
}

// sweepSize reads how many generated files to add.
func sweepSize(t *testing.T) int {
	t.Helper()
	raw, set := os.LookupEnv("INFRAPROOF_HCL_SWEEP")
	if !set {
		return 48
	}
	count, err := strconv.Atoi(raw)
	if err != nil || count < 0 {
		t.Fatalf("INFRAPROOF_HCL_SWEEP is %q, want a count", raw)
	}
	return count
}

// validates asks Terraform whether the directory holds valid configuration.
func validates(t *testing.T, terraform, dir string) bool {
	t.Helper()
	command := exec.Command(terraform, "validate", "-json")
	command.Dir = dir
	out, err := command.Output()
	if len(out) == 0 && err != nil {
		t.Fatalf("terraform validate produced nothing: %v", err)
	}

	var report struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("terraform validate did not answer in JSON: %v\n%s", err, out)
	}
	return report.Valid
}

// markedLine returns the line the marker is written on, and whether it is there at
// all. A case with no marker expects the argument not to be reported.
func markedLine(t *testing.T, body string) (int, bool) {
	t.Helper()
	line, found := 0, false
	for i, text := range strings.Split(body, "\n") {
		if !strings.Contains(text, marker) {
			continue
		}
		if found {
			t.Fatalf("the marker is on more than one line:\n%s", body)
		}
		line, found = i+1, true
	}
	return line, found
}

// subjectOf returns the one declaration every case is about.
func subjectOf(declarations []declaration) (declaration, bool) {
	for _, d := range declarations {
		if d.Kind == "resource" && d.Type == "terraform_data" && d.Name == "subject" {
			return d, true
		}
	}
	return declaration{}, false
}

// subject wraps an argument in the declaration every case is about.
func subject(arguments string) string {
	return "resource \"terraform_data\" \"subject\" {\n" + arguments + "}\n"
}

type agreementCase struct {
	name string
	body string
	// refused is why this build refuses a file Terraform accepts. Empty means it
	// must be read.
	//
	// The field exists so that a deliberate refusal is a statement rather than a
	// hole in the comparison: this harness exists to find the refusals nobody
	// decided on, and it cannot do that if the ones somebody did decide on are
	// indistinguishable from them.
	refused string
}

// agreementCases is one case per construct four reviews of this milestone raised,
// each written out so the next reader can see what was asked rather than infer it.
func agreementCases() []agreementCase {
	value := "  input = \"" + marker + "\"\n"

	return []agreementCase{
		{name: "plain argument", body: subject(value)},
		{name: "heredoc above", body: subject("  triggers_replace = <<EOT\n  body\nEOT\n" + value)},
		{name: "dedented heredoc above", body: subject("  triggers_replace = <<-EOT\n    body\n  EOT\n" + value)},
		{name: "heredoc with an indented terminator", body: subject("  triggers_replace = <<EOT\n  body\n  EOT\n" + value)},
		{name: "heredoc terminator with trailing spaces", body: subject("  triggers_replace = <<EOT\n  body\nEOT   \n" + value)},
		{name: "heredoc body holding its own tag", body: subject("  triggers_replace = <<EOT\nEOTx\nEOT\n" + value)},
		{name: "heredoc body holding a fake block", body: subject("  triggers_replace = <<EOT\nresource \"terraform_data\" \"decoy\" {\n}\nEOT\n" + value)},
		{name: "heredoc body holding braces", body: subject("  triggers_replace = <<EOT\n}}}{{{\nEOT\n" + value)},
		{name: "two heredocs", body: subject("  triggers_replace = [<<EOT\na\nEOT\n    ,\n    <<EOT2\nb\nEOT2\n  ]\n" + value)},
		{name: "empty heredoc", body: subject("  triggers_replace = <<EOT\nEOT\n" + value)},
		{name: "heredoc in a function call", body: subject("  triggers_replace = trimspace(<<-EOT\n    a\n  EOT\n  )\n" + value)},
		{name: "line comment above", body: subject("  # a comment\n" + value)},
		{name: "slash comment above", body: subject("  // a comment\n" + value)},
		{name: "block comment above", body: subject("  /* a comment\n     over lines */\n" + value)},
		{name: "comment splitting the header", body: "resource /* c\n */ \"terraform_data\" \"subject\" {\n" + value + "}\n"},
		{name: "comment splitting the labels", body: "resource \"terraform_data\" /* c\n */ \"subject\" {\n" + value + "}\n"},
		{name: "comment before the brace", body: "resource \"terraform_data\" \"subject\" /* c\n */ {\n" + value + "}\n"},
		// The marker goes on the name's line, because that is where the argument
		// is written: HCL lets a comment sit between a name and its "=", and the
		// position worth having is the name's.
		{name: "comment splitting the argument", body: subject("  input /* " + marker + "\n  */ = \"x\"\n")},
		{name: "escaped interpolation sigil", body: subject("  triggers_replace = \"$${\"\n" + value)},
		{name: "escaped directive sigil", body: subject("  triggers_replace = \"%%{\"\n" + value)},
		{name: "comment inside an interpolation", body: subject("  triggers_replace = \"${ 1 /* \" */ }\"\n" + value)},
		{name: "directive holding a string", body: subject("  triggers_replace = \"%{ if length(\"{\") > 0 }y%{ endif }\"\n" + value)},
		{name: "interpolation over lines", body: subject("  triggers_replace = \"${join(\n    \"\",\n    [\"a\"]\n  )}\"\n" + value)},
		{name: "object over lines", body: subject("  triggers_replace = {\n    a = 1\n    b = 2\n  }\n" + value)},
		{name: "for expression", body: subject("  triggers_replace = [for k in [\"a\"] : k]\n" + value)},
		{name: "nested block", body: subject("  lifecycle {\n    prevent_destroy = false\n  }\n" + value)},
		{name: "carriage returns throughout", body: strings.ReplaceAll(subject("  triggers_replace = 1\n"+value), "\n", "\r\n")},
		{name: "byte order mark", body: "\ufeff" + subject(value)},
		{name: "no trailing newline", body: strings.TrimSuffix(subject(value), "\n")},
		{name: "non-ascii value", body: subject("  triggers_replace = \"café\"\n" + value)},

		// Files Terraform rejects. Nothing is required of them beyond not
		// reporting a wrong position, and the marker is left off the ones whose
		// argument must not be reported at all.
		{name: "header split by a bare newline", body: "resource\n\"terraform_data\" \"subject\" {\n  input = \"x\"\n}\n"},
		{name: "two arguments on one line", body: subject("  triggers_replace = 1  input = \"x\"\n")},
		{name: "content after a heredoc marker", body: subject("  triggers_replace = <<EOT trailing\nbody\nEOT\n  input = \"x\"\n")},
		{name: "tag starting with a digit", body: subject("  triggers_replace = <<9EOT\nbody\n9EOT\n  input = \"x\"\n")},
		{
			name: "non-ascii heredoc tag",
			body: subject("  triggers_replace = <<EOTÖ\nEOT\nEOTÖ\n  input = \"x\"\n"),
			refused: "an HCL identifier is Unicode and this lexer's is ASCII, so the tag " +
				"would be truncated to a prefix of the real terminator -- the heredoc would " +
				"end early and its body would be read as structure",
		},
		{name: "lone carriage return", body: subject("  input\r= \"x\"\n")},
	}
}

// generatedCases wraps the subject in filler, so the sweep covers combinations
// nobody chose. Each file's expected line is read off the marker like every other
// case, so nothing here depends on counting.
func generatedCases(count int) []agreementCase {
	if count == 0 {
		return nil
	}

	fillers := []string{
		"",
		"  triggers_replace = 1\n",
		"  # comment\n",
		"  /* comment\n     over lines */\n",
		"  triggers_replace = <<EOT\nbody\nEOT\n",
		"  triggers_replace = <<-EOT\n    body\n  EOT\n",
		"  triggers_replace = \"${join(\n    \"\",\n    []\n  )}\"\n",
		"  triggers_replace = {\n    a = 1\n  }\n",
		"  lifecycle {\n    prevent_destroy = false\n  }\n",
		"  triggers_replace = \"$${a}\"\n",
	}
	preambles := []string{
		"",
		"# a file comment\n\n",
		"/* a file comment\n   over lines */\n\n",
		"\ufeff",
		"variable \"unused\" {\n  type = string\n}\n\n",
	}

	out := make([]agreementCase, 0, count)
	for i := range count {
		// Deterministic rather than random: a sweep whose cases change between
		// runs cannot be reproduced from a failure message.
		before := fillers[i%len(fillers)]
		after := fillers[(i/len(fillers)+1)%len(fillers)]
		preamble := preambles[(i/(len(fillers)*len(fillers)))%len(preambles)]

		body := preamble + subject(before+"  input = \""+marker+"\"\n"+after)
		out = append(out, agreementCase{name: fmt.Sprintf("generated/%02d", i), body: body})
	}
	return out
}
